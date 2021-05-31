/*
 * This is an implementation of RFC 3623 Graceful OSPF Restart.
 *
 * Copyright 2021 NetDEF (c), All rights reserved.
 * Copyright 2020 6WIND (c), All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 2 of the License, or (at your option)
 * any later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; see the file COPYING; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
 */

#include <zebra.h>

#include "memory.h"
#include "command.h"
#include "table.h"
#include "vty.h"
#include "log.h"

#include "ospfd/ospfd.h"
#include "ospfd/ospf_abr.h"
#include "ospfd/ospf_flood.h"
#include "ospfd/ospf_ism.h"
#include "ospfd/ospf_interface.h"
#include "ospfd/ospf_asbr.h"
#include "ospfd/ospf_lsa.h"
#include "ospfd/ospf_route.h"
#include "ospfd/ospf_zebra.h"
#include "ospfd/ospf_lsdb.h"
#include "ospfd/ospf_neighbor.h"
#include "ospfd/ospf_opaque.h"
#include "ospfd/ospf_nsm.h"
#include "ospfd/ospf_gr.h"
#include "ospfd/ospf_errors.h"
#include "ospfd/ospf_dump.h"

static void ospf_gr_nvm_delete(struct ospf *ospf);

static struct ospf_lsa *ospf_gr_lsa_lookup(struct ospf *ospf,
					   struct ospf_area *area)
{
	struct ospf_lsa *lsa;
	struct in_addr lsa_id;
	uint32_t lsa_id_host_byte_order;

	lsa_id_host_byte_order = SET_OPAQUE_LSID(OPAQUE_TYPE_GRACE_LSA, 0);
	lsa_id.s_addr = htonl(lsa_id_host_byte_order);
	lsa = ospf_lsa_lookup(ospf, area, OSPF_OPAQUE_LINK_LSA, lsa_id,
			      ospf->router_id);

	return lsa;
}

static struct ospf_lsa *ospf_gr_flush_grace_lsa(struct ospf_interface *oi,
						struct ospf_lsa *old)
{
	struct ospf_lsa *lsa;

	if (ospf_interface_neighbor_count(oi) == 0)
		return NULL;

	if (IS_DEBUG_OSPF_GR)
		zlog_debug(
			"GR: flushing self-originated Grace-LSAs [interface %s]",
			oi->ifp->name);

	lsa = ospf_lsa_dup(old);
	lsa->data->ls_age = htons(OSPF_LSA_MAXAGE);
	lsa->data->ls_seqnum = lsa_seqnum_increment(lsa);

	/* Install this LSA into LSDB. */
	if (ospf_lsa_install(oi->ospf, oi, lsa) == NULL) {
		zlog_warn("%s: ospf_lsa_install() failed", __func__);
		ospf_lsa_unlock(&lsa);
		return NULL;
	}

	/* Flood the LSA through out the interface */
	ospf_flood_through_interface(oi, NULL, lsa);

	return lsa;
}

static void ospf_gr_flush_grace_lsas(struct ospf *ospf)
{
	struct ospf_area *area;
	struct listnode *anode;

	for (ALL_LIST_ELEMENTS_RO(ospf->areas, anode, area)) {
		struct ospf_lsa *lsa;
		struct ospf_interface *oi;
		struct listnode *inode;

		if (IS_DEBUG_OSPF_GR)
			zlog_debug(
				"GR: flushing self-originated Grace-LSAs [area %pI4]",
				&area->area_id);

		lsa = ospf_gr_lsa_lookup(ospf, area);
		if (!lsa) {
			zlog_warn("%s: Grace-LSA not found [area %pI4]",
				  __func__, &area->area_id);
			continue;
		}

		for (ALL_LIST_ELEMENTS_RO(area->oiflist, inode, oi))
			ospf_gr_flush_grace_lsa(oi, lsa);
	}
}

static void ospf_gr_restart_exit(struct ospf *ospf)
{
	struct ospf_area *area;
	struct listnode *onode, *anode;

	if (IS_DEBUG_OSPF_GR)
		zlog_debug("GR: exiting graceful restart");

	ospf->gr_info.restart_in_progress = false;
	OSPF_TIMER_OFF(ospf->gr_info.t_grace_period);
	ospf_gr_nvm_delete(ospf);

	for (ALL_LIST_ELEMENTS_RO(ospf->areas, onode, area)) {
		struct ospf_interface *oi;

		/*
		 * 1) The router should reoriginate its router-LSAs for
		 * all attached areas in order to make sure they have
		 * the correct contents.
		 */
		ospf_router_lsa_update_area(area);

		for (ALL_LIST_ELEMENTS_RO(area->oiflist, anode, oi)) {
			/*
			 * 2) The router should reoriginate network-LSAs
			 * on all segments where it is the Designated
			 * Router.
			 */
			if (oi->state == ISM_DR)
				ospf_network_lsa_update(oi);
		}
	}

	/*
	 * 5) Any received self-originated LSAs that are no longer valid
	 *    should be flushed.
	 */
	ospf_schedule_abr_task(ospf);

	/*
	 * 3) The router reruns its OSPF routing calculations (Section 16 of
	 *    [1]), this time installing the results into the system
	 *    forwarding table, and originating summary-LSAs, Type-7 LSAs and
	 *    AS-external-LSAs as necessary.
	 *
	 * 4) Any remnant entries in the system forwarding table that were
	 *    installed before the restart, but that are no longer valid,
	 *    should be removed.
	 */
	ospf_spf_calculate_schedule(ospf, SPF_FLAG_GR_FINISH);

	/* 6) Any grace-LSAs that the router originated should be flushed. */
	ospf_gr_flush_grace_lsas(ospf);
}

static bool ospf_router_lsa_contains_adj(struct ospf_lsa *lsa,
					 struct in_addr *id)
{
	struct router_lsa *rl;

	rl = (struct router_lsa *)lsa->data;
	for (int i = 0; i < ntohs(rl->links); i++) {
		struct in_addr *link_id = &rl->link[i].link_id;

		if (rl->link[i].type != LSA_LINK_TYPE_POINTOPOINT)
			continue;

		if (IPV4_ADDR_SAME(id, link_id))
			return true;
	}

	return false;
}

static bool ospf_gr_check_router_lsa_consistency(struct ospf *ospf,
						 struct ospf_area *area,
						 struct ospf_lsa *lsa)
{
	if (CHECK_FLAG(lsa->flags, OSPF_LSA_SELF)) {
		struct ospf_lsa *lsa_self = lsa;
		struct router_lsa *rl = (struct router_lsa *)lsa->data;

		for (int i = 0; i < ntohs(rl->links); i++) {
			struct in_addr *link_id = &rl->link[i].link_id;
			struct ospf_lsa *lsa_adj;

			lsa_adj = ospf_lsa_lookup_by_id(area, OSPF_ROUTER_LSA,
							*link_id);
			if (!lsa_adj)
				continue;

			if (ospf_router_lsa_contains_adj(lsa_adj,
							 &lsa_self->data->id)
			    != ospf_router_lsa_contains_adj(lsa_self,
							    &lsa_adj->data->id))
				return false;
		}
	} else {
		struct ospf_lsa *lsa_self;

		lsa_self = ospf_lsa_lookup_by_id(area, OSPF_ROUTER_LSA,
						 ospf->router_id);
		if (!lsa_self
		    || !CHECK_FLAG(lsa_self->flags, OSPF_LSA_RECEIVED))
			return true;

		if (ospf_router_lsa_contains_adj(lsa, &ospf->router_id)
		    != ospf_router_lsa_contains_adj(lsa_self, &lsa->data->id))
			return false;
	}

	return true;
}

void ospf_gr_check_lsdb_consistency(struct ospf *ospf, struct ospf_area *area)
{
	struct route_node *rn;
	struct ospf_lsa *lsa;

	for (rn = route_top(ROUTER_LSDB(area)); rn; rn = route_next(rn)) {
		lsa = rn->info;
		if (!lsa)
			continue;

		if (!ospf_gr_check_router_lsa_consistency(ospf, area, lsa)) {
			if (IS_DEBUG_OSPF_GR)
				zlog_debug(
					"GR: detected inconsistent LSA [area %pI4]",
					&area->area_id);
			ospf_gr_restart_exit(ospf);
			route_unlock_node(rn);
			return;
		}
	}
}

static struct ospf_neighbor *
ospf_area_nbr_lookup_by_routerid(struct ospf_area *area, struct in_addr *id)
{
	struct ospf_interface *oi;
	struct ospf_neighbor *nbr;
	struct listnode *node;

	for (ALL_LIST_ELEMENTS_RO(area->oiflist, node, oi)) {
		nbr = ospf_nbr_lookup_by_routerid(oi->nbrs, id);
		if (nbr)
			return nbr;
	}

	return NULL;
}

static bool ospf_gr_check_lsa_adjacencies(struct ospf_area *area, struct ospf_lsa *lsa)
{
	struct router_lsa *rl = (struct router_lsa *)lsa->data;

	for (int i = 0; i < ntohs(rl->links); i++) {
		struct in_addr *link_id = &rl->link[i].link_id;
		struct ospf_neighbor *nbr;

		if (rl->link[i].type != LSA_LINK_TYPE_POINTOPOINT)
			continue;

		nbr = ospf_area_nbr_lookup_by_routerid(area, link_id);
		if (!nbr || nbr->state < NSM_Full) {
			if (IS_DEBUG_OSPF_GR)
				zlog_debug(
					"GR: missing adjacency to router %pI4",
					link_id);
			return false;
		}
	}

	return true;
}

void ospf_gr_check_adjacencies(struct ospf *ospf)
{
	struct ospf_area *area;
	struct listnode *node;

	for (ALL_LIST_ELEMENTS_RO(ospf->areas, node, area)) {
		struct ospf_lsa *lsa_self;

		lsa_self = ospf_lsa_lookup_by_id(area, OSPF_ROUTER_LSA,
						 ospf->router_id);
		if (!lsa_self || !ospf_gr_check_lsa_adjacencies(area, lsa_self)) {
			if (IS_DEBUG_OSPF_GR)
				zlog_debug(
					"GR: not all adjacencies were reestablished yet [area %pI4]",
					&area->area_id);
			return;
		}
	}

	if (IS_DEBUG_OSPF_GR)
		zlog_debug("GR: all adjacencies were reestablished");
	ospf_gr_restart_exit(ospf);
}

static void ospf_gr_lsa_body_set(struct ospf_gr_info *gr_info, struct stream *s,
				 struct ospf_interface *oi)
{
	struct grace_tlv_graceperiod tlv_period = {};
	struct grace_tlv_restart_reason tlv_reason = {};
	struct grace_tlv_restart_addr tlv_address = {};

	/* Put grace period. */
	tlv_period.header.type = htons(GRACE_PERIOD_TYPE);
	tlv_period.header.length = htons(GRACE_PERIOD_LENGTH);
	tlv_period.interval = htonl(gr_info->grace_period);
	stream_put(s, &tlv_period, sizeof(tlv_period));

	/* Put restart reason. */
	tlv_reason.header.type = htons(RESTART_REASON_TYPE);
	tlv_reason.header.length = htons(RESTART_REASON_LENGTH);
	if (gr_info->restart_support)
		tlv_reason.reason = OSPF_GR_SW_RESTART;
	else
		tlv_reason.reason = OSPF_GR_UNKNOWN_RESTART;
	stream_put(s, &tlv_reason, sizeof(tlv_reason));

	/* Put IP address. */
	if (oi->type == OSPF_IFTYPE_BROADCAST || oi->type == OSPF_IFTYPE_NBMA
	    || oi->type == OSPF_IFTYPE_POINTOMULTIPOINT) {
		tlv_address.header.type = htons(RESTARTER_IP_ADDR_TYPE);
		tlv_address.header.length = htons(RESTARTER_IP_ADDR_LEN);
		tlv_address.addr = oi->address->u.prefix4;
		stream_put(s, &tlv_address, sizeof(tlv_address));
	}
}

static struct ospf_lsa *ospf_gr_lsa_new(struct ospf_interface *oi)
{
	struct stream *s;
	struct lsa_header *lsah;
	struct ospf_lsa *new;
	uint8_t options, lsa_type;
	struct in_addr lsa_id;
	uint32_t lsa_id_host_byte_order;
	uint16_t length;

	/* Create a stream for LSA. */
	s = stream_new(OSPF_MAX_LSA_SIZE);

	lsah = (struct lsa_header *)STREAM_DATA(s);

	options = LSA_OPTIONS_GET(oi->area);
	options |= LSA_OPTIONS_NSSA_GET(oi->area);
	options |= OSPF_OPTION_O;

	lsa_type = OSPF_OPAQUE_LINK_LSA;
	lsa_id_host_byte_order = SET_OPAQUE_LSID(OPAQUE_TYPE_GRACE_LSA, 0);
	lsa_id.s_addr = htonl(lsa_id_host_byte_order);

	/* Set opaque-LSA header fields. */
	lsa_header_set(s, options, lsa_type, lsa_id, oi->ospf->router_id);

	/* Set opaque-LSA body fields. */
	ospf_gr_lsa_body_set(&oi->ospf->gr_info, s, oi);

	/* Set length. */
	length = stream_get_endp(s);
	lsah->length = htons(length);

	/* Now, create an OSPF LSA instance. */
	new = ospf_lsa_new_and_data(length);

	if (IS_DEBUG_OSPF_GR)
		zlog_debug("LSA[Type%d:%pI4]: Create an Opaque-LSA/GR instance",
			   lsa_type, &lsa_id);

	new->area = oi->area;
	new->oi = oi;
	SET_FLAG(new->flags, OSPF_LSA_SELF);
	memcpy(new->data, lsah, length);
	stream_free(s);

	return new;
}

static struct ospf_lsa *ospf_gr_lsa_originate(struct ospf_interface *oi)
{
	struct ospf_lsa *lsa, *old;

	if (ospf_interface_neighbor_count(oi) == 0)
		return NULL;

	/* Create new Grace-LSA instance. */
	lsa = ospf_gr_lsa_new(oi);
	if (!lsa) {
		zlog_warn("%s: ospf_gr_lsa_new() failed", __func__);
		return NULL;
	}

	/* Find the old LSA and increase the seqno. */
	old = ospf_gr_lsa_lookup(oi->ospf, oi->area);
	if (old)
		lsa->data->ls_seqnum = lsa_seqnum_increment(old);

	/* Install this LSA into LSDB. */
	if (ospf_lsa_install(oi->ospf, oi, lsa) == NULL) {
		zlog_warn("%s: ospf_lsa_install() failed", __func__);
		ospf_lsa_unlock(&lsa);
		return NULL;
	}

	/* Update new LSA origination count. */
	oi->ospf->lsa_originate_count++;

	/* Flood the LSA through out the interface */
	ospf_flood_through_interface(oi, NULL, lsa);

	return lsa;
}

static int ospf_gr_grace_period_expired(struct thread *thread)
{
	struct ospf *ospf = THREAD_ARG(thread);

	ospf->gr_info.t_grace_period = NULL;

	if (IS_DEBUG_OSPF_GR)
		zlog_debug("GR: grace period has expired");
	ospf_gr_restart_exit(ospf);

	return 0;
}

static char *ospf_gr_nvm_filepath(struct ospf *ospf)
{
	static char filepath[MAXPATHLEN];
	char instance[16] = "";

	if (ospf->instance)
		snprintf(instance, sizeof(instance), "-%d", ospf->instance);
	snprintf(filepath, sizeof(filepath), OSPFD_GR_STATE, instance);
	return filepath;
}

static void ospf_gr_nvm_update(struct ospf *ospf)
{
	char *filepath;
	const char *inst_name;
	json_object *json;
	json_object *json_instances;
	json_object *json_instance;

	filepath = ospf_gr_nvm_filepath(ospf);
	inst_name = ospf->name ? ospf->name : VRF_DEFAULT_NAME;

	json = json_object_from_file(filepath);
	if (json == NULL)
		json = json_object_new_object();

	json_object_object_get_ex(json, "instances", &json_instances);
	if (!json_instances) {
		json_instances = json_object_new_object();
		json_object_object_add(json, "instances", json_instances);
	}

	json_object_object_get_ex(json_instances, inst_name, &json_instance);
	if (!json_instance) {
		json_instance = json_object_new_object();
		json_object_object_add(json_instances, inst_name, json_instance);
	}

	json_object_int_add(json_instance, "gracePeriod",
			    ospf->gr_info.grace_period);
	json_object_int_add(json_instance, "timestamp",
			    time(NULL) + ospf->gr_info.grace_period);

	json_object_to_file_ext(filepath, json, JSON_C_TO_STRING_PRETTY);
	json_object_free(json);
}

static void ospf_gr_nvm_delete(struct ospf *ospf)
{
	char *filepath;
	const char *inst_name;
	json_object *json;
	json_object *json_instances;

	filepath = ospf_gr_nvm_filepath(ospf);
	inst_name = ospf->name ? ospf->name : VRF_DEFAULT_NAME;

	json = json_object_from_file(filepath);
	if (json == NULL)
		json = json_object_new_object();

	json_object_object_get_ex(json, "instances", &json_instances);
	if (!json_instances) {
		json_instances = json_object_new_object();
		json_object_object_add(json, "instances", json_instances);
	}

	json_object_object_del(json_instances, inst_name);

	json_object_to_file_ext(filepath, json, JSON_C_TO_STRING_PRETTY);
	json_object_free(json);
}

void ospf_gr_nvm_read(struct ospf *ospf)
{
	char *filepath;
	const char *inst_name;
	json_object *json;
	json_object *json_instances;
	json_object *json_instance;
	json_object *json_timestamp;
	time_t timestamp = 0;

	filepath = ospf_gr_nvm_filepath(ospf);
	inst_name = ospf->name ? ospf->name : VRF_DEFAULT_NAME;

	json = json_object_from_file(filepath);
	if (json == NULL)
		json = json_object_new_object();

	json_object_object_get_ex(json, "instances", &json_instances);
	if (!json_instances) {
		json_instances = json_object_new_object();
		json_object_object_add(json, "instances", json_instances);
	}

	json_object_object_get_ex(json_instances, inst_name, &json_instance);
	if (!json_instance) {
		json_instance = json_object_new_object();
		json_object_object_add(json_instances, inst_name, json_instance);
	}

	json_object_object_get_ex(json_instance, "timestamp", &json_timestamp);
	if (json_timestamp) {
		time_t now;
		unsigned long remaining_time;

		// check if the grace period has already expired
		now = time(NULL);
		timestamp = json_object_get_int(json_timestamp);

		if (now > timestamp) {
			if (IS_DEBUG_OSPF_GR)
				zlog_debug(
					"GR: grace period has expired already");
			ospf_gr_restart_exit(ospf);
		} else {
			// schedule grace LSA timer
			ospf->gr_info.restart_in_progress = true;
			remaining_time = timestamp - time(NULL);
			if (IS_DEBUG_OSPF_GR)
				zlog_debug(
					"GR: remaining time until grace period expires: %lu(s)",
					remaining_time);

			thread_add_timer(master, ospf_gr_grace_period_expired, ospf,
					 remaining_time,
					 &ospf->gr_info.t_grace_period);
		}
	}

	json_object_object_del(json_instances, inst_name);

	json_object_to_file_ext(filepath, json, JSON_C_TO_STRING_PRETTY);
	json_object_free(json);
}

static void ospf_gr_prepare(void)
{
	struct ospf *ospf;
	struct ospf_interface *oi;
	struct listnode *onode;

	for (ALL_LIST_ELEMENTS_RO(om->ospf, onode, ospf)) {
		struct listnode *inode;

		if (!ospf->gr_info.restart_support
		    || ospf->gr_info.prepare_in_progress)
			continue;

		ospf->gr_info.prepare_in_progress = true;

		if (IS_DEBUG_OSPF_GR)
			zlog_debug(
				"GR: preparing to perform a graceful restart [period %u second(s)]",
				ospf->gr_info.grace_period);

		if (ospf_zebra_gr_enable(ospf, ospf->gr_info.grace_period)) {
			zlog_warn("%s: failed to activate graceful restart", __func__);
			continue;
		}

		/* Send a Grace-LSA to all neighbors */
		for (ALL_LIST_ELEMENTS_RO(ospf->oiflist, inode, oi))
			ospf_gr_lsa_originate(oi);

		/* Record timestamp in non-volatile memory */
		ospf_gr_nvm_update(ospf);
	}
}

DEFUN(graceful_restart_prepare, graceful_restart_prepare_cmd,
      "graceful-restart prepare ospf",
      "Graceful Restart commands\n"
      "Prepare upcoming graceful restart\n"
      "Prepare to restart the OSPF process")
{
	ospf_gr_prepare();

	return CMD_SUCCESS;
}

DEFUN(graceful_restart, graceful_restart_cmd,
      "graceful-restart [grace-period (1-1800)]",
      OSPF_GR_STR
      "Maximum length of the 'grace period'\n"
      "Maximum length of the 'grace period' in seconds\n")
{
	VTY_DECLVAR_INSTANCE_CONTEXT(ospf, ospf);
	uint16_t grace_period;
	int idx = 2;

	/* Check and get restart period if present */
	if (argc > 1)
		grace_period = strtoul(argv[idx]->arg, NULL, 10);
	else
		grace_period = OSPF_GR_DEFAULT_GRACE_PERIOD;

	if (!ospf->gr_info.restart_support)
		ospf->gr_info.restart_support = true;
	ospf->gr_info.grace_period = grace_period;

	return CMD_SUCCESS;
}

DEFUN(no_graceful_restart, no_graceful_restart_cmd,
      "no graceful-restart [period (1-1800)]",
      NO_STR OSPF_GR_STR
      "Maximum length of the 'grace period'\n"
      "Maximum length of the 'grace period' in seconds\n")
{
	VTY_DECLVAR_INSTANCE_CONTEXT(ospf, ospf);

	if (!ospf->gr_info.restart_support)
		return CMD_SUCCESS;

	ospf->gr_info.restart_support = false;
	ospf->gr_info.grace_period = OSPF_GR_DEFAULT_GRACE_PERIOD;

	return CMD_SUCCESS;
}

void ospf_gr_init(void)
{
	install_element(ENABLE_NODE, &graceful_restart_prepare_cmd);
	install_element(OSPF_NODE, &graceful_restart_cmd);
	install_element(OSPF_NODE, &no_graceful_restart_cmd);
}
