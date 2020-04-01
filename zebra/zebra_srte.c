/* Zebra SR-TE code
 * Copyright (C) 2020  NetDEF, Inc.
 *
 * This file is part of GNU Zebra.
 *
 * GNU Zebra is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2, or (at your option) any
 * later version.
 *
 * GNU Zebra is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; see the file COPYING; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
 */

#include "lib/zclient.h"
#include "lib/lib_errors.h"

#include "zebra/zebra_srte.h"
#include "zebra/zebra_memory.h"
#include "zebra/zebra_mpls.h"
#include "zebra/zebra_rnh.h"
#include "zebra/zapi_msg.h"

DEFINE_MTYPE_STATIC(ZEBRA, ZEBRA_SR_POLICY, "SR Policy")

/* Generate rb-tree of SR Policy instances. */
static inline int
zebra_sr_policy_instance_compare(const struct zebra_sr_policy *a,
				 const struct zebra_sr_policy *b)
{
	return sr_policy_compare(&a->endpoint, &b->endpoint, a->color,
				 b->color);
}
RB_GENERATE(zebra_sr_policy_instance_head, zebra_sr_policy, entry,
	    zebra_sr_policy_instance_compare)

struct zebra_sr_policy_instance_head zebra_sr_policy_instances =
	RB_INITIALIZER(&zebra_sr_policy_instances);

struct zebra_sr_policy *zebra_sr_policy_add(uint32_t color,
					    struct ipaddr *endpoint, char *name)
{
	struct zebra_sr_policy *policy;

	policy = XCALLOC(MTYPE_ZEBRA_SR_POLICY, sizeof(*policy));
	policy->color = color;
	policy->endpoint = *endpoint;
	strlcpy(policy->name, name, sizeof(policy->name));
	policy->status = ZEBRA_SR_POLICY_UNKNOWN;
	RB_INSERT(zebra_sr_policy_instance_head, &zebra_sr_policy_instances,
		  policy);

	return policy;
}

void zebra_sr_policy_del(struct zebra_sr_policy *policy)
{
	if (policy->status == ZEBRA_SR_POLICY_UP)
		zebra_sr_policy_bsid_uninstall(policy);
	RB_REMOVE(zebra_sr_policy_instance_head, &zebra_sr_policy_instances,
		  policy);
	XFREE(MTYPE_ZEBRA_SR_POLICY, policy);
}

struct zebra_sr_policy *zebra_sr_policy_find(uint32_t color,
					     struct ipaddr *endpoint)
{
	struct zebra_sr_policy policy = {};

	policy.color = color;
	policy.endpoint = *endpoint;
	return RB_FIND(zebra_sr_policy_instance_head,
		       &zebra_sr_policy_instances, &policy);
}

struct zebra_sr_policy *zebra_sr_policy_find_by_name(char *name)
{
	struct zebra_sr_policy *policy;

	// TODO: create index for policy names
	RB_FOREACH (policy, zebra_sr_policy_instance_head,
		    &zebra_sr_policy_instances) {
		if (strcmp(policy->name, name) == 0)
			return policy;
	}

	return NULL;
}

static void zebra_sr_policy_notify_update(struct zebra_sr_policy *policy)
{
	struct rnh *rnh;
	struct prefix p = {};
	struct zebra_vrf *zvrf;
	struct listnode *node;
	struct zserv *client;

	zvrf = policy->zvrf;
	switch (policy->endpoint.ipa_type) {
	case IPADDR_V4:
		p.family = AF_INET;
		p.prefixlen = IPV4_MAX_BITLEN;
		p.u.prefix4 = policy->endpoint.ipaddr_v4;
		break;
	case IPADDR_V6:
		p.family = AF_INET6;
		p.prefixlen = IPV6_MAX_BITLEN;
		p.u.prefix6 = policy->endpoint.ipaddr_v6;
		break;
	default:
		flog_warn(EC_LIB_DEVELOPMENT,
			  "%s: unknown policy endpoint address family: %u",
			  __func__, policy->endpoint.ipa_type);
		exit(1);
	}

	rnh = zebra_lookup_rnh(&p, zvrf_id(zvrf), RNH_NEXTHOP_TYPE);
	if (!rnh)
		return;

	for (ALL_LIST_ELEMENTS_RO(rnh->client_list, node, client))
		send_client(rnh, client, RNH_NEXTHOP_TYPE, zvrf_id(zvrf),
			    policy->color);
}

static void zebra_sr_policy_activate(struct zebra_sr_policy *policy,
				     zebra_lsp_t *lsp)
{
	policy->status = ZEBRA_SR_POLICY_UP;
	policy->lsp = lsp;
	zsend_sr_policy_notify_status(policy->color, &policy->endpoint,
				      policy->name, ZEBRA_SR_POLICY_UP);
	zebra_sr_policy_notify_update(policy);
	(void)zebra_sr_policy_bsid_install(policy);
}

static void zebra_sr_policy_deactivate(struct zebra_sr_policy *policy)
{
	zebra_sr_policy_bsid_uninstall(policy);
	policy->status = ZEBRA_SR_POLICY_DOWN;
	policy->lsp = NULL;
	zsend_sr_policy_notify_status(policy->color, &policy->endpoint,
				      policy->name, ZEBRA_SR_POLICY_DOWN);
	zebra_sr_policy_notify_update(policy);
}

int zebra_sr_policy_validate(struct zebra_sr_policy *policy)
{
	struct zapi_srte_tunnel *zt = &policy->segment_list;
	zebra_lsp_t *lsp;

	/* Try to resolve the Binding-SID nexthops. */
	lsp = mpls_lsp_find(policy->zvrf, zt->labels[0]);
	if (!lsp || !(lsp->best_nhlfe)
	    || lsp->addr_family != ipaddr_family(&policy->endpoint)) {
		zebra_sr_policy_deactivate(policy);
		return -1;
	}

	zebra_sr_policy_activate(policy, lsp);

	return 0;
}

int zebra_sr_policy_bsid_install(struct zebra_sr_policy *policy)
{
	struct zapi_srte_tunnel *zt = &policy->segment_list;
	zebra_nhlfe_t *nhlfe;

	if (zt->local_label == MPLS_LABEL_NONE)
		return 0;

	frr_each_safe(nhlfe_list, &policy->lsp->nhlfe_list, nhlfe) {
		if (!CHECK_FLAG(nhlfe->flags, NHLFE_FLAG_SELECTED)
		    || CHECK_FLAG(nhlfe->flags, NHLFE_FLAG_DELETED))
			continue;

		if (mpls_lsp_install(
			    policy->zvrf, zt->type, zt->local_label,
			    zt->label_num, zt->labels, nhlfe->nexthop->type,
			    &nhlfe->nexthop->gate, nhlfe->nexthop->ifindex)
		    < 0)
			return -1;
	}

	return 0;
}

void zebra_sr_policy_bsid_uninstall(struct zebra_sr_policy *policy)
{
	struct zapi_srte_tunnel *zt = &policy->segment_list;

	if (zt->local_label == MPLS_LABEL_NONE)
		return;

	mpls_lsp_uninstall_all_vrf(policy->zvrf, zt->type, zt->local_label);
}

static int zebra_sr_policy_process_label_update(
	mpls_label_t label, enum zebra_sr_policy_update_label_mode mode)
{
	struct zebra_sr_policy *policy;

	RB_FOREACH (policy, zebra_sr_policy_instance_head,
		    &zebra_sr_policy_instances) {
		struct zapi_srte_tunnel *zt;
		mpls_label_t next_hop_label;

		zt = &policy->segment_list;
		next_hop_label = zt->labels[0];
		if (next_hop_label != label)
			continue;

		switch (mode) {
		case ZEBRA_SR_POLICY_LABEL_CREATED:
		case ZEBRA_SR_POLICY_LABEL_UPDATED:
		case ZEBRA_SR_POLICY_LABEL_REMOVED:
			if (policy->status == ZEBRA_SR_POLICY_UP)
				zebra_sr_policy_bsid_uninstall(policy);
			zebra_sr_policy_validate(policy);
			break;
		}
	}

	return 0;
}

static int zebra_sr_policy_nexthop_label_created(mpls_label_t label)
{
	return zebra_sr_policy_process_label_update(
		label, ZEBRA_SR_POLICY_LABEL_CREATED);
}

static int zebra_sr_policy_nexthop_label_updated(mpls_label_t label)
{
	return zebra_sr_policy_process_label_update(
		label, ZEBRA_SR_POLICY_LABEL_UPDATED);
}

static int zebra_sr_policy_nexthop_label_removed(mpls_label_t label)
{
	return zebra_sr_policy_process_label_update(
		label, ZEBRA_SR_POLICY_LABEL_REMOVED);
}

void zebra_srte_init(void)
{
	hook_register(zebra_mpls_label_created,
		      zebra_sr_policy_nexthop_label_created);
	hook_register(zebra_mpls_label_updated,
		      zebra_sr_policy_nexthop_label_updated);
	hook_register(zebra_mpls_label_removed,
		      zebra_sr_policy_nexthop_label_removed);
}
