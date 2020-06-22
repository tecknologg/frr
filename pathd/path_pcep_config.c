/*
 * Copyright (C) 2020  NetDEF, Inc.
 *                     Sebastien Merle
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

#include <northbound.h>
#include <yang.h>
#include <printfrr.h>
#include <pcep-objects.h>
#include "pathd/pathd.h"
#include "pathd/path_pcep.h"
#include "pathd/path_pcep_config.h"
#include "pathd/path_pcep_debug.h"

#define MAX_XPATH 256
#define MAX_FLOAT_LEN 22
#define INETADDR4_MAXLEN 16
#define INETADDR6_MAXLEN 40


static struct path_hop *
path_pcep_config_list_path_hops(struct srte_segment_list *segment_list);

static void path_pcep_config_delete_lsp_segment_list(struct lsp_nb_key *key);
static void path_pcep_config_add_segment_list_segment(
	struct srte_segment_list *segment_list, uint32_t index, uint32_t label);
static void path_pcep_config_add_segment_list_segment_no_nai(
	struct srte_segment_list *segment_list, uint32_t index);
static void path_pcep_config_add_segment_list_segment_nai_ipv4_node(
	struct srte_segment_list *segment_list, uint32_t index,
	struct ipaddr *ip);
static void path_pcep_config_add_segment_list_segment_nai_ipv6_node(
	struct srte_segment_list *segment_list, uint32_t index,
	struct ipaddr *ip);
static void path_pcep_config_add_segment_list_segment_nai_ipv4_adj(
	struct srte_segment_list *segment_list, uint32_t index,
	struct ipaddr *local_ip, struct ipaddr *remote_ip);
static void path_pcep_config_add_segment_list_segment_nai_ipv6_adj(
	struct srte_segment_list *segment_list, uint32_t index,
	struct ipaddr *local_ip, struct ipaddr *remote_ip);
static void path_pcep_config_add_segment_list_segment_nai_ipv4_unnumbered_adj(
	struct srte_segment_list *segment_list, uint32_t index,
	struct ipaddr *local_ip, uint32_t local_iface, struct ipaddr *remote_ip,
	uint32_t remote_iface);
static struct srte_segment_list *
path_pcep_config_create_segment_list(const char *segment_list_name,
				     enum srte_protocol_origin protocol,
				     const char *originator);
static void path_pcep_config_update_lsp(struct lsp_nb_key *key,
					struct srte_segment_list *segment_list);
static void path_pcep_config_add_lsp_metric(uint32_t color,
					    struct ipaddr *endpoint,
					    uint32_t preference,
					    enum pcep_metric_types type,
					    float value, bool is_bound,
					    bool is_computed);
static void path_pcep_config_set_lsp_bandwidth(uint32_t color,
					       struct ipaddr *endpoint,
					       uint32_t preference,
					       float value);

static struct srte_candidate *lookup_candidate(struct lsp_nb_key *key);
static char *candidate_name(struct srte_candidate *candidate);
static enum pcep_lsp_operational_status
status_int_to_ext(enum srte_policy_status status);
static enum pcep_sr_subobj_nai pcep_nai_type(enum srte_segment_nai_type type);

void path_pcep_config_lookup(struct path *path)
{
	struct srte_candidate *candidate = lookup_candidate(&path->nbkey);
	struct srte_lsp *lsp = candidate->lsp;
	;

	if (candidate == NULL)
		return;
	if (path->name == NULL)
		path->name = candidate_name(candidate);
	if (path->type == SRTE_CANDIDATE_TYPE_UNDEFINED)
		path->type = candidate->type;
	if (path->create_origin == SRTE_ORIGIN_UNDEFINED)
		path->create_origin = candidate->protocol_origin;
	if ((path->update_origin == SRTE_ORIGIN_UNDEFINED)
	    && (lsp->segment_list != NULL))
		path->update_origin = lsp->segment_list->protocol_origin;
}

struct path *path_pcep_config_get_path(struct lsp_nb_key *key)
{
	struct srte_candidate *candidate = lookup_candidate(key);
	if (candidate == NULL)
		return NULL;
	return candidate_to_path(candidate);
}

void path_pcep_config_list_path(path_list_cb_t cb, void *arg)
{
	struct path *path;
	struct srte_policy *policy;
	struct srte_candidate *candidate;

	RB_FOREACH (policy, srte_policy_head, &srte_policies) {
		RB_FOREACH (candidate, srte_candidate_head,
			    &policy->candidate_paths) {
			path = candidate_to_path(candidate);
			if (!cb(path, arg))
				return;
		}
	}
}

struct path *candidate_to_path(struct srte_candidate *candidate)
{
	char *name;
	struct path *path;
	struct path_hop *hop = NULL;
	struct path_metric *metric = NULL;
	struct srte_policy *policy;
	struct srte_lsp *lsp;
	enum pcep_lsp_operational_status status;
	enum srte_protocol_origin update_origin = 0;
	char *originator = NULL;

	policy = candidate->policy;
	lsp = candidate->lsp;

	if (lsp->segment_list != NULL) {
		hop = path_pcep_config_list_path_hops(lsp->segment_list);
		update_origin = lsp->segment_list->protocol_origin;
		originator = XSTRDUP(MTYPE_PCEP, lsp->segment_list->originator);
	}
	path = pcep_new_path();
	name = candidate_name(candidate);
	if (CHECK_FLAG(candidate->flags, F_CANDIDATE_BEST)) {
		status = status_int_to_ext(policy->status);
	} else {
		status = PCEP_LSP_OPERATIONAL_DOWN;
	}
	if (CHECK_FLAG(lsp->flags, F_CANDIDATE_HAS_METRIC_ABC)) {
		struct path_metric *new_metric = pcep_new_metric();
		new_metric->next = metric;
		metric = new_metric;
		metric->type = PCEP_METRIC_AGGREGATE_BW;
		metric->value = lsp->metric_abc;
		metric->is_bound =
			CHECK_FLAG(lsp->flags, F_CANDIDATE_METRIC_ABC_BOUND);
		metric->is_computed =
			CHECK_FLAG(lsp->flags, F_CANDIDATE_METRIC_ABC_COMPUTED);
	}
	if (CHECK_FLAG(lsp->flags, F_CANDIDATE_HAS_METRIC_TE)) {
		struct path_metric *new_metric = pcep_new_metric();
		new_metric->next = metric;
		metric = new_metric;
		metric->type = PCEP_METRIC_TE;
		metric->value = lsp->metric_te;
		metric->is_bound =
			CHECK_FLAG(lsp->flags, F_CANDIDATE_METRIC_TE_BOUND);
		metric->is_computed =
			CHECK_FLAG(lsp->flags, F_CANDIDATE_METRIC_TE_COMPUTED);
	}
	*path = (struct path){
		.nbkey = (struct lsp_nb_key){.color = policy->color,
					     .endpoint = policy->endpoint,
					     .preference =
						     candidate->preference},
		.create_origin = lsp->protocol_origin,
		.update_origin = update_origin,
		.originator = originator,
		.plsp_id = 0,
		.name = name,
		.type = candidate->type,
		.srp_id = 0,
		.req_id = 0,
		.binding_sid = policy->binding_sid,
		.status = status,
		.do_remove = false,
		.go_active = false,
		.was_created = false,
		.was_removed = false,
		.is_synching = false,
		.is_delegated = false,
		.first_hop = hop,
		.first_metric = metric};

	path->has_bandwidth = CHECK_FLAG(lsp->flags, F_CANDIDATE_HAS_BANDWIDTH);
	path->bandwidth = lsp->bandwidth;

	return path;
}

struct path_hop *
path_pcep_config_list_path_hops(struct srte_segment_list *segment_list)
{
	struct srte_segment_entry *segment;
	struct path_hop *hop = NULL, *last_hop = NULL;

	RB_FOREACH_REVERSE (segment, srte_segment_entry_head,
			    &segment_list->segments) {
		hop = pcep_new_hop();
		*hop = (struct path_hop){
			.next = last_hop,
			.is_loose = false,
			.has_sid = true,
			.is_mpls = true,
			.has_attribs = false,
			.sid = {.mpls = {.label = segment->sid_value}},
			.has_nai =
				segment->nai_type != SRTE_SEGMENT_NAI_TYPE_NONE,
			.nai = {.type = pcep_nai_type(segment->nai_type)}};
		switch (segment->nai_type) {
		case SRTE_SEGMENT_NAI_TYPE_IPV4_NODE:
		case SRTE_SEGMENT_NAI_TYPE_IPV6_NODE:
			memcpy(&hop->nai.local_addr, &segment->nai_local_addr,
			       sizeof(struct ipaddr));
			break;
		case SRTE_SEGMENT_NAI_TYPE_IPV4_ADJACENCY:
		case SRTE_SEGMENT_NAI_TYPE_IPV6_ADJACENCY:
			memcpy(&hop->nai.local_addr, &segment->nai_local_addr,
			       sizeof(struct ipaddr));
			memcpy(&hop->nai.remote_addr, &segment->nai_remote_addr,
			       sizeof(struct ipaddr));
			break;
		case SRTE_SEGMENT_NAI_TYPE_IPV4_UNNUMBERED_ADJACENCY:
			memcpy(&hop->nai.local_addr, &segment->nai_local_addr,
			       sizeof(struct ipaddr));
			hop->nai.local_iface = segment->nai_local_iface;
			memcpy(&hop->nai.remote_addr, &segment->nai_remote_addr,
			       sizeof(struct ipaddr));
			hop->nai.remote_iface = segment->nai_remote_iface;
			break;
		default:
			break;
		}
		last_hop = hop;
	}
	return hop;
}

int path_pcep_config_update_path(struct path *path)
{
	assert(path != NULL);
	assert(path->nbkey.preference != 0);
	assert(path->nbkey.endpoint.ipa_type == IPADDR_V4);

	struct path_hop *hop;
	struct path_metric *metric;
	int index;
	char segment_list_name_buff[64 + 1 + 64 + 1 + 11 + 1];
	char *segment_list_name = NULL;
	struct srte_segment_list *segment_list;

	path_pcep_config_delete_lsp_segment_list(&path->nbkey);

	if (path->first_hop != NULL) {

		snprintf(segment_list_name_buff, sizeof(segment_list_name_buff),
			 "%s-%u", path->name, path->plsp_id);
		segment_list_name = segment_list_name_buff;
		segment_list = path_pcep_config_create_segment_list(
			segment_list_name, path->update_origin,
			path->originator);
		for (hop = path->first_hop, index = 10; hop != NULL;
		     hop = hop->next, index += 10) {
			assert(hop->has_sid);
			assert(hop->is_mpls);
			path_pcep_config_add_segment_list_segment(
				segment_list, index, hop->sid.mpls.label);
			if (hop->has_nai) {
				switch (hop->nai.type) {
				case PCEP_SR_SUBOBJ_NAI_IPV4_NODE:
					path_pcep_config_add_segment_list_segment_nai_ipv4_node(
						segment_list, index,
						&hop->nai.local_addr);
					break;
				case PCEP_SR_SUBOBJ_NAI_IPV6_NODE:
					path_pcep_config_add_segment_list_segment_nai_ipv6_node(
						segment_list, index,
						&hop->nai.local_addr);
					break;
				case PCEP_SR_SUBOBJ_NAI_IPV4_ADJACENCY:
					path_pcep_config_add_segment_list_segment_nai_ipv4_adj(
						segment_list, index,
						&hop->nai.local_addr,
						&hop->nai.remote_addr);
					break;
				case PCEP_SR_SUBOBJ_NAI_IPV6_ADJACENCY:
					path_pcep_config_add_segment_list_segment_nai_ipv6_adj(
						segment_list, index,
						&hop->nai.local_addr,
						&hop->nai.remote_addr);
					break;
				case PCEP_SR_SUBOBJ_NAI_UNNUMBERED_IPV4_ADJACENCY:
					path_pcep_config_add_segment_list_segment_nai_ipv4_unnumbered_adj(
						segment_list, index,
						&hop->nai.local_addr,
						hop->nai.local_iface,
						&hop->nai.remote_addr,
						hop->nai.remote_iface);
					break;
				default:
					path_pcep_config_add_segment_list_segment_no_nai(
						segment_list, index);
					break;
				}
			}
		}
	}

	path_pcep_config_update_lsp(&path->nbkey, segment_list);

	for (metric = path->first_metric; metric != NULL;
	     metric = metric->next) {
		path_pcep_config_add_lsp_metric(
			path->nbkey.color, &path->nbkey.endpoint,
			path->nbkey.preference, metric->type, metric->value,
			metric->is_bound, metric->is_computed);
	}

	if (path->has_bandwidth) {
		path_pcep_config_set_lsp_bandwidth(
			path->nbkey.color, &path->nbkey.endpoint,
			path->nbkey.preference, path->bandwidth);
	}

	srte_apply_changes();

	return 0;
}

/* Delete the candidate path segment list if it was created through PCEP
   and by the given originator */
void path_pcep_config_delete_lsp_segment_list(struct lsp_nb_key *key)
{
	struct srte_candidate *candidate = lookup_candidate(key);

	if ((candidate == NULL) || (candidate->lsp->segment_list == NULL))
		return;

	SET_FLAG(candidate->lsp->segment_list->flags, F_SEGMENT_LIST_DELETED);

	candidate->lsp->segment_list = NULL;
	SET_FLAG(candidate->flags, F_CANDIDATE_MODIFIED);
}

void path_pcep_config_add_segment_list_segment(
	struct srte_segment_list *segment_list, uint32_t index, uint32_t label)
{
	struct srte_segment_entry *segment;

	segment = srte_segment_entry_add(segment_list, index);
	segment->sid_value = (mpls_label_t)label;
	SET_FLAG(segment->segment_list->flags, F_SEGMENT_LIST_MODIFIED);
}

void path_pcep_config_add_segment_list_segment_no_nai(
	struct srte_segment_list *segment_list, uint32_t index)
{
	struct srte_segment_entry *segment;

	segment = srte_segment_entry_find(segment_list, index);
	segment->nai_type = SRTE_SEGMENT_NAI_TYPE_NONE;
	segment->nai_local_addr.ipa_type = IPADDR_NONE;
	segment->nai_local_iface = 0;
	segment->nai_remote_addr.ipa_type = IPADDR_NONE;
	segment->nai_remote_iface = 0;
}

void path_pcep_config_add_segment_list_segment_nai_ipv4_node(
	struct srte_segment_list *segment_list, uint32_t index,
	struct ipaddr *ip)
{
	struct srte_segment_entry *segment;

	segment = srte_segment_entry_find(segment_list, index);
	segment->nai_type = SRTE_SEGMENT_NAI_TYPE_IPV4_NODE;
	memcpy(&segment->nai_local_addr, ip, sizeof(struct ipaddr));
}

void path_pcep_config_add_segment_list_segment_nai_ipv6_node(
	struct srte_segment_list *segment_list, uint32_t index,
	struct ipaddr *ip)
{
	struct srte_segment_entry *segment;

	segment = srte_segment_entry_find(segment_list, index);
	segment->nai_type = SRTE_SEGMENT_NAI_TYPE_IPV6_NODE;
	memcpy(&segment->nai_local_addr, ip, sizeof(struct ipaddr));
}

void path_pcep_config_add_segment_list_segment_nai_ipv4_adj(
	struct srte_segment_list *segment_list, uint32_t index,
	struct ipaddr *local_ip, struct ipaddr *remote_ip)
{
	struct srte_segment_entry *segment;

	segment = srte_segment_entry_find(segment_list, index);
	segment->nai_type = SRTE_SEGMENT_NAI_TYPE_IPV4_ADJACENCY;
	memcpy(&segment->nai_local_addr, local_ip, sizeof(struct ipaddr));
	memcpy(&segment->nai_remote_addr, remote_ip, sizeof(struct ipaddr));
}

void path_pcep_config_add_segment_list_segment_nai_ipv6_adj(
	struct srte_segment_list *segment_list, uint32_t index,
	struct ipaddr *local_ip, struct ipaddr *remote_ip)
{
	struct srte_segment_entry *segment;

	segment = srte_segment_entry_find(segment_list, index);
	segment->nai_type = SRTE_SEGMENT_NAI_TYPE_IPV6_ADJACENCY;
	memcpy(&segment->nai_local_addr, local_ip, sizeof(struct ipaddr));
	memcpy(&segment->nai_remote_addr, remote_ip, sizeof(struct ipaddr));
}

void path_pcep_config_add_segment_list_segment_nai_ipv4_unnumbered_adj(
	struct srte_segment_list *segment_list, uint32_t index,
	struct ipaddr *local_ip, uint32_t local_iface, struct ipaddr *remote_ip,
	uint32_t remote_iface)
{
	struct srte_segment_entry *segment;

	segment = srte_segment_entry_find(segment_list, index);
	segment->nai_type = SRTE_SEGMENT_NAI_TYPE_IPV4_UNNUMBERED_ADJACENCY;
	memcpy(&segment->nai_local_addr, local_ip, sizeof(struct ipaddr));
	memcpy(&segment->nai_remote_addr, remote_ip, sizeof(struct ipaddr));
	segment->nai_local_iface = local_iface;
	segment->nai_remote_iface = remote_iface;
}

struct srte_segment_list *
path_pcep_config_create_segment_list(const char *segment_list_name,
				     enum srte_protocol_origin protocol,
				     const char *originator)
{
	struct srte_segment_list *segment_list;

	segment_list = srte_segment_list_add(segment_list_name);
	SET_FLAG(segment_list->flags, F_SEGMENT_LIST_NEW);

	segment_list->protocol_origin = protocol;
	strlcpy(segment_list->originator, originator,
		sizeof(segment_list->originator));
	SET_FLAG(segment_list->flags, F_SEGMENT_LIST_MODIFIED);

	return segment_list;
}

void path_pcep_config_update_lsp(struct lsp_nb_key *key,
				 struct srte_segment_list *segment_list)
{
	struct srte_policy *policy;
	struct srte_candidate *candidate;

	policy = srte_policy_find(key->color, &key->endpoint);
	candidate = srte_candidate_find(policy, key->preference);

	candidate->lsp->segment_list = segment_list;
	assert(candidate->lsp->segment_list);

	SET_FLAG(candidate->flags, F_CANDIDATE_MODIFIED);
}

void path_pcep_config_add_lsp_metric(uint32_t color, struct ipaddr *endpoint,
				     uint32_t preference,
				     enum pcep_metric_types type, float value,
				     bool is_bound, bool is_computed)
{
	struct srte_policy *policy;
	struct srte_candidate *candidate;

	policy = srte_policy_find(color, endpoint);
	candidate = srte_candidate_find(policy, preference);

	srte_lsp_set_metric(candidate->lsp, type, value, is_bound, is_computed);
}

void path_pcep_config_set_lsp_bandwidth(uint32_t color, struct ipaddr *endpoint,
					uint32_t preference, float value)
{
	struct srte_policy *policy;
	struct srte_candidate *candidate;

	policy = srte_policy_find(color, endpoint);
	candidate = srte_candidate_find(policy, preference);

	srte_lsp_set_bandwidth(candidate->lsp, value);
}

struct srte_candidate *lookup_candidate(struct lsp_nb_key *key)
{
	struct srte_policy *policy = NULL;
	policy = srte_policy_find(key->color, &key->endpoint);
	if (policy == NULL)
		return NULL;
	return srte_candidate_find(policy, key->preference);
}

char *candidate_name(struct srte_candidate *candidate)
{
	return asprintfrr(MTYPE_PCEP, "%s-%s", candidate->policy->name,
			  candidate->name);
}

enum pcep_lsp_operational_status
status_int_to_ext(enum srte_policy_status status)
{
	switch (status) {
	case SRTE_POLICY_STATUS_UP:
		return PCEP_LSP_OPERATIONAL_ACTIVE;
	case SRTE_POLICY_STATUS_GOING_UP:
		return PCEP_LSP_OPERATIONAL_GOING_UP;
	case SRTE_POLICY_STATUS_GOING_DOWN:
		return PCEP_LSP_OPERATIONAL_GOING_DOWN;
	default:
		return PCEP_LSP_OPERATIONAL_DOWN;
	}
}

enum pcep_sr_subobj_nai pcep_nai_type(enum srte_segment_nai_type type)
{
	switch (type) {
	case SRTE_SEGMENT_NAI_TYPE_NONE:
		return PCEP_SR_SUBOBJ_NAI_ABSENT;
	case SRTE_SEGMENT_NAI_TYPE_IPV4_NODE:
		return PCEP_SR_SUBOBJ_NAI_IPV4_NODE;
	case SRTE_SEGMENT_NAI_TYPE_IPV6_NODE:
		return PCEP_SR_SUBOBJ_NAI_IPV6_NODE;
	case SRTE_SEGMENT_NAI_TYPE_IPV4_ADJACENCY:
		return PCEP_SR_SUBOBJ_NAI_IPV4_ADJACENCY;
	case SRTE_SEGMENT_NAI_TYPE_IPV6_ADJACENCY:
		return PCEP_SR_SUBOBJ_NAI_IPV6_ADJACENCY;
	case SRTE_SEGMENT_NAI_TYPE_IPV4_UNNUMBERED_ADJACENCY:
		return PCEP_SR_SUBOBJ_NAI_UNNUMBERED_IPV4_ADJACENCY;
	default:
		return PCEP_SR_SUBOBJ_NAI_UNKNOWN;
	}
}
