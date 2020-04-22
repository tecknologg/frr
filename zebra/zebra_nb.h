/*
 * Copyright (C) 2020 Cumulus Networks, Inc.
 *                    Chirag Shah
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

#ifndef ZEBRA_ZEBRA_NB_H_
#define ZEBRA_ZEBRA_NB_H_

extern const struct frr_yang_module_info frr_zebra_info;

/* prototypes */
int get_route_information_rpc(NB_CB_RPC_ARGS);
int get_v6_mroute_info_rpc(NB_CB_RPC_ARGS);
int get_vrf_info_rpc(NB_CB_RPC_ARGS);
int get_vrf_vni_info_rpc(NB_CB_RPC_ARGS);
int get_evpn_info_rpc(NB_CB_RPC_ARGS);
int get_vni_info_rpc(NB_CB_RPC_ARGS);
int get_evpn_vni_rmac_rpc(NB_CB_RPC_ARGS);
int get_evpn_vni_nexthops_rpc(NB_CB_RPC_ARGS);
int clear_evpn_dup_addr_rpc(NB_CB_RPC_ARGS);
int get_evpn_macs_rpc(NB_CB_RPC_ARGS);
int get_evpn_arp_cache_rpc(NB_CB_RPC_ARGS);
int get_pbr_ipset_rpc(NB_CB_RPC_ARGS);
int get_pbr_iptable_rpc(NB_CB_RPC_ARGS);
int get_debugs_rpc(NB_CB_RPC_ARGS);
int zebra_mcast_rpf_lookup_modify(NB_CB_MODIFY_ARGS);
int zebra_ip_forwarding_modify(NB_CB_MODIFY_ARGS);
int zebra_ip_forwarding_destroy(NB_CB_DESTROY_ARGS);
int zebra_ipv6_forwarding_modify(NB_CB_MODIFY_ARGS);
int zebra_ipv6_forwarding_destroy(NB_CB_DESTROY_ARGS);
int zebra_workqueue_hold_timer_modify(NB_CB_MODIFY_ARGS);
int zebra_zapi_packets_modify(NB_CB_MODIFY_ARGS);
int zebra_import_kernel_table_table_id_modify(NB_CB_MODIFY_ARGS);
int zebra_import_kernel_table_table_id_destroy(NB_CB_DESTROY_ARGS);
int zebra_import_kernel_table_distance_modify(NB_CB_MODIFY_ARGS);
int zebra_import_kernel_table_route_map_modify(NB_CB_MODIFY_ARGS);
int zebra_import_kernel_table_route_map_destroy(NB_CB_DESTROY_ARGS);
int zebra_allow_external_route_update_create(NB_CB_CREATE_ARGS);
int zebra_allow_external_route_update_destroy(NB_CB_DESTROY_ARGS);
int zebra_dplane_queue_limit_modify(NB_CB_MODIFY_ARGS);
int zebra_vrf_vni_mapping_create(NB_CB_CREATE_ARGS);
int zebra_vrf_vni_mapping_destroy(NB_CB_DESTROY_ARGS);
int zebra_vrf_vni_mapping_vni_id_modify(NB_CB_MODIFY_ARGS);
int zebra_vrf_vni_mapping_vni_id_destroy(NB_CB_DESTROY_ARGS);
int zebra_vrf_vni_mapping_prefix_only_create(NB_CB_CREATE_ARGS);
int zebra_vrf_vni_mapping_prefix_only_destroy(NB_CB_DESTROY_ARGS);
int zebra_debugs_debug_events_modify(NB_CB_MODIFY_ARGS);
int zebra_debugs_debug_events_destroy(NB_CB_DESTROY_ARGS);
int zebra_debugs_debug_zapi_send_modify(NB_CB_MODIFY_ARGS);
int zebra_debugs_debug_zapi_send_destroy(NB_CB_DESTROY_ARGS);
int zebra_debugs_debug_zapi_recv_modify(NB_CB_MODIFY_ARGS);
int zebra_debugs_debug_zapi_recv_destroy(NB_CB_DESTROY_ARGS);
int zebra_debugs_debug_zapi_detail_modify(NB_CB_MODIFY_ARGS);
int zebra_debugs_debug_zapi_detail_destroy(NB_CB_DESTROY_ARGS);
int zebra_debugs_debug_kernel_modify(NB_CB_MODIFY_ARGS);
int zebra_debugs_debug_kernel_destroy(NB_CB_DESTROY_ARGS);
int zebra_debugs_debug_kernel_msg_send_modify(NB_CB_MODIFY_ARGS);
int zebra_debugs_debug_kernel_msg_send_destroy(NB_CB_DESTROY_ARGS);
int zebra_debugs_debug_kernel_msg_recv_modify(NB_CB_MODIFY_ARGS);
int zebra_debugs_debug_kernel_msg_recv_destroy(NB_CB_DESTROY_ARGS);
int zebra_debugs_debug_rib_modify(NB_CB_MODIFY_ARGS);
int zebra_debugs_debug_rib_destroy(NB_CB_DESTROY_ARGS);
int zebra_debugs_debug_rib_detail_modify(NB_CB_MODIFY_ARGS);
int zebra_debugs_debug_rib_detail_destroy(NB_CB_DESTROY_ARGS);
int zebra_debugs_debug_fpm_modify(NB_CB_MODIFY_ARGS);
int zebra_debugs_debug_fpm_destroy(NB_CB_DESTROY_ARGS);
int zebra_debugs_debug_nht_modify(NB_CB_MODIFY_ARGS);
int zebra_debugs_debug_nht_destroy(NB_CB_DESTROY_ARGS);
int zebra_debugs_debug_nht_detail_modify(NB_CB_MODIFY_ARGS);
int zebra_debugs_debug_nht_detail_destroy(NB_CB_DESTROY_ARGS);
int zebra_debugs_debug_mpls_modify(NB_CB_MODIFY_ARGS);
int zebra_debugs_debug_mpls_destroy(NB_CB_DESTROY_ARGS);
int zebra_debugs_debug_vxlan_modify(NB_CB_MODIFY_ARGS);
int zebra_debugs_debug_vxlan_destroy(NB_CB_DESTROY_ARGS);
int zebra_debugs_debug_pw_modify(NB_CB_MODIFY_ARGS);
int zebra_debugs_debug_pw_destroy(NB_CB_DESTROY_ARGS);
int zebra_debugs_debug_dplane_modify(NB_CB_MODIFY_ARGS);
int zebra_debugs_debug_dplane_destroy(NB_CB_DESTROY_ARGS);
int zebra_debugs_debug_dplane_detail_modify(NB_CB_MODIFY_ARGS);
int zebra_debugs_debug_dplane_detail_destroy(NB_CB_DESTROY_ARGS);
int zebra_debugs_debug_mlag_modify(NB_CB_MODIFY_ARGS);
int zebra_debugs_debug_mlag_destroy(NB_CB_DESTROY_ARGS);
int lib_interface_zebra_ip_addrs_create(NB_CB_CREATE_ARGS);
int lib_interface_zebra_ip_addrs_destroy(NB_CB_DESTROY_ARGS);
int lib_interface_zebra_ip_addrs_label_modify(NB_CB_MODIFY_ARGS);
int lib_interface_zebra_ip_addrs_label_destroy(NB_CB_DESTROY_ARGS);
int lib_interface_zebra_ip_addrs_ip4_peer_modify(NB_CB_MODIFY_ARGS);
int lib_interface_zebra_ip_addrs_ip4_peer_destroy(NB_CB_DESTROY_ARGS);
int lib_interface_zebra_multicast_modify(NB_CB_MODIFY_ARGS);
int lib_interface_zebra_multicast_destroy(NB_CB_DESTROY_ARGS);
int lib_interface_zebra_link_detect_modify(NB_CB_MODIFY_ARGS);
int lib_interface_zebra_link_detect_destroy(NB_CB_DESTROY_ARGS);
int lib_interface_zebra_shutdown_modify(NB_CB_MODIFY_ARGS);
int lib_interface_zebra_shutdown_destroy(NB_CB_DESTROY_ARGS);
int lib_interface_zebra_bandwidth_modify(NB_CB_MODIFY_ARGS);
int lib_interface_zebra_bandwidth_destroy(NB_CB_DESTROY_ARGS);
int lib_route_map_entry_match_condition_ipv4_prefix_length_modify(
	NB_CB_MODIFY_ARGS);
int lib_route_map_entry_match_condition_ipv4_prefix_length_destroy(
	NB_CB_DESTROY_ARGS);
int lib_route_map_entry_match_condition_ipv6_prefix_length_modify(
	NB_CB_MODIFY_ARGS);
int lib_route_map_entry_match_condition_ipv6_prefix_length_destroy(
	NB_CB_DESTROY_ARGS);
int lib_route_map_entry_match_condition_source_protocol_modify(
	NB_CB_MODIFY_ARGS);
int lib_route_map_entry_match_condition_source_protocol_destroy(
	NB_CB_DESTROY_ARGS);
int lib_route_map_entry_match_condition_source_instance_modify(
	NB_CB_MODIFY_ARGS);
int lib_route_map_entry_match_condition_source_instance_destroy(
	NB_CB_DESTROY_ARGS);
int lib_route_map_entry_set_action_source_v4_modify(NB_CB_MODIFY_ARGS);
int lib_route_map_entry_set_action_source_v4_destroy(NB_CB_DESTROY_ARGS);
int lib_route_map_entry_set_action_source_v6_modify(NB_CB_MODIFY_ARGS);
int lib_route_map_entry_set_action_source_v6_destroy(NB_CB_DESTROY_ARGS);
struct yang_data *
	lib_interface_zebra_state_up_count_get_elem(NB_CB_GET_ELEM_ARGS);
struct yang_data *
	lib_interface_zebra_state_down_count_get_elem(NB_CB_GET_ELEM_ARGS);
struct yang_data *
	lib_interface_zebra_state_zif_type_get_elem(NB_CB_GET_ELEM_ARGS);
struct yang_data *
	lib_interface_zebra_state_ptm_status_get_elem(NB_CB_GET_ELEM_ARGS);
struct yang_data *
	lib_interface_zebra_state_vlan_id_get_elem(NB_CB_GET_ELEM_ARGS);
struct yang_data *
	lib_interface_zebra_state_vni_id_get_elem(NB_CB_GET_ELEM_ARGS);
struct yang_data *
	lib_interface_zebra_state_remote_vtep_get_elem(NB_CB_GET_ELEM_ARGS);
struct yang_data *
	lib_interface_zebra_state_mcast_group_get_elem(NB_CB_GET_ELEM_ARGS);
int lib_vrf_ribs_rib_create(NB_CB_CREATE_ARGS);
int lib_vrf_ribs_rib_destroy(NB_CB_DESTROY_ARGS);
const void *lib_vrf_ribs_rib_get_next(NB_CB_GET_NEXT_ARGS);
int lib_vrf_ribs_rib_get_keys(NB_CB_GET_KEYS_ARGS);
const void *lib_vrf_ribs_rib_lookup_entry(NB_CB_LOOKUP_ENTRY_ARGS);
const void *lib_vrf_ribs_rib_route_get_next(NB_CB_GET_NEXT_ARGS);
int lib_vrf_ribs_rib_route_get_keys(NB_CB_GET_KEYS_ARGS);
const void *lib_vrf_ribs_rib_route_lookup_entry(NB_CB_LOOKUP_ENTRY_ARGS);
struct yang_data *lib_vrf_ribs_rib_route_prefix_get_elem(NB_CB_GET_ELEM_ARGS);
struct yang_data *lib_vrf_ribs_rib_route_protocol_get_elem(NB_CB_GET_ELEM_ARGS);
struct yang_data *
	lib_vrf_ribs_rib_route_protocol_v6_get_elem(NB_CB_GET_ELEM_ARGS);
struct yang_data *lib_vrf_ribs_rib_route_vrf_get_elem(NB_CB_GET_ELEM_ARGS);
struct yang_data *lib_vrf_ribs_rib_route_distance_get_elem(NB_CB_GET_ELEM_ARGS);
struct yang_data *lib_vrf_ribs_rib_route_metric_get_elem(NB_CB_GET_ELEM_ARGS);
struct yang_data *lib_vrf_ribs_rib_route_tag_get_elem(NB_CB_GET_ELEM_ARGS);
struct yang_data *lib_vrf_ribs_rib_route_selected_get_elem(NB_CB_GET_ELEM_ARGS);
struct yang_data *
	lib_vrf_ribs_rib_route_installed_get_elem(NB_CB_GET_ELEM_ARGS);
struct yang_data *lib_vrf_ribs_rib_route_failed_get_elem(NB_CB_GET_ELEM_ARGS);
struct yang_data *lib_vrf_ribs_rib_route_queued_get_elem(NB_CB_GET_ELEM_ARGS);
struct yang_data *
	lib_vrf_ribs_rib_route_internal_flags_get_elem(NB_CB_GET_ELEM_ARGS);
struct yang_data *
	lib_vrf_ribs_rib_route_internal_status_get_elem(NB_CB_GET_ELEM_ARGS);
struct yang_data *lib_vrf_ribs_rib_route_uptime_get_elem(NB_CB_GET_ELEM_ARGS);
const void *lib_vrf_ribs_rib_route_nexthop_group_get_next(NB_CB_GET_NEXT_ARGS);
int lib_vrf_ribs_rib_route_nexthop_group_get_keys(NB_CB_GET_KEYS_ARGS);
const void *lib_vrf_ribs_rib_route_nexthop_group_lookup_entry(
	NB_CB_LOOKUP_ENTRY_ARGS);
struct yang_data *
	lib_vrf_ribs_rib_route_nexthop_group_name_get_elem(NB_CB_GET_ELEM_ARGS);
const void *lib_vrf_ribs_rib_route_nexthop_group_frr_nexthops_nexthop_get_next(
	NB_CB_GET_NEXT_ARGS);
int lib_vrf_ribs_rib_route_nexthop_group_frr_nexthops_nexthop_get_keys(
	NB_CB_GET_KEYS_ARGS);
int lib_vrf_ribs_rib_create(NB_CB_CREATE_ARGS);
int lib_vrf_ribs_rib_destroy(NB_CB_DESTROY_ARGS);
const void *lib_vrf_ribs_rib_get_next(NB_CB_GET_NEXT_ARGS);
int lib_vrf_ribs_rib_get_keys(NB_CB_GET_KEYS_ARGS);
const void *lib_vrf_ribs_rib_lookup_entry(NB_CB_LOOKUP_ENTRY_ARGS);
const void *lib_vrf_ribs_rib_route_get_next(NB_CB_GET_NEXT_ARGS);
int lib_vrf_ribs_rib_route_get_keys(NB_CB_GET_KEYS_ARGS);
const void *lib_vrf_ribs_rib_route_lookup_entry(NB_CB_LOOKUP_ENTRY_ARGS);
struct yang_data *lib_vrf_ribs_rib_route_prefix_get_elem(NB_CB_GET_ELEM_ARGS);
const void *lib_vrf_ribs_rib_route_route_entry_get_next(NB_CB_GET_NEXT_ARGS);
int lib_vrf_ribs_rib_route_route_entry_get_keys(NB_CB_GET_KEYS_ARGS);
const void *lib_vrf_ribs_rib_route_route_entry_lookup_entry(
	NB_CB_LOOKUP_ENTRY_ARGS);
struct yang_data *lib_vrf_ribs_rib_route_route_entry_protocol_get_elem(
	NB_CB_GET_ELEM_ARGS);
struct yang_data *lib_vrf_ribs_rib_route_route_entry_instance_get_elem(
	NB_CB_GET_ELEM_ARGS);
struct yang_data *lib_vrf_ribs_rib_route_route_entry_distance_get_elem(
	NB_CB_GET_ELEM_ARGS);
struct yang_data *
	lib_vrf_ribs_rib_route_route_entry_metric_get_elem(NB_CB_GET_ELEM_ARGS);
struct yang_data *
	lib_vrf_ribs_rib_route_route_entry_tag_get_elem(NB_CB_GET_ELEM_ARGS);
struct yang_data *lib_vrf_ribs_rib_route_route_entry_selected_get_elem(
	NB_CB_GET_ELEM_ARGS);
struct yang_data *lib_vrf_ribs_rib_route_route_entry_installed_get_elem(
	NB_CB_GET_ELEM_ARGS);
struct yang_data *
	lib_vrf_ribs_rib_route_route_entry_failed_get_elem(NB_CB_GET_ELEM_ARGS);
struct yang_data *
	lib_vrf_ribs_rib_route_route_entry_queued_get_elem(NB_CB_GET_ELEM_ARGS);
struct yang_data *lib_vrf_ribs_rib_route_route_entry_internal_flags_get_elem(
	NB_CB_GET_ELEM_ARGS);
struct yang_data *lib_vrf_ribs_rib_route_route_entry_internal_status_get_elem(
	NB_CB_GET_ELEM_ARGS);
struct yang_data *
	lib_vrf_ribs_rib_route_route_entry_uptime_get_elem(NB_CB_GET_ELEM_ARGS);
const void *lib_vrf_ribs_rib_route_route_entry_nexthop_group_get_next(
	NB_CB_GET_NEXT_ARGS);
int lib_vrf_ribs_rib_route_route_entry_nexthop_group_get_keys(
	NB_CB_GET_KEYS_ARGS);
const void *lib_vrf_ribs_rib_route_route_entry_nexthop_group_lookup_entry(
	NB_CB_LOOKUP_ENTRY_ARGS);
struct yang_data *
	lib_vrf_ribs_rib_route_route_entry_nexthop_group_name_get_elem(
		NB_CB_GET_ELEM_ARGS);
const void *
	lib_vrf_ribs_rib_route_route_entry_nexthop_group_frr_nexthops_nexthop_get_next(
		NB_CB_GET_NEXT_ARGS);
int lib_vrf_ribs_rib_route_route_entry_nexthop_group_frr_nexthops_nexthop_get_keys(
	NB_CB_GET_KEYS_ARGS);
const void *
	lib_vrf_ribs_rib_route_route_entry_nexthop_group_frr_nexthops_nexthop_lookup_entry(
		NB_CB_LOOKUP_ENTRY_ARGS);
struct yang_data *
	lib_vrf_ribs_rib_route_route_entry_nexthop_group_frr_nexthops_nexthop_nh_type_get_elem(
		NB_CB_GET_ELEM_ARGS);
struct yang_data *
	lib_vrf_ribs_rib_route_route_entry_nexthop_group_frr_nexthops_nexthop_vrf_get_elem(
		NB_CB_GET_ELEM_ARGS);
struct yang_data *
	lib_vrf_ribs_rib_route_route_entry_nexthop_group_frr_nexthops_nexthop_gateway_get_elem(
		NB_CB_GET_ELEM_ARGS);
struct yang_data *
	lib_vrf_ribs_rib_route_route_entry_nexthop_group_frr_nexthops_nexthop_interface_get_elem(
		NB_CB_GET_ELEM_ARGS);
struct yang_data *
	lib_vrf_ribs_rib_route_route_entry_nexthop_group_frr_nexthops_nexthop_bh_type_get_elem(
		NB_CB_GET_ELEM_ARGS);
struct yang_data *
	lib_vrf_ribs_rib_route_route_entry_nexthop_group_frr_nexthops_nexthop_onlink_get_elem(
		NB_CB_GET_ELEM_ARGS);
const void *
	lib_vrf_ribs_rib_route_route_entry_nexthop_group_frr_nexthops_nexthop_mpls_label_stack_entry_get_next(
		NB_CB_GET_NEXT_ARGS);
int lib_vrf_ribs_rib_route_route_entry_nexthop_group_frr_nexthops_nexthop_mpls_label_stack_entry_get_keys(
	NB_CB_GET_KEYS_ARGS);
const void *
	lib_vrf_ribs_rib_route_route_entry_nexthop_group_frr_nexthops_nexthop_mpls_label_stack_entry_lookup_entry(
		NB_CB_LOOKUP_ENTRY_ARGS);
struct yang_data *
	lib_vrf_ribs_rib_route_route_entry_nexthop_group_frr_nexthops_nexthop_mpls_label_stack_entry_id_get_elem(
		NB_CB_GET_ELEM_ARGS);
struct yang_data *
	lib_vrf_ribs_rib_route_route_entry_nexthop_group_frr_nexthops_nexthop_mpls_label_stack_entry_label_get_elem(
		NB_CB_GET_ELEM_ARGS);
struct yang_data *
	lib_vrf_ribs_rib_route_route_entry_nexthop_group_frr_nexthops_nexthop_mpls_label_stack_entry_ttl_get_elem(
		NB_CB_GET_ELEM_ARGS);
struct yang_data *
	lib_vrf_ribs_rib_route_route_entry_nexthop_group_frr_nexthops_nexthop_mpls_label_stack_entry_traffic_class_get_elem(
		NB_CB_GET_ELEM_ARGS);
struct yang_data *
	lib_vrf_ribs_rib_route_route_entry_nexthop_group_frr_nexthops_nexthop_duplicate_get_elem(
		NB_CB_GET_ELEM_ARGS);
struct yang_data *
	lib_vrf_ribs_rib_route_route_entry_nexthop_group_frr_nexthops_nexthop_recursive_get_elem(
		NB_CB_GET_ELEM_ARGS);
struct yang_data *
	lib_vrf_ribs_rib_route_route_entry_nexthop_group_frr_nexthops_nexthop_active_get_elem(
		NB_CB_GET_ELEM_ARGS);
struct yang_data *
	lib_vrf_ribs_rib_route_route_entry_nexthop_group_frr_nexthops_nexthop_fib_get_elem(
		NB_CB_GET_ELEM_ARGS);
struct yang_data *
	lib_vrf_ribs_rib_route_route_entry_nexthop_group_frr_nexthops_nexthop_weight_get_elem(
		NB_CB_GET_ELEM_ARGS);

#endif
