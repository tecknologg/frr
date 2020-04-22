/*
 * BFD daemon northbound implementation.
 *
 * Copyright (C) 2019 Network Device Education Foundation, Inc. ("NetDEF")
 *                    Rafael Zalamena
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301 USA.
 */

#ifndef _FRR_BFDD_NB_H_
#define _FRR_BFDD_NB_H_

extern const struct frr_yang_module_info frr_bfdd_info;

/* Mandatory callbacks. */
int bfdd_bfd_create(NB_CB_CREATE_ARGS);
int bfdd_bfd_destroy(NB_CB_DESTROY_ARGS);
int bfdd_bfd_sessions_single_hop_create(NB_CB_CREATE_ARGS);
int bfdd_bfd_sessions_single_hop_destroy(NB_CB_DESTROY_ARGS);
const void *bfdd_bfd_sessions_single_hop_get_next(NB_CB_GET_NEXT_ARGS);
int bfdd_bfd_sessions_single_hop_get_keys(NB_CB_GET_KEYS_ARGS);
const void *bfdd_bfd_sessions_single_hop_lookup_entry(NB_CB_LOOKUP_ENTRY_ARGS);
int bfdd_bfd_sessions_single_hop_source_addr_modify(NB_CB_MODIFY_ARGS);
int bfdd_bfd_sessions_single_hop_source_addr_destroy(NB_CB_DESTROY_ARGS);
int bfdd_bfd_sessions_single_hop_detection_multiplier_modify(NB_CB_MODIFY_ARGS);
int bfdd_bfd_sessions_single_hop_desired_transmission_interval_modify(
	NB_CB_MODIFY_ARGS);
int bfdd_bfd_sessions_single_hop_required_receive_interval_modify(
	NB_CB_MODIFY_ARGS);
int bfdd_bfd_sessions_single_hop_administrative_down_modify(NB_CB_MODIFY_ARGS);
int bfdd_bfd_sessions_single_hop_echo_mode_modify(NB_CB_MODIFY_ARGS);
int bfdd_bfd_sessions_single_hop_desired_echo_transmission_interval_modify(
	NB_CB_MODIFY_ARGS);
struct yang_data *
	bfdd_bfd_sessions_single_hop_stats_local_discriminator_get_elem(
		NB_CB_GET_ELEM_ARGS);
struct yang_data *bfdd_bfd_sessions_single_hop_stats_local_state_get_elem(
	NB_CB_GET_ELEM_ARGS);
struct yang_data *bfdd_bfd_sessions_single_hop_stats_local_diagnostic_get_elem(
	NB_CB_GET_ELEM_ARGS);
struct yang_data *bfdd_bfd_sessions_single_hop_stats_local_multiplier_get_elem(
	NB_CB_GET_ELEM_ARGS);
struct yang_data *
	bfdd_bfd_sessions_single_hop_stats_remote_discriminator_get_elem(
		NB_CB_GET_ELEM_ARGS);
struct yang_data *bfdd_bfd_sessions_single_hop_stats_remote_state_get_elem(
	NB_CB_GET_ELEM_ARGS);
struct yang_data *bfdd_bfd_sessions_single_hop_stats_remote_diagnostic_get_elem(
	NB_CB_GET_ELEM_ARGS);
struct yang_data *bfdd_bfd_sessions_single_hop_stats_remote_multiplier_get_elem(
	NB_CB_GET_ELEM_ARGS);
struct yang_data *
	bfdd_bfd_sessions_single_hop_stats_negotiated_transmission_interval_get_elem(
		NB_CB_GET_ELEM_ARGS);
struct yang_data *
	bfdd_bfd_sessions_single_hop_stats_negotiated_receive_interval_get_elem(
		NB_CB_GET_ELEM_ARGS);
struct yang_data *bfdd_bfd_sessions_single_hop_stats_detection_mode_get_elem(
	NB_CB_GET_ELEM_ARGS);
struct yang_data *bfdd_bfd_sessions_single_hop_stats_last_down_time_get_elem(
	NB_CB_GET_ELEM_ARGS);
struct yang_data *bfdd_bfd_sessions_single_hop_stats_last_up_time_get_elem(
	NB_CB_GET_ELEM_ARGS);
struct yang_data *
	bfdd_bfd_sessions_single_hop_stats_session_down_count_get_elem(
		NB_CB_GET_ELEM_ARGS);
struct yang_data *bfdd_bfd_sessions_single_hop_stats_session_up_count_get_elem(
	NB_CB_GET_ELEM_ARGS);
struct yang_data *
	bfdd_bfd_sessions_single_hop_stats_control_packet_input_count_get_elem(
		NB_CB_GET_ELEM_ARGS);
struct yang_data *
	bfdd_bfd_sessions_single_hop_stats_control_packet_output_count_get_elem(
		NB_CB_GET_ELEM_ARGS);
struct yang_data *
	bfdd_bfd_sessions_single_hop_stats_negotiated_echo_transmission_interval_get_elem(
		NB_CB_GET_ELEM_ARGS);
struct yang_data *
	bfdd_bfd_sessions_single_hop_stats_echo_packet_input_count_get_elem(
		NB_CB_GET_ELEM_ARGS);
struct yang_data *
	bfdd_bfd_sessions_single_hop_stats_echo_packet_output_count_get_elem(
		NB_CB_GET_ELEM_ARGS);
int bfdd_bfd_sessions_multi_hop_create(NB_CB_CREATE_ARGS);
int bfdd_bfd_sessions_multi_hop_destroy(NB_CB_DESTROY_ARGS);
const void *bfdd_bfd_sessions_multi_hop_get_next(NB_CB_GET_NEXT_ARGS);
int bfdd_bfd_sessions_multi_hop_get_keys(NB_CB_GET_KEYS_ARGS);
const void *bfdd_bfd_sessions_multi_hop_lookup_entry(NB_CB_LOOKUP_ENTRY_ARGS);
int bfdd_bfd_sessions_multi_hop_detection_multiplier_modify(NB_CB_MODIFY_ARGS);
int bfdd_bfd_sessions_multi_hop_desired_transmission_interval_modify(
	NB_CB_MODIFY_ARGS);
int bfdd_bfd_sessions_multi_hop_required_receive_interval_modify(
	NB_CB_MODIFY_ARGS);
int bfdd_bfd_sessions_multi_hop_administrative_down_modify(NB_CB_MODIFY_ARGS);
struct yang_data *
	bfdd_bfd_sessions_multi_hop_stats_local_discriminator_get_elem(
		NB_CB_GET_ELEM_ARGS);
struct yang_data *bfdd_bfd_sessions_multi_hop_stats_local_state_get_elem(
	NB_CB_GET_ELEM_ARGS);
struct yang_data *bfdd_bfd_sessions_multi_hop_stats_local_diagnostic_get_elem(
	NB_CB_GET_ELEM_ARGS);
struct yang_data *bfdd_bfd_sessions_multi_hop_stats_local_multiplier_get_elem(
	NB_CB_GET_ELEM_ARGS);
struct yang_data *
	bfdd_bfd_sessions_multi_hop_stats_remote_discriminator_get_elem(
		NB_CB_GET_ELEM_ARGS);
struct yang_data *bfdd_bfd_sessions_multi_hop_stats_remote_state_get_elem(
	NB_CB_GET_ELEM_ARGS);
struct yang_data *bfdd_bfd_sessions_multi_hop_stats_remote_diagnostic_get_elem(
	NB_CB_GET_ELEM_ARGS);
struct yang_data *bfdd_bfd_sessions_multi_hop_stats_remote_multiplier_get_elem(
	NB_CB_GET_ELEM_ARGS);
struct yang_data *
	bfdd_bfd_sessions_multi_hop_stats_negotiated_transmission_interval_get_elem(
		NB_CB_GET_ELEM_ARGS);
struct yang_data *
	bfdd_bfd_sessions_multi_hop_stats_negotiated_receive_interval_get_elem(
		NB_CB_GET_ELEM_ARGS);
struct yang_data *bfdd_bfd_sessions_multi_hop_stats_detection_mode_get_elem(
	NB_CB_GET_ELEM_ARGS);
struct yang_data *bfdd_bfd_sessions_multi_hop_stats_last_down_time_get_elem(
	NB_CB_GET_ELEM_ARGS);
struct yang_data *bfdd_bfd_sessions_multi_hop_stats_last_up_time_get_elem(
	NB_CB_GET_ELEM_ARGS);
struct yang_data *bfdd_bfd_sessions_multi_hop_stats_session_down_count_get_elem(
	NB_CB_GET_ELEM_ARGS);
struct yang_data *bfdd_bfd_sessions_multi_hop_stats_session_up_count_get_elem(
	NB_CB_GET_ELEM_ARGS);
struct yang_data *
	bfdd_bfd_sessions_multi_hop_stats_control_packet_input_count_get_elem(
		NB_CB_GET_ELEM_ARGS);
struct yang_data *
	bfdd_bfd_sessions_multi_hop_stats_control_packet_output_count_get_elem(
		NB_CB_GET_ELEM_ARGS);
struct yang_data *
	bfdd_bfd_sessions_multi_hop_stats_negotiated_echo_transmission_interval_get_elem(
		NB_CB_GET_ELEM_ARGS);
struct yang_data *
	bfdd_bfd_sessions_multi_hop_stats_echo_packet_input_count_get_elem(
		NB_CB_GET_ELEM_ARGS);
struct yang_data *
	bfdd_bfd_sessions_multi_hop_stats_echo_packet_output_count_get_elem(
		NB_CB_GET_ELEM_ARGS);

/* Optional 'cli_show' callbacks. */
void bfd_cli_show_header(struct vty *vty, struct lyd_node *dnode,
			 bool show_defaults);
void bfd_cli_show_header_end(struct vty *vty, struct lyd_node *dnode);
void bfd_cli_show_single_hop_peer(struct vty *vty, struct lyd_node *dnode,
				  bool show_defaults);
void bfd_cli_show_multi_hop_peer(struct vty *vty, struct lyd_node *dnode,
				 bool show_defaults);
void bfd_cli_show_peer_end(struct vty *vty, struct lyd_node *dnode);
void bfd_cli_show_mult(struct vty *vty, struct lyd_node *dnode,
		       bool show_defaults);
void bfd_cli_show_tx(struct vty *vty, struct lyd_node *dnode,
		     bool show_defaults);
void bfd_cli_show_rx(struct vty *vty, struct lyd_node *dnode,
		     bool show_defaults);
void bfd_cli_show_shutdown(struct vty *vty, struct lyd_node *dnode,
			   bool show_defaults);
void bfd_cli_show_echo(struct vty *vty, struct lyd_node *dnode,
		       bool show_defaults);
void bfd_cli_show_echo_interval(struct vty *vty, struct lyd_node *dnode,
				bool show_defaults);

#endif /* _FRR_BFDD_NB_H_ */
