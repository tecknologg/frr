/*
 * MRT kernel API test interface
 *
 * Copyright (C) 2022 by David Lamparter,
 *                   for Open Source Routing / NetDEF, Inc.
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

#include "tests/lib/cli/common_cli.h"
#include "lib/log.h"
#include "lib/network.h"
#include "lib/thread.h"

#include <linux/mroute.h>

#include "pimd/test_mrt_clippy.c"

static int mrt_sock = -1;
struct thread *t_mrt_read;
static ifindex_t vifi_map[MAXVIFS];

static int ifi2vifi(ifindex_t ifi)
{
	size_t i;

	if (!ifi)
		return -1;

	for (i = 0; i < array_size(vifi_map); i++)
		if (vifi_map[i] == ifi)
			return i;

	return -1;
}

__attribute__((_CONSTRUCTOR(2000)))
static void test_setup(void)
{
	test_log_prio = LOG_DEBUG;
}

#ifdef _FRR_ATTRIBUTE_PRINTFRR
#pragma FRR printfrr_ext "%dIGMT" (int)
#endif

printfrr_ext_autoreg_i("IGMT", printfrr_igmt);
static ssize_t printfrr_igmt(struct fbuf *buf, struct printfrr_eargs *ea,
			     uintmax_t val)
{
	switch (val) {
	case IGMPMSG_NOCACHE:		return bputs(buf, "NOCACHE");
	case IGMPMSG_WRONGVIF:		return bputs(buf, "WRONGVIF");
	case IGMPMSG_WHOLEPKT:		return bputs(buf, "WHOLEPKT");
	case IGMPMSG_WRVIFWHOLE:	return bputs(buf, "WRVIFWHOLE");
	default:
		return bprintfrr(buf, "UNKNOWN(%ju)", val);
	}
};

static void mrt_read(struct thread *t)
{
	union {
		char buf[CMSG_SPACE(sizeof(struct in_pktinfo))];
		struct cmsghdr align;
	} cmsgbuf;
	struct cmsghdr *cmsg;
	struct in_pktinfo *pktinfo = NULL;
	char rxbuf[2048];
	struct msghdr mh[1] = {};
	struct iovec iov[1];
	struct sockaddr_in pkt_src[1];
	ssize_t nread;
	const struct ip *ip_hdr;
	const struct igmpmsg *igmp;
	char ifname[IFNAMSIZ + 1];

	thread_add_read(master, mrt_read, NULL, mrt_sock, &t_mrt_read);

	iov->iov_base = rxbuf;
	iov->iov_len = sizeof(rxbuf);

	mh->msg_name = pkt_src;
	mh->msg_namelen = sizeof(pkt_src);
	mh->msg_control = cmsgbuf.buf;
	mh->msg_controllen = sizeof(cmsgbuf.buf);
	mh->msg_iov = iov;
	mh->msg_iovlen = array_size(iov);
	mh->msg_flags = 0;

	nread = recvmsg(mrt_sock, mh, 0);
	if (nread <= 0) {
		zlog_err("mrt socket RX error: %m");
		return;
	}

	ip_hdr = (const struct ip *)rxbuf;
	if (ip_hdr->ip_p == IPPROTO_IGMP) {
		zlog_info("ignoring IGMP packet on MRT socket");
		return;
	} else if (ip_hdr->ip_p) {
		zlog_info("ignoring IPPROTO_%u packet on MRT socket",
			  ip_hdr->ip_p);
		return;
	}

	for (cmsg = CMSG_FIRSTHDR(mh); cmsg; cmsg = CMSG_NXTHDR(mh, cmsg)) {
		if (cmsg->cmsg_level != SOL_IP)
			continue;

		switch (cmsg->cmsg_type) {
		case IP_PKTINFO:
			pktinfo = (struct in_pktinfo *)CMSG_DATA(cmsg);
			break;
		}
	}

	if (!pktinfo)
		zlog_info("pktinfo: none");
	else
		zlog_info("pktinfo: ipi_addr=%pI4 ipi_spec_dst=%pI4 ipi_ifindex=%d",
			  &pktinfo->ipi_addr, &pktinfo->ipi_spec_dst,
			  pktinfo->ipi_ifindex);

	igmp = (const struct igmpmsg *)rxbuf;
	zlog_debug("upcall[%dIGMT] iface=%s (%pI4,%pI4)", igmp->im_msgtype,
		   if_indextoname(vifi_map[igmp->im_vif], ifname),
		   &igmp->im_src, &igmp->im_dst);
	FMT_NSTD_BEGIN;
	zlog_debug("phdr: %.*pHX", (int)sizeof(*igmp), igmp);
	zlog_debug("data: %.*pHX", (int)(nread - sizeof(*igmp)), igmp + 1);
	FMT_NSTD_END;
}

DEFPY(mfc, mfc_cmd,
	"mfc <add$add|del> A.B.C.D$src A.B.C.D$grp iif IIF [oifs OIFS]",
	"MFC\n"
	"add entry\n"
	"delete entry\n"
	"source\n"
	"group\n"
	"input iface\n"
	"input iface\n"
	"output ifaces (comma separate)\n"
	"output ifaces (comma separate)\n")
{
	int err;
	int op = add ? MRT_ADD_MFC : MRT_DEL_MFC;
	struct mfcctl mfc[1] = {};
	int vifi;
	char ifname[IFNAMSIZ + 1];
	const char *oifpos, *oifnext;

	mfc->mfcc_origin = src;
	mfc->mfcc_mcastgrp = grp;

	vifi = ifi2vifi(if_nametoindex(iif));
	if (vifi == -1) {
		vty_out(vty, "invalid ifname: %s\n", iif);
		return CMD_WARNING;
	}
	mfc->mfcc_parent = vifi;

	for (oifpos = oifs; oifpos; oifpos = oifnext) {
		memset(ifname, 0, sizeof(ifname));

		oifnext = strchr(oifpos, ',');
		if (oifnext) {
			memcpy(ifname, oifpos, oifnext - oifpos);
			oifnext++;
		} else
			strcpy(ifname, oifpos);

		vifi = ifi2vifi(if_nametoindex(ifname));
		if (vifi == -1) {
			vty_out(vty, "invalid ifname: %s\n", ifname);
			return CMD_WARNING;
		}
		mfc->mfcc_ttls[vifi] = 1;
	}

	FMT_NSTD_BEGIN;
	vty_out(vty, "mfcc_ttls: %.*pHX\n", (int)sizeof(mfc->mfcc_ttls),
		mfc->mfcc_ttls);
	FMT_NSTD_END;

	err = setsockopt(mrt_sock, IPPROTO_IP, op, mfc, sizeof(mfc));
	if (err)
		vty_out(vty, "error: %m\n");
	else
		vty_out(vty, "OK\n");
	return CMD_SUCCESS;
}

void test_init(int argc, char **argv)
{
	int one = 1;
	int upc = IGMPMSG_WRVIFWHOLE;
	int ret;
	int vifi = 0;
	struct vifctl vc;

	if (optind >= argc) {
		fprintf(stderr, "specify one or more interfaces on cmdline\n");
		exit(1);
	}

	install_element(ENABLE_NODE, &mfc_cmd);

	mrt_sock = socket(AF_INET, SOCK_RAW, IPPROTO_IGMP);
	assertf(mrt_sock >= 0, "socket(): %m");

	ret = setsockopt(mrt_sock, IPPROTO_IP, MRT_INIT, &one, sizeof(one));
	assertf(!ret, "MRT_INIT: %m");

	ret = setsockopt(mrt_sock, IPPROTO_IP, IP_PKTINFO, &one, sizeof(one));
	assertf(!ret, "IP_PKTINFO: %m");

	ret = set_nonblocking(mrt_sock);
	assertf(!ret, "set_nonblocking: %m");

	ret = setsockopt(mrt_sock, IPPROTO_IP, MRT_PIM, &upc, sizeof(upc));
	assertf(!ret, "MRT_PIM/IGMPMSG_WRVIFWHOLE: %m");

	memset(&vc, 0, sizeof(vc));
	vc.vifc_vifi = vifi++;
	vc.vifc_lcl_ifindex = 0;
	vc.vifc_flags = VIFF_REGISTER;
	vc.vifc_threshold = 1;
	vc.vifc_rate_limit = 0;
	ret = setsockopt(mrt_sock, IPPROTO_IP, MRT_ADD_VIF, &vc, sizeof(vc));
	assertf(!ret, "MRT_ADD_VIF(pimreg)");

	vifi_map[0] = if_nametoindex("pimreg");

	for (int i = optind; i < argc; i++) {
		memset(&vc, 0, sizeof(vc));
		vc.vifc_vifi = vifi++;
		vc.vifc_lcl_ifindex = if_nametoindex(argv[i]);
		vc.vifc_flags = VIFF_USE_IFINDEX;
		vc.vifc_threshold = 1;
		vc.vifc_rate_limit = 0;
		ret = setsockopt(mrt_sock, IPPROTO_IP, MRT_ADD_VIF, &vc, sizeof(vc));
		assertf(!ret, "MRT_ADD_VIF(%s)", argv[i]);
		zlog_info("%-16s => vifi %d", argv[i], vc.vifc_vifi);

		vifi_map[vc.vifc_vifi] = vc.vifc_lcl_ifindex;
	}

	thread_add_read(master, mrt_read, NULL, mrt_sock, &t_mrt_read);

	zlog_info("MRT test startup complete");
}
