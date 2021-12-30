#!/usr/bin/env python

#
# test_ospf_virtual_link_topo1.py
# Part of NetDEF Topology Tests
#
# Copyright (c) 2021 by
# Network Device Education Foundation, Inc. ("NetDEF")
#
# Permission to use, copy, modify, and/or distribute this software
# for any purpose with or without fee is hereby granted, provided
# that the above copyright notice and this permission notice appear
# in all copies.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND NETDEF DISCLAIMS ALL WARRANTIES
# WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
# MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL NETDEF BE LIABLE FOR
# ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY
# DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS,
# WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS
# ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE
# OF THIS SOFTWARE.
#

"""
test_ospf_virtual_link_topo1.py: Test the FRR OSPF routing daemon
virtual-link feature.
"""

import os
import re
import sys
from functools import partial
import pytest

# Save the Current Working Directory to find configuration files.
CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
# Import topogen and topotest helpers
from lib import topotest
from lib.topogen import Topogen, TopoRouter, get_topogen
from lib.topolog import logger

pytestmark = [pytest.mark.ospfd]


def build_topo(self, *_args, **_opts):
    "Build function"
    tgen = get_topogen(self)

    for routern in range(1, 7):
        tgen.add_router("r{}".format(routern))

    switch = tgen.add_switch("s1")
    switch.add_link(tgen.gears["r1"])
    switch.add_link(tgen.gears["r2"])

    switch = tgen.add_switch("s2")
    switch.add_link(tgen.gears["r2"])
    switch.add_link(tgen.gears["r3"])

    switch = tgen.add_switch("r3-stub")
    switch.add_link(tgen.gears["r3"])

    switch = tgen.add_switch("s3")
    switch.add_link(tgen.gears["r2"])
    switch.add_link(tgen.gears["r4"])

    switch = tgen.add_switch("s4")
    switch.add_link(tgen.gears["r1"])
    switch.add_link(tgen.gears["r5"])

    switch = tgen.add_switch("s5")
    switch.add_link(tgen.gears["r5"])
    switch.add_link(tgen.gears["r6"])


def setup_module(mod):
    "Sets up the pytest environment"
    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    router_list = tgen.routers()
    for rname, router in router_list.items():
        router.load_config(
            TopoRouter.RD_ZEBRA, os.path.join(CWD, "{}/zebra.conf".format(rname))
        )
        router.load_config(
            TopoRouter.RD_OSPF, os.path.join(CWD, "{}/ospfd.conf".format(rname))
        )

    # Initialize all routers.
    tgen.start_router()


def teardown_module(mod):
    "Teardown the pytest environment"
    tgen = get_topogen()
    tgen.stop_topology()


def test_wait_protocol_convergence():
    "Wait for OSPFv2 to converge"
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    logger.info("waiting for protocols to converge")

    def expect_ospfv2_neighbor_full(router, neighbor):
        "Wait until OSPFv2 convergence."
        logger.info(
            "waiting OSPFv2 router '{}' for neighbor '{}'".format(router, neighbor)
        )

        def run_command_and_expect():
            """
            Function that runs command and expect the following outcomes:
             * Full/DR
             * Full/DROther
             * Full/Backup
            """
            result = tgen.gears[router].vtysh_cmd(
                "show ip ospf neighbor json", isjson=True
            )
            if (
                topotest.json_cmp(
                    result, {"neighbors": {neighbor: [{"state": "Full/DR"}]}}
                )
                is None
            ):
                return None

            if (
                topotest.json_cmp(
                    result, {"neighbors": {neighbor: [{"state": "Full/DROther"}]}}
                )
                is None
            ):
                return None

            return topotest.json_cmp(
                result, {"neighbors": {neighbor: [{"state": "Full/Backup"}]}}
            )

        _, result = topotest.run_and_expect(
            run_command_and_expect, None, count=130, wait=1
        )
        assertmsg = '"{}" convergence failure'.format(router)
        assert result is None, assertmsg

    # Wait for OSPFv2 convergence
    expect_ospfv2_neighbor_full("r1", "10.254.254.2")
    expect_ospfv2_neighbor_full("r1", "10.254.254.3")
    expect_ospfv2_neighbor_full("r1", "10.254.254.4")
    expect_ospfv2_neighbor_full("r1", "10.254.254.5")
    expect_ospfv2_neighbor_full("r1", "10.254.254.6")

    expect_ospfv2_neighbor_full("r2", "10.254.254.1")
    expect_ospfv2_neighbor_full("r2", "10.254.254.3")
    expect_ospfv2_neighbor_full("r2", "10.254.254.4")

    expect_ospfv2_neighbor_full("r3", "10.254.254.1")
    expect_ospfv2_neighbor_full("r3", "10.254.254.2")

    expect_ospfv2_neighbor_full("r4", "10.254.254.1")
    expect_ospfv2_neighbor_full("r4", "10.254.254.2")

    expect_ospfv2_neighbor_full("r5", "10.254.254.1")
    expect_ospfv2_neighbor_full("r5", "10.254.254.6")

    expect_ospfv2_neighbor_full("r6", "10.254.254.1")
    expect_ospfv2_neighbor_full("r6", "10.254.254.5")


def test_memory_leak():
    "Run the memory leak test and report results."
    tgen = get_topogen()
    if not tgen.is_memleak_enabled():
        pytest.skip("Memory leak test/report is disabled")

    tgen.report_memory_leaks()


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
