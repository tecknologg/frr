# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2023 Nathan Mangar

"""
Test if routes are retained during BGP restarts.
"""

__topotests_file__ = "bgp_gr_restart_retain_routes/test_bgp_gr_restart_retain_routes.py"
__topotests_gitrev__ = "6a62adabb3938b1f478d04500e2d918b43f6107d"

# pylint: disable=invalid-name, missing-class-docstring, missing-function-docstring, line-too-long, consider-using-f-string, wildcard-import, unused-wildcard-import, f-string-without-interpolation, too-few-public-methods, unused-argument

from topotato import *


@topology_fixture()
def topology(topo):
    """
    [ r1 ]
      |
    { s1 }
      |
    [ r2 ]

    """


class Configs(FRRConfigs):
    routers = ["r1", "r2"]

    zebra = """
    #% extends "boilerplate.conf"
    #% block main
    #%   for iface in router.ifaces
    interface {{ iface.ifname }}
     ip address {{ iface.ip4[0] }}
    !
    #%   endfor
    #% endblock
    """

    bgpd = """
    #% block main
    #%   if router.name == 'r1'
    router bgp 65001
     no bgp ebgp-requires-policy
     bgp graceful-restart
     bgp graceful-restart preserve-fw-state
     neighbor {{ routers.r2.iface_to('s1').ip4[0].ip }} remote-as external
     neighbor {{ routers.r2.iface_to('s1').ip4[0].ip }} timers 1 3
     neighbor {{ routers.r2.iface_to('s1').ip4[0].ip }} timers connect 1
     address-family ipv4
      redistribute connected
     exit-address-family
    !
    #%   elif router.name == 'r2'
    router bgp 65002
     no bgp ebgp-requires-policy
     bgp graceful-restart
     bgp graceful-restart preserve-fw-state
     neighbor {{ routers.r1.iface_to('s1').ip4[0].ip }} remote-as external
     neighbor {{ routers.r1.iface_to('s1').ip4[0].ip }} timers 1 3
     neighbor {{ routers.r1.iface_to('s1').ip4[0].ip }} timers connect 1
    !
    #%   endif
    #% endblock
    """


class BGPGrRestartRetainRoutes(TestBase, AutoFixture, topo=topology, configs=Configs):
    @topotatofunc
    def bgp_converge(self, r1, r2):
        expected = {
            str(r1.iface_to("s1").ip4[0].ip): {
                "bgpState": "Established",
                "addressFamilyInfo": {"ipv4Unicast": {"acceptedPrefixCounter": 2}},
            }
        }
        yield from AssertVtysh.make(
            r2,
            "bgpd",
            f"show bgp ipv4 neighbors {r1.iface_to('s1').ip4[0].ip} json",
            maxwait=5.0,
            compare=expected,
        )

    @topotatofunc
    def bgp_check_bgp_retained_routes(self, r1, r2):
        expected = {"paths": [{"stale": True}]}
        yield from AssertVtysh.make(
            r2,
            "vtysh",
            f"clear ip bgp * soft",
            maxwait=5.0,
            compare="",
        )
        yield from AssertVtysh.make(
            r2,
            "bgpd",
            f"show bgp ipv4 unicast {r1.lo_ip4[0]} json",
            maxwait=5.0,
            compare=expected,
        )

    @topotatofunc
    def bgp_check_kernel_retained_routes(self, r1, r2):
        expected = [
            {
                "dst": str(r1.lo_ip4[0]),
                "gateway": str(r1.iface_to("s1").ip4[0].ip),
                "metric": 20,
            }
        ]
        yield from AssertVtysh.make(
            r2,
            "vtysh",
            f"show ip bgp neighbor {r1.lo_ip4[0]} advertised-routes json",
            maxwait=5.0,
            compare=expected,
        )
