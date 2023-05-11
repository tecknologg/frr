#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2023 Nathan Mangar

"""
Test if BGP ORF filtering is working correctly when modifying
prefix-list.

Initially advertise 10.10.10.1/32 from R1 to R2. Add new prefix
10.10.10.2/32 to r1 prefix list on R2. Test if we updated ORF
prefix-list correctly.
"""

__topotests_file__ = "bgp_orf/test_bgp_orf.py"
__topotests_gitrev__ = "4953ca977f3a5de8109ee6353ad07f816ca1774c"

# pylint: disable=wildcard-import, unused-wildcard-import, trailing-whitespace

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
    # topo.router("r1").iface_to("s1").ip4.append("192.168.1.1/24")
    # topo.router("r2").iface_to("s1").ip4.append("192.168.1.2/24")


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
     neighbor {{ routers.r2.iface_to('s1').ip4[0].ip }} remote-as external
     address-family ipv4 unicast
      redistribute connected
      neighbor {{ routers.r2.iface_to('s1').ip4[0].ip }} capability orf prefix-list both
     exit-address-family
    !
    #%   elif router.name == 'r2'    
    router bgp 65002
     no bgp ebgp-requires-policy
     neighbor {{ routers.r1.iface_to('s1').ip4[0].ip }} remote-as external
     address-family ipv4 unicast
      neighbor {{ routers.r1.iface_to('s1').ip4[0].ip }} capability orf prefix-list both
      neighbor {{ routers.r1.iface_to('s1').ip4[0].ip }} prefix-list r1 in
     exit-address-family
    !
    ip prefix-list r1 seq 5 permit {{ routers.r1.lo_ip4[0] }}
    #%   endif
    #% endblock
    """


class TestBGPORF(TestBase, AutoFixture, topo=topology, configs=Configs):
    @topotatofunc
    def bgp_converge_r1(self, r1, r2):
        expected = {
            "advertisedRoutes": {str(r1.lo_ip4[0]): {}, str(r2.lo_ip4[0]): None}
        }

        yield from AssertVtysh.make(
            r1,
            "bgpd",
            f"show bgp ipv4 unicast neighbor {r2.iface_to('s1').ip4[0].ip} advertised-routes json",
            maxwait=5.0,
            compare=expected,
        )

    @topotatofunc
    def bgp_converge_r2(self, r1, r2):
        expected = {
            "peers": {
                str(r1.iface_to("s1").ip4[0].ip): {
                    "pfxRcd": 1,
                    "pfxSnt": 1,
                    "state": "Established",
                    "peerState": "OK",
                }
            }
        }

        yield from AssertVtysh.make(
            r2,
            "bgpd",
            f"show bgp ipv4 unicast summary json",
            maxwait=5.0,
            compare=expected,
        )

    # These bits of the test fail. For some reason it's not able to apply the new changes.
    @topotatofunc
    def bgp_orf_changed_r1(self, r1, r2):

        expected = {"advertisedRoutes": {str(r1.lo_ip4[0]): {}, str(r2.lo_ip4[0]): {}}}

        yield from AssertVtysh.make(
            r2,
            "bgpd",
            f"""
            enable
            configure terminal
            ip prefix-list r1 seq 10 permit {r2.lo_ip4[0]}
            """,
            compare="",
        )

        yield from AssertVtysh.make(
            r1,
            "bgpd",
            f"show bgp ipv4 unicast neighbor {r2.iface_to('s1').ip4[0].ip} advertised-routes json",
            maxwait=5.0,
            compare=expected,
        )

    @topotatofunc
    def bgp_orf_changed_r2(self, r1, r2):
        expected = {
            "routes": {
                str(r1.lo_ip4[0]): [{"valid": True}],
                str(r2.lo_ip4[0]): [{"valid": True}],
            }
        }

        yield from AssertVtysh.make(
            r2,
            "bgpd",
            f"show bgp ipv4 unicast summary json",
            maxwait=5.0,
            compare=expected,
        )
