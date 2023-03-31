# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2023 Nathan Mangar for NetDEF, Inc.

"""
Test if 172.16.255.254/32 tagged with BLACKHOLE community is not
re-advertised downstream outside local AS.
"""

__topotests_file__ = "bgp_blackhole_community/test_bgp_blackhole_community.py"
__topotests_gitrev__ = "4953ca977f3a5de8109ee6353ad07f816ca1774c"

# pylint: disable=invalid-name, missing-class-docstring, missing-function-docstring, line-too-long, consider-using-f-string, wildcard-import, unused-wildcard-import, f-string-without-interpolation, too-few-public-methods, unused-argument, attribute-defined-outside-init
from topotato import *


@topology_fixture()
def topology(topo):
    """
            [ r1 ]
              |
    [ r3 ]--{ s1 }--[ r4 ]
      |       |       |
    { s2 }--[ r2 ]--{ s3 }

    """
    topo.router("r1").lo_ip4.append("172.16.255.254/32")


class Configs(FRRConfigs):
    routers = ["r1", "r2", "r3", "r4"]

    zebra = """
    #% extends "boilerplate.conf"
    #% block main
    #%   if router.name == 'r1'
    interface lo
     ip address {{ routers.r1.lo_ip4[0] }}
    !
    #%   endif
    #%  for iface in router.ifaces
    interface {{ iface.ifname }}
        ip address {{ iface.ip4[0] }}
    !
    #%  endfor
    ip forwarding
    !
    #% endblock
    """

    bgpd = """
    #% block main
    #%  if router.name == 'r1' 
    router bgp 65001
      timers bgp 3 9
      no bgp ebgp-requires-policy
      neighbor {{ routers.r1.iface_to('s1').ip4[0].ip }} remote-as external
      address-family ipv4 unicast
        redistribute connected route-map r2
        neighbor {{ routers.r1.iface_to('s1').ip4[0].ip }} route-map r2 out
      exit-address-family
    !
    route-map r2 permit 10
      set community blackhole no-export
    !
    #%   elif router.name == 'r2'
    router bgp 65002
      no bgp ebgp-requires-policy
      timers bgp 3 9
      neighbor {{ routers.r2.iface_to('s1').ip4[0].ip }} remote-as external
      neighbor {{ routers.r2.iface_to('s2').ip4[0].ip }} remote-as external
      neighbor {{ routers.r2.iface_to('s3').ip4[0].ip }} remote-as internal
    !
    #%   elif router.name == 'r3'
    router bgp 65003
      timers bgp 3 9
      no bgp ebgp-requires-policy
      neighbor {{ routers.r3.iface_to('s1').ip4[0].ip }} remote-as external
    !
    #%   elif router.name == 'r4'
    router bgp 65004
      timers bgp 3 9
      no bgp ebgp-requires-policy
      neighbor {{ routers.r4.iface_to('s1').ip4[0].ip }} remote-as internal
    !
    #%   endif
    #% endblock
    """


class BGPBlackholeCommunity(TestBase, AutoFixture, topo=topology, configs=Configs):
    @topotatofunc
    def bgp_converge(self, r1):

        expected = {"paths": [{"community": {"list": ["blackhole", "noExport"]}}]}
        yield from AssertVtysh.make(
            r1,
            "bgpd",
            f"show ip bgp {r1.lo_ip4[0]} json",
            maxwait=4.0,
            compare=expected,
        )

    @topotatofunc
    def bgp_no_advertise_ebgp(self, r2):

        expected = {
            "advertisedRoutes": {},
            "totalPrefixCounter": 0,
            "filteredPrefixCounter": 0,
        }

        yield from AssertVtysh.make(
            r2,
            "bgpd",
            f"show ip bgp neighbor {r2.iface_to('s1').ip4[0].ip} advertised-routes json",
            compare=expected,
            maxwait=5.0,
        )

    # This bit of the test fails.
    @topotatofunc
    def bgp_no_advertise_ibgp(self, r1, r2):

        expected = {
            "advertisedRoutes": {str(r1.lo_ip4[0]): {}},
            "totalPrefixCounter": 2,
        }

        yield from AssertVtysh.make(
            r2,
            "bgpd",
            f"show ip bgp neighbor {r2.iface_to('s3').ip4[0].ip} advertised-routes json",
            maxwait=5.0,
            compare=expected,
        )
