from topotato import *

"""
Test if BGP community alias is visible in CLI outputs
"""


@topology_fixture()
def allproto_topo(topo):
    """
    [ r1 ]
      |
    { s1 }
      |
    [ r2 ]

    """
    topo.router("r2").lo_ip4.append("172.16.16.1/32")
    topo.router("r2").lo_ip4.append("172.16.16.2/32")
    topo.router("r2").lo_ip4.append("172.16.16.3/32")
    topo.router("r1").iface_to("s1").ip4.append("192.168.1.1/24")
    topo.router("r2").iface_to("s1").ip4.append("192.168.1.2/24")


class Configs(FRRConfigs):
    routers = ["r1", "r2"]

    zebra = """
    #% extends "boilerplate.conf"
    #% block main
    #%   if router.name == 'r1'
    interface lo
     ip address {{ routers.r1.lo_ip4[0] }} 
    !
    #%   endif
    #%   for iface in router.ifaces
    interface {{ iface.ifname }}
     ip address {{ iface.ip4[0] }} 
    !
    #%   endfor
    ip forwarding
    !
    #% endblock
    """

    bgpd = """
    #% block main
    #%   if router.name == 'r2'
    bgp send-extra-data zebra
    !
    router bgp 65002
     no bgp ebgp-requires-policy
     neighbor 192.168.1.1 remote-as external
     address-family ipv4 unicast
      redistribute connected
      neighbor 192.168.1.1 route-map r1 out
     exit-address-family
    !
    ip prefix-list p1 permit 172.16.16.1/32
    ip prefix-list p2 permit 172.16.16.2/32
    ip prefix-list p3 permit 172.16.16.3/32
    !
    route-map r1 permit 10
     match ip address prefix-list p1
     set community 65001:1 65001:2
     set large-community 65001:1:1 65001:1:2
    route-map r1 permit 20
     match ip address prefix-list p2
     set community 65002:1 65002:2
    route-map r1 permit 30
     match ip address prefix-list p3
    !
    #%   elif router.name == 'r1'
    bgp send-extra-data zebra
    !
    bgp community alias 65001:1 community-r2-1
    bgp community alias 65002:2 community-r2-2
    bgp community alias 65001:1:1 large-community-r2-1
    !
    bgp large-community-list expanded r2 seq 5 permit _65001:1:1_
    !
    router bgp 65001
     no bgp ebgp-requires-policy
     neighbor 192.168.1.2 remote-as external
     address-family ipv4 unicast
      redistribute connected
      neighbor 192.168.1.2 route-map r2 in
     exit-address-family
    !
    route-map r2 permit 10
     match alias community-r2-1
     set tag 10
    route-map r2 permit 20
     match alias community-r2-2
     set tag 20
    route-map r2 permit 30
     set tag 100
    !
    #%   endif
    #% endblock
  """


@config_fixture(Configs)
def configs(config, allproto_topo):
    return config


@instance_fixture()
def testenv(configs):
    return FRRNetworkInstance(configs.topology, configs).prepare()


class BGPCommunityAlias(TestBase):
    instancefn = testenv

    @topotatofunc
    def bgp_converge(self, topo, r1, r2):
        expected = {
            "172.16.16.1/32": [
                {
                    "tag": 10,
                    "communities": "community-r2-1 65001:2",
                    "largeCommunities": "large-community-r2-1 65001:1:2",
                }
            ],
            "172.16.16.2/32": [
                {
                    "tag": 20,
                    "communities": "65002:1 community-r2-2",
                    "largeCommunities": "",
                }
            ],
            "172.16.16.3/32": [
                {
                    "tag": 100,
                    "communities": "",
                    "largeCommunities": "",
                }
            ],
        }
        yield from AssertVtysh.make(
            r1,
            "zebra",
            f"show ip route json",
            maxwait=6.0,
            compare=expected,
        )

    @topotatofunc
    def bgp_show_prefixes_by_alias(self, topo, r1, r2):
        expected = {
            "routes": {
                "172.16.16.1/32": [
                    {
                        "community": {"string": "community-r2-1 65001:2"},
                        "largeCommunity": {"string": "large-community-r2-1 65001:1:2"},
                    }
                ]
            }
        }
        yield from AssertVtysh.make(
            r1,
            "bgpd",
            f"show bgp ipv4 unicast alias large-community-r2-1 json detail",
            maxwait=5.0,
            compare=expected,
        )

    @topotatofunc
    def bgp_show_prefixes_by_large_community_list(self, topo, r1, r2):
        expected = {"routes": {"172.16.16.1/32": [{"valid": True}]}}
        yield from AssertVtysh.make(
            r1,
            "bgpd",
            f"show bgp ipv4 unicast large-community-list r2 json",
            maxwait=5.0,
            compare=expected,
        )
