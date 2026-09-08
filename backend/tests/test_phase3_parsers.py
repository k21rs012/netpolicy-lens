from app.analyzer import build_matrix
from app.parsers import ParserRegistry
from app.sample import SAMPLES


def test_aoscx_golden():
    cfg, ranked = ParserRegistry.parse(SAMPLES["aoscx01.conf"], "aoscx01.conf")
    assert ranked[0].parser_id == "aruba_aoscx"
    assert cfg.device.network_os == "aos-cx"
    assert cfg.vlans[0].name == "SERVER-CX"
    assert cfg.vlans[0].subnets == ["10.100.0.0/24"]
    assert cfg.policies[0].interface == "vlan 100"
    assert cfg.policies[0].src_segments == ["aoscx01-vlan-100"]
    assert cfg.policies[0].dst_ports == ["443"]
    assert cfg.routes[0].next_hop == "10.100.0.254"


def test_arista_eos_golden():
    cfg, ranked = ParserRegistry.parse(SAMPLES["eos01.conf"], "eos01.conf")
    assert ranked[0].parser_id == "arista_eos"
    assert cfg.device.vendor == "arista"
    assert cfg.interfaces[0].vlan_id == 110
    assert cfg.policies[0].name == "APP-IN"
    assert cfg.policies[0].dst_ports == ["8443"]
    assert cfg.policies[1].action == "deny"


def test_alliedware_plus_golden():
    cfg, ranked = ParserRegistry.parse(SAMPLES["allied01.conf"], "allied01.conf")
    assert ranked[0].parser_id == "alliedware_plus"
    assert cfg.device.vendor == "allied"
    assert cfg.vlans[0].id == 120
    assert cfg.vlans[0].name == "MGMT-AW"
    assert len(cfg.policies) == 2
    assert cfg.policies[0].protocol == ["tcp"]
    assert cfg.policies[0].dst_ports == ["22"]
    assert cfg.policies[0].interface == "vlan120"


def test_alliedware_classifier_traffic_filter_and_ipv6_binding():
    raw = """! AlliedWare Plus
hostname aw-edge
vlan 120 name MGMT
interface vlan120
 ip address 10.120.0.1/24
 traffic-filter EDGE-FILTER in
 ipv6 traffic-filter V6-IN out
access-list EDGE-ACL permit tcp 10.120.0.0/24 any eq 443
ipv6 access-list V6-IN
 permit tcp 2001:db8:120::/64 any eq 443
classifier WEB
 match access-group EDGE-ACL
traffic-filter EDGE-FILTER
 classifier WEB
"""
    cfg, _ = ParserRegistry.parse(raw, "aw-edge.conf")
    iface = cfg.interfaces[0]
    assert iface.acl_in == ["EDGE-ACL"]
    assert iface.acl_out == ["V6-IN"]
    edge = next(policy for policy in cfg.policies if policy.name == "EDGE-ACL")
    ipv6 = next(policy for policy in cfg.policies if policy.name == "V6-IN")
    assert edge.interface == "vlan120" and edge.direction == "in"
    assert ipv6.interface == "vlan120" and ipv6.direction == "out"


def test_vyos_golden_zone_firewall_and_nat():
    cfg, ranked = ParserRegistry.parse(SAMPLES["vyos01.set"], "vyos01.set")
    assert ranked[0].parser_id == "vyos"
    assert cfg.device.hostname == "vyos01"
    assert {z.name for z in cfg.zones} == {"LAN", "WAN"}
    assert cfg.vlans[0].id == 130
    policy = cfg.policies[0]
    assert policy.from_zone == "LAN" and policy.to_zone == "WAN"
    assert policy.action == "permit"
    assert policy.dst_ports == ["443"]
    assert cfg.nat[0].translated_src == "masquerade"
    assert cfg.routes[0].next_hop == "192.0.2.1"
    cell = next(c for c in build_matrix([cfg]) if c.source.endswith("zone-lan") and c.destination.endswith("zone-wan"))
    assert cell.result == "ALLOW" and cell.allowed == ["TCP/443"]


def test_vyos_14_hierarchical_configuration():
    raw = '''firewall {
    ipv4 {
        input {
            filter {
                default-action accept
                rule 5 {
                    action jump
                    inbound-interface {
                        name eth0
                    }
                    jump-target WAN-IN
                }
            }
        }
        name WAN-IN {
            default-action drop
            rule 10 {
                action accept
                description "Allow SSH"
                destination {
                    port 22
                }
                protocol tcp
            }
            rule 20 {
                action accept
                source {
                    port 53
                }
                protocol udp
            }
        }
    }
}
interfaces {
    ethernet eth0 {
        address 114.129.1.183/28
    }
    ethernet eth1 {
        address 192.168.0.1/24
    }
}
nat {
    source {
        rule 10 {
            source {
                address 192.168.0.0/24
            }
            translation {
                address masquerade
            }
        }
    }
}
protocols {
    static {
        route 0.0.0.0/0 {
            next-hop 114.129.1.177 {
            }
        }
    }
}
system {
    host-name vyos
}
'''
    cfg, ranked = ParserRegistry.parse(raw, "config.boot")

    assert ranked[0].parser_id == "vyos"
    assert cfg.device.hostname == "vyos"
    assert {interface.name for interface in cfg.interfaces} == {"eth0", "eth1"}
    assert len(cfg.policies) == 3
    entry = next(policy for policy in cfg.policies if policy.name == "base-input")
    assert entry.action == "jump"
    assert entry.jump_target == "WAN-IN"
    assert entry.in_interfaces == ["eth0"]
    assert entry.direction == "in"
    ssh = next(policy for policy in cfg.policies if policy.name == "WAN-IN" and policy.sequence == 10)
    assert ssh.action == "permit"
    assert ssh.protocol == ["tcp"]
    assert ssh.dst_ports == ["22"]
    assert ssh.default_action == "deny"
    dns = next(policy for policy in cfg.policies if policy.name == "WAN-IN" and policy.sequence == 20)
    assert dns.src_ports == ["53"]
    assert cfg.nat[0].original_src == "192.168.0.0/24"
    assert cfg.nat[0].translated_src == "masquerade"
    assert cfg.routes[0].destination == "0.0.0.0/0"
    assert cfg.routes[0].next_hop == "114.129.1.177"


def test_vyos_14_groups_families_state_routes_and_nat_conditions():
    raw = """set system host-name edge-vyos
set interfaces ethernet eth0 address 10.0.1.1/24
set interfaces ethernet eth1 address 10.0.2.1/24
set interfaces ethernet eth1 address 2001:db8:2::1/64
set firewall group network-group CLIENTS network 10.0.1.0/24
set firewall group port-group WEB port 80
set firewall group port-group WEB port 443
set firewall group interface-group LAN interface eth0
set firewall ipv4 forward filter default-action drop
set firewall ipv4 forward filter rule 10 action accept
set firewall ipv4 forward filter rule 10 source group network-group CLIENTS
set firewall ipv4 forward filter rule 10 destination group port-group WEB
set firewall ipv4 forward filter rule 10 inbound-interface group LAN
set firewall ipv4 forward filter rule 10 state new
set firewall ipv4 forward filter rule 20 action accept
set firewall ipv4 forward filter rule 20 time weekdays Mon,Tue
set firewall ipv6 forward filter default-action drop
set firewall ipv6 forward filter rule 10 action drop
set firewall ipv6 forward filter rule 10 destination address 2001:db8:2::/64
set protocols static route 203.0.113.0/24 next-hop 10.0.2.2
set protocols static route 203.0.113.0/24 next-hop 10.0.2.3
set protocols static route 198.51.100.0/24 blackhole
set nat source rule 10 source address 10.0.1.0/24
set nat source rule 10 source port 1024-65535
set nat source rule 10 destination port 443
set nat source rule 10 outbound-interface name eth1
set nat source rule 10 translation address masquerade
"""
    cfg, _ = ParserRegistry.parse(raw, "vyos.conf", parser_id="vyos")

    assert len(cfg.policies) == 3
    ipv4 = next(policy for policy in cfg.policies if policy.sequence == 10 and policy.ip_version == 4)
    ipv6 = next(policy for policy in cfg.policies if policy.sequence == 10 and policy.ip_version == 6)
    assert ipv4.src == ["10.0.1.0/24"]
    assert ipv4.dst_ports == ["80", "443"]
    assert ipv4.in_interfaces == ["eth0"]
    assert ipv4.states == ["new"]
    assert ipv6.action == "deny"
    partial = next(policy for policy in cfg.policies if policy.sequence == 20)
    assert partial.confidence.value == "PARTIAL"
    assert partial.unsupported_matches == ["time weekdays Mon,Tue"]
    route = next(route for route in cfg.routes if route.destination == "203.0.113.0/24")
    assert route.next_hops == ["10.0.2.2", "10.0.2.3"]
    assert next(route for route in cfg.routes if route.destination == "198.51.100.0/24").route_type == "blackhole"
    nat = cfg.nat[0]
    assert nat.sequence == 10
    assert nat.source_ports == ["1024-65535"]
    assert nat.destination_ports == ["443"]
    assert nat.out_interfaces == ["eth1"]


def test_vyos_zone_local_default_and_default_only_ruleset():
    raw = """set system host-name zones
set interfaces ethernet eth0 address 192.0.2.1/24
set interfaces ethernet eth1 address 10.0.0.1/24
set firewall zone WAN interface eth0
set firewall zone LAN interface eth1
set firewall zone LOCAL local-zone
set firewall zone WAN default-action drop
set firewall zone WAN from LAN firewall name LAN-WAN
set firewall ipv4 name LAN-WAN default-action accept
"""
    cfg, _ = ParserRegistry.parse(raw, "zones.conf", parser_id="vyos")

    assert {zone.name for zone in cfg.zones} == {"WAN", "LAN", "LOCAL"}
    attached = next(policy for policy in cfg.policies if policy.name == "LAN-WAN")
    assert attached.action == "continue"
    assert attached.default_action == "permit"
    assert attached.from_zone == "LAN" and attached.to_zone == "WAN"
    assert any(policy.name == "zone-default-WAN" and policy.from_zone == "LOCAL"
               and policy.action == "deny" for policy in cfg.policies)


def test_phase3_detection_is_distinct():
    cases = {"aoscx01.conf": "aruba_aoscx", "eos01.conf": "arista_eos", "allied01.conf": "alliedware_plus", "vyos01.set": "vyos"}
    for filename, expected in cases.items():
        assert ParserRegistry.detect(SAMPLES[filename])[0].parser_id == expected
