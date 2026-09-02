from app.models import CanonicalConfig, Device, Interface, NATRule, Policy, Route, Segment
from app.parsers import ParserRegistry
from app.topology import analyze_reachability


def _manual_config(*policies: Policy) -> CanonicalConfig:
    return CanonicalConfig(
        device=Device(id="edge", hostname="edge", vendor="cisco", network_os="ios-xe", source_file="edge.conf"),
        interfaces=[
            Interface(device="edge", name="Vlan10", segment_id="edge-a", acl_in=["IN"]),
            Interface(device="edge", name="Vlan20", segment_id="edge-b", acl_out=["OUT"]),
        ],
        segments=[
            Segment(id="edge-a", name="A", type="vlan", device="edge", networks=["10.0.1.0/24"]),
            Segment(id="edge-b", name="B", type="vlan", device="edge", networks=["10.0.2.0/24"]),
        ], policies=list(policies),
    )


def test_ingress_permit_does_not_bypass_egress_deny():
    config = _manual_config(
        Policy(id="in", device="edge", name="IN", sequence=10, action="permit", direction="in",
               interface="Vlan10", chain_id="in:Vlan10:IN"),
        Policy(id="out", device="edge", name="OUT", sequence=10, action="deny", direction="out",
               interface="Vlan20", chain_id="out:Vlan20:OUT"),
    )
    result = analyze_reachability([config], "edge-a", "edge-b", "icmp", None)
    assert result["result"] == "DENY"
    assert {chain["result"] for chain in result["steps"][0]["chains"]} == {"ALLOW", "DENY"}


def test_cisco_standard_acl_treats_first_address_as_source():
    raw = """hostname ios
vlan 10
vlan 20
interface Vlan10
 ip address 10.0.1.1 255.255.255.0
interface Vlan20
 ip address 10.0.2.1 255.255.255.0
 ip access-group STD out
ip access-list standard STD
 10 deny 10.0.1.0 0.0.0.255
 20 permit any
"""
    config, _ = ParserRegistry.parse(raw, "ios.conf", parser_id="cisco_ios")
    assert config.policies[0].protocol == ["ip"]
    assert config.policies[0].src == ["10.0.1.0/24"]
    assert analyze_reachability([config], "ios-vlan-10", "ios-vlan-20", "icmp", None)["result"] == "DENY"


def test_aoscx_unbound_acl_is_not_global_policy():
    raw = """ArubaOS-CX
hostname cx
vlan 10
vlan 20
interface vlan 10
 ip address 10.0.1.1/24
interface vlan 20
 ip address 10.0.2.1/24
access-list ip UNUSED
 10 permit ip any any
"""
    config, _ = ParserRegistry.parse(raw, "cx.conf", parser_id="aruba_aoscx")
    result = analyze_reachability([config], "cx-vlan-10", "cx-vlan-20", "icmp", None)
    assert result["result"] == "UNKNOWN"


def test_fortios_uses_configuration_order_not_policy_id():
    raw = """config system global
 set hostname fg
end
config system interface
 edit lan
  set ip 10.0.1.1 255.255.255.0
 next
 edit dmz
  set ip 10.0.2.1 255.255.255.0
 next
end
config firewall policy
 edit 100
  set srcintf lan
  set dstintf dmz
  set srcaddr all
  set dstaddr all
  set service ALL
  set action deny
 next
 edit 1
  set srcintf lan
  set dstintf dmz
  set srcaddr all
  set dstaddr all
  set service ALL
  set action accept
 next
end
"""
    config, _ = ParserRegistry.parse(raw, "fg.conf", parser_id="fortinet_fortios")
    source = next(segment.id for segment in config.segments if segment.name == "LAN")
    target = next(segment.id for segment in config.segments if segment.name == "DMZ")
    assert [policy.sequence for policy in config.policies] == [100, 1]
    assert analyze_reachability([config], source, target, "icmp", None)["result"] == "DENY"


def test_panos_move_changes_first_matching_rule():
    raw = """set deviceconfig system hostname pa
set network interface ethernet ethernet1/1 layer3 ip 10.0.1.1/24
set network interface ethernet ethernet1/2 layer3 ip 10.0.2.1/24
set zone trust network layer3 ethernet1/1
set zone dmz network layer3 ethernet1/2
set rulebase security rules DENY from trust
set rulebase security rules DENY to dmz
set rulebase security rules DENY source any
set rulebase security rules DENY destination any
set rulebase security rules DENY service any
set rulebase security rules DENY application any
set rulebase security rules DENY action deny
set rulebase security rules ALLOW from trust
set rulebase security rules ALLOW to dmz
set rulebase security rules ALLOW source any
set rulebase security rules ALLOW destination any
set rulebase security rules ALLOW service any
set rulebase security rules ALLOW application any
set rulebase security rules ALLOW action allow
move rulebase security rules ALLOW top
"""
    config, _ = ParserRegistry.parse(raw, "pa.conf", parser_id="paloalto_panos")
    assert [policy.name for policy in config.policies] == ["ALLOW", "DENY"]
    assert analyze_reachability([config], "pa-zone-trust", "pa-zone-dmz", "tcp", 443)["result"] == "ALLOW"


def test_junos_global_policy_is_fallback_for_zone_pair():
    raw = """set system host-name srx
set interfaces ge-0/0/0 unit 0 family inet address 10.0.1.1/24
set interfaces ge-0/0/1 unit 0 family inet address 10.0.2.1/24
set security zones security-zone trust interfaces ge-0/0/0.0
set security zones security-zone dmz interfaces ge-0/0/1.0
set security policies global policy GLOBAL match from-zone trust
set security policies global policy GLOBAL match to-zone dmz
set security policies global policy GLOBAL match source-address any
set security policies global policy GLOBAL match destination-address any
set security policies global policy GLOBAL match application any
set security policies global policy GLOBAL then permit
"""
    config, _ = ParserRegistry.parse(raw, "srx.conf", parser_id="juniper_srx")
    assert len(config.policies) == 1
    assert analyze_reachability([config], "srx-zone-trust", "srx-zone-dmz", "icmp", None)["result"] == "ALLOW"


def test_routeros_forward_chain_skips_disabled_and_handles_jump():
    raw = """# RouterOS 7
/ip address
add address=10.0.1.1/24 interface=lan
add address=10.0.2.1/24 interface=dmz
/ip firewall filter
add chain=forward action=accept disabled=yes
add chain=forward action=jump jump-target=CHECK
add chain=CHECK action=drop src-address=10.0.1.0/24 dst-address=10.0.2.0/24
"""
    config, _ = ParserRegistry.parse(raw, "router.rsc", parser_id="mikrotik_routeros")
    assert len(config.policies) == 2
    assert analyze_reachability([config], "router-lan", "router-dmz", "tcp", 443)["result"] == "DENY"


def test_vyos_current_forward_chain_is_parsed():
    raw = """set system host-name vy
set interfaces ethernet eth0 address 10.0.1.1/24
set interfaces ethernet eth1 address 10.0.2.1/24
set firewall ipv4 forward filter default-action accept
set firewall ipv4 forward filter rule 10 action drop
set firewall ipv4 forward filter rule 10 source address 10.0.1.0/24
set firewall ipv4 forward filter rule 10 destination address 10.0.2.0/24
"""
    config, _ = ParserRegistry.parse(raw, "vy.conf", parser_id="vyos")
    assert len(config.policies) == 1
    assert analyze_reachability([config], "vy-if-eth0", "vy-if-eth1", "tcp", 443)["result"] == "DENY"


def test_static_route_controls_multidevice_egress():
    first = CanonicalConfig(
        device=Device(id="r1", hostname="r1", vendor="cisco", network_os="ios", source_file="r1"),
        interfaces=[Interface(device="r1", name="lan", segment_id="r1-lan"), Interface(device="r1", name="wan", segment_id="r1-wan")],
        segments=[Segment(id="r1-lan", name="LAN", type="interface", device="r1", networks=["10.0.1.0/24"]),
                  Segment(id="r1-wan", name="WAN", type="interface", device="r1", networks=["192.0.2.0/30"])],
        routes=[Route(device="r1", destination="10.0.2.0/24", next_hop="198.51.100.1")],
    )
    second = CanonicalConfig(
        device=Device(id="r2", hostname="r2", vendor="cisco", network_os="ios", source_file="r2"),
        interfaces=[Interface(device="r2", name="wan", segment_id="r2-wan"), Interface(device="r2", name="lan", segment_id="r2-lan")],
        segments=[Segment(id="r2-wan", name="WAN", type="interface", device="r2", networks=["192.0.2.0/30"]),
                  Segment(id="r2-lan", name="LAN", type="interface", device="r2", networks=["10.0.2.0/24"])],
    )
    assert analyze_reachability([first, second], "r1-lan", "r2-lan", "icmp", None)["result"] == "NO_ROUTE"
    first.routes[0].next_hop = "192.0.2.2"
    assert analyze_reachability([first, second], "r1-lan", "r2-lan", "icmp", None)["path"]


def test_routeros_connection_state_is_evaluated():
    raw = """# RouterOS 7
/ip address
add address=10.0.1.1/24 interface=lan
add address=10.0.2.1/24 interface=dmz
/ip firewall filter
add chain=forward action=accept connection-state=established,related
add chain=forward action=drop
"""
    config, _ = ParserRegistry.parse(raw, "router.rsc", parser_id="mikrotik_routeros")
    assert analyze_reachability([config], "router-lan", "router-dmz", "tcp", 443, "new")["result"] == "DENY"
    assert analyze_reachability([config], "router-lan", "router-dmz", "tcp", 443, "established")["result"] == "ALLOW"


def test_routeros_return_resumes_caller_chain():
    raw = """# RouterOS 7
/ip address
add address=10.0.1.1/24 interface=lan
add address=10.0.2.1/24 interface=dmz
/ip firewall filter
add chain=forward action=jump jump-target=CHECK
add chain=forward action=accept
add chain=CHECK action=return
"""
    config, _ = ParserRegistry.parse(raw, "router.rsc", parser_id="mikrotik_routeros")
    assert analyze_reachability([config], "router-lan", "router-dmz", "tcp", 443)["result"] == "ALLOW"


def test_asa_security_levels_apply_without_acl():
    raw = """ASA Version 9.18
hostname asa
interface GigabitEthernet0/0
 nameif outside
 security-level 0
 ip address 203.0.113.1 255.255.255.0
interface GigabitEthernet0/1
 nameif inside
 security-level 100
 ip address 10.0.1.1 255.255.255.0
"""
    config, _ = ParserRegistry.parse(raw, "asa.conf", parser_id="cisco_asa")
    assert analyze_reachability([config], "asa-zone-inside", "asa-zone-outside", "tcp", 443)["result"] == "ALLOW"
    assert analyze_reachability([config], "asa-zone-outside", "asa-zone-inside", "tcp", 443)["result"] == "DENY"


def test_exos_applied_acl_defaults_to_permit():
    raw = """configure snmp sysName ex
create vlan USERS tag 10
configure vlan USERS ipaddress 10.0.1.1 255.255.255.0
create vlan DMZ tag 20
configure vlan DMZ ipaddress 10.0.2.1 255.255.255.0
create access-list BLOCK "deny tcp source-address 10.0.1.0/24 destination-address 10.0.2.0/24 destination-port 22"
configure access-list BLOCK vlan USERS ingress
"""
    config, _ = ParserRegistry.parse(raw, "ex.conf", parser_id="extreme_exos")
    assert analyze_reachability([config], "ex-vlan-10", "ex-vlan-20", "tcp", 22)["result"] == "DENY"
    assert analyze_reachability([config], "ex-vlan-10", "ex-vlan-20", "tcp", 443)["result"] == "ALLOW"


def test_voss_acl_is_bound_to_vlan():
    raw = """snmp-server name voss
vlan create 10 name USERS type port
vlan create 20 name DMZ type port
interface Vlan 10
 ip address 10.0.1.1/24
interface Vlan 20
 ip address 10.0.2.1/24
filter acl 1 type inVlan
filter acl vlan 10 1
filter acl ace 1 10
filter acl ace ip 1 10 src-ip 10.0.1.0/24 dst-ip 10.0.2.0/24 protocol icmp
filter acl ace action 1 10 drop
"""
    config, _ = ParserRegistry.parse(raw, "voss.conf", parser_id="extreme_voss")
    assert len(config.policies) == 1
    assert analyze_reachability([config], "voss-vlan-10", "voss-vlan-20", "icmp", None)["result"] == "DENY"


def test_nat_effect_is_exposed_on_path_step():
    config = _manual_config(Policy(id="permit", device="edge", name="IN", sequence=10,
        action="permit", direction="in", interface="Vlan10", chain_id="in:Vlan10:IN"))
    config.nat.append(NATRule(device="edge", name="snat", type="source", original_src="10.0.1.0/24",
                              original_dst="10.0.2.0/24", translated_src="192.0.2.10"))
    result = analyze_reachability([config], "edge-a", "edge-b", "tcp", 443)
    assert result["steps"][0]["nat"][0]["translated_src"] == "192.0.2.10"


def test_stateful_session_requires_an_explicit_assumption():
    config = _manual_config()
    config.device.network_os = "panos"

    unknown = analyze_reachability(
        [config], "edge-a", "edge-b", "tcp", 443, "established"
    )
    assumed = analyze_reachability(
        [config], "edge-a", "edge-b", "tcp", 443, "established", True
    )

    assert unknown["result"] == "UNKNOWN"
    assert "セッションテーブル未取得" in unknown["steps"][0]["reason"]
    assert assumed["result"] == "ALLOW"
    assert assumed["assume_session"] is True
