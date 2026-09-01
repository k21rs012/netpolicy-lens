import pytest

from app.parsers import ParserRegistry


CASES = [
    ("cisco_nxos", """!Command: show running-config
version 10.3(4a) NXOS
hostname leaf01
feature interface-vlan
vlan 10
 name USERS
interface Vlan10
 ip address 10.10.0.1/24
ip access-list WEB
 10 permit tcp 10.10.0.0 0.0.0.255 any eq 443
ip route 0.0.0.0/0 10.10.0.254
"""),
    ("cisco_asa", """ASA Version 9.18(3)
hostname asa01
interface GigabitEthernet0/0
 nameif outside
 ip address 203.0.113.2 255.255.255.0
interface GigabitEthernet0/1
 nameif inside
 ip address 10.0.0.1 255.255.255.0
object network WEB
 host 10.0.0.10
 nat (inside,outside) static 203.0.113.10
object service HTTPS
 service tcp destination eq 443
access-list OUTSIDE_IN extended permit tcp any object WEB eq 443
access-group OUTSIDE_IN in interface outside
route outside 0.0.0.0 0.0.0.0 203.0.113.1
"""),
    ("cisco_ftd", """FTD Version 7.4.1
hostname ftd01
interface GigabitEthernet0/0
 nameif outside
 ip address 198.51.100.2 255.255.255.0
object network APP
 host 10.1.0.10
access-list ACP extended deny ip any object APP
access-group ACP in interface outside
"""),
    ("extreme_exos", """configure snmp sysName exos01
create vlan USERS tag 10
configure vlan USERS ipaddress 10.10.0.1 255.255.255.0
configure iproute add 0.0.0.0/0 10.10.0.254
create access-list WEB \"permit tcp destination-port 443\" application WEB
"""),
    ("extreme_voss", """snmp-server name voss01
vlan create 20 name SERVERS type port
interface Vlan 20
 ip address 10.20.0.1/24
ip route 0.0.0.0/0 10.20.0.254
"""),
    ("mikrotik_routeros", """# RouterOS 7.15
/system identity
set name=mt01
/interface vlan
add interface=ether1 name=vlan30 vlan-id=30
/ip address
add address=10.30.0.1/24 interface=vlan30
/ip route
add dst-address=0.0.0.0/0 gateway=10.30.0.254
/ip firewall address-list
add address=10.30.0.0/24 list=USERS
/ip firewall filter
add chain=forward action=accept protocol=tcp src-address-list=USERS dst-port=443 comment=WEB
/ip firewall nat
add chain=srcnat action=masquerade out-interface=ether1 comment=INTERNET
"""),
]


@pytest.mark.parametrize(("parser_id", "config"), CASES)
def test_phase4_detection_and_contract(parser_id, config):
    ranked = ParserRegistry.detect(config)
    assert ranked[0].parser_id == parser_id
    parsed, _ = ParserRegistry.parse(config, f"{parser_id}.conf")
    assert parsed.device.hostname
    assert parsed.device.confidence >= 0.55
    assert parsed.segments
    assert all(item.trace and item.trace.line_start > 0 for item in parsed.interfaces)


def test_nxos_acl_route_and_svi():
    parsed, _ = ParserRegistry.parse(CASES[0][1], "nxos.conf")
    assert parsed.device.network_os == "nx-os"
    assert parsed.vlans[0].subnets == ["10.10.0.0/24"]
    assert parsed.policies[0].dst_ports == ["443"]
    assert parsed.routes[0].destination == "0.0.0.0/0"


def test_asa_objects_binding_and_nat():
    parsed, _ = ParserRegistry.parse(CASES[1][1], "asa.conf")
    assert {segment.name for segment in parsed.segments} == {"inside", "outside"}
    assert parsed.address_objects[0].values == ["10.0.0.10/32"]
    assert parsed.service_objects[0].ports == ["443"]
    assert {zone.name for zone in parsed.zones} == {"inside", "outside"}
    assert parsed.policies[0].interface == "outside"
    assert parsed.policies[0].dst_ports == ["443"]
    assert parsed.nat[0].translated_src == "203.0.113.10"


def test_mikrotik_firewall_nat_and_address_list():
    parsed, _ = ParserRegistry.parse(CASES[-1][1], "routeros.rsc")
    assert parsed.vlans[0].id == 30
    assert parsed.policies[0].action == "permit"
    assert parsed.policies[0].dst_ports == ["443"]
    assert parsed.address_objects[0].name == "USERS"
    assert parsed.nat[0].type == "source"
