from app.parsers import ParserRegistry


def test_cisco_static_and_overload_nat():
    raw = """version 17.12
hostname ios-edge
interface GigabitEthernet0/0
 ip address 203.0.113.2 255.255.255.248
ip nat inside source static tcp 10.0.0.10 443 203.0.113.10 8443
ip nat inside source static 10.0.0.20 203.0.113.20
ip nat inside source list NAT-SOURCES interface GigabitEthernet0/0 overload
"""
    config, _ = ParserRegistry.parse(raw, "ios-edge.conf")

    assert len(config.nat) == 3
    assert config.nat[0].original_src == "10.0.0.10"
    assert config.nat[0].translated_src == "203.0.113.10"
    assert config.nat[0].original_port == 443
    assert config.nat[0].translated_port == 8443
    assert config.nat[2].translated_src == "interface:GigabitEthernet0/0"


def test_yamaha_vlan_and_nat_descriptor():
    raw = """hostname rtx-edge
vlan lan1/1 802.1q vid=100 name=SERVER
ip lan1/1 address 192.168.100.1/24
ip lan2 address 203.0.113.2/29
nat descriptor type 1 masquerade
ip lan2 nat descriptor 1
nat descriptor masquerade static 1 10 192.168.100.10 tcp 443
"""
    config, _ = ParserRegistry.parse(raw, "rtx-edge.conf")

    assert config.vlans[0].subnets == ["192.168.100.0/24"]
    assert config.vlans[0].gateway == "192.168.100.1"
    vlan_iface = next(item for item in config.interfaces if item.name == "lan1/1")
    assert vlan_iface.vlan_id == 100
    assert len(config.nat) == 2
    assert config.nat[0].translated_src == "interface:lan2"
    assert config.nat[1].translated_dst == "192.168.100.10"
    assert config.nat[1].original_port == 443


def test_junos_vlan_and_source_nat_pool():
    raw = """set system host-name srx-edge
set interfaces irb unit 100 family inet address 192.168.100.1/24
set interfaces ge-0/0/0 unit 0 family inet address 203.0.113.2/29
set vlans SERVER vlan-id 100
set vlans SERVER l3-interface irb.100
set security zones security-zone trust interfaces irb.100
set security zones security-zone untrust interfaces ge-0/0/0.0
set security nat source pool PUBLIC address 203.0.113.4/32
set security nat source rule-set OUT rule SNAT match source-address 192.168.100.0/24
set security nat source rule-set OUT rule SNAT match destination-address 0.0.0.0/0
set security nat source rule-set OUT rule SNAT then source-nat pool PUBLIC
"""
    config, ranked = ParserRegistry.parse(raw, "srx-edge.conf")

    assert ranked[0].parser_id == "juniper_srx"
    assert config.vlans[0].id == 100
    assert config.vlans[0].subnets == ["192.168.100.0/24"]
    assert config.nat[0].type == "source"
    assert config.nat[0].original_src == "192.168.100.0/24"
    assert config.nat[0].translated_src == "203.0.113.4/32"


def test_panos_subinterface_creates_vlan():
    raw = """set deviceconfig system hostname pa-edge
set network interface ethernet ethernet1/2 layer3 units ethernet1/2.100 tag 100
set network interface ethernet ethernet1/2 layer3 units ethernet1/2.100 ip 192.168.100.1/24
set zone trust network layer3 ethernet1/2.100
"""
    config, _ = ParserRegistry.parse(raw, "pa-edge.set")

    assert config.vlans[0].id == 100
    assert config.vlans[0].subnets == ["192.168.100.0/24"]
    assert config.interfaces[0].vlan_id == 100
    assert config.interfaces[0].zone == "trust"
