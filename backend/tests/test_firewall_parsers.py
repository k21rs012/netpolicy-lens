from app.analyzer import build_matrix
from app.parsers import ParserRegistry
from app.sample import SAMPLES


def test_fortios_golden():
    cfg, ranked = ParserRegistry.parse(SAMPLES["fortigate01.conf"], "fortigate01.conf")
    assert ranked[0].parser_id == "fortinet_fortios"
    assert cfg.device.hostname == "fortigate01"
    assert cfg.device.network_os == "fortios"
    assert {z.name for z in cfg.zones} == {"WAN", "DMZ"}
    assert {i.name for i in cfg.interfaces} == {"port1", "port2"}
    assert cfg.address_objects[0].values == ["172.16.100.10/32"]
    assert cfg.service_objects[0].protocol == "tcp"
    policy = cfg.policies[0]
    assert policy.name == "Internet-to-Web"
    assert policy.src == ["any"]
    assert policy.dst == ["172.16.100.10/32"]
    assert policy.dst_ports == ["443"]
    assert policy.action == "permit"
    assert policy.src_segments == ["fortigate01-zone-wan"]
    assert policy.dst_segments == ["fortigate01-zone-dmz"]
    assert len(cfg.nat) == 1 and cfg.nat[0].type == "source"
    assert cfg.routes[0].destination == "0.0.0.0/0"


def test_panos_golden_and_object_resolution():
    cfg, ranked = ParserRegistry.parse(SAMPLES["panos01.set"], "panos01.set")
    assert ranked[0].parser_id == "paloalto_panos"
    assert cfg.device.hostname == "panos01"
    assert {z.name for z in cfg.zones} == {"trust", "untrust"}
    policy = cfg.policies[0]
    assert policy.src == ["10.20.0.0/24", "10.20.0.10/32"]
    assert policy.protocol == ["tcp"]
    assert policy.dst_ports == ["443"]
    assert policy.from_zone == "trust" and policy.to_zone == "untrust"
    assert cfg.nat[0].translated_dst == "10.20.0.20"
    assert cfg.nat[0].original_port == 443
    assert cfg.nat[0].translated_port == 443
    assert cfg.routes[0].next_hop == "198.51.100.1"


def test_firewall_policy_flows_into_matrix():
    forti, _ = ParserRegistry.parse(SAMPLES["fortigate01.conf"], "fortigate01.conf")
    cells = build_matrix([forti])
    cell = next(c for c in cells if c.source.endswith("zone-wan") and c.destination.endswith("zone-dmz"))
    assert cell.result == "ALLOW"
    assert cell.allowed == ["TCP/443"]
    assert cell.traces[0]["policy"] == "Internet-to-Web"


def test_unrelated_device_any_does_not_leak():
    forti, _ = ParserRegistry.parse(SAMPLES["fortigate01.conf"], "fortigate01.conf")
    cisco, _ = ParserRegistry.parse(SAMPLES["cisco01.conf"], "cisco01.conf")
    cells = build_matrix([forti, cisco])
    cell = next(c for c in cells if c.source.endswith("zone-wan") and c.destination.endswith("vlan-20"))
    assert cell.result == "UNKNOWN"
