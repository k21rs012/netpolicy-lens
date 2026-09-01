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


def test_phase3_detection_is_distinct():
    cases = {"aoscx01.conf": "aruba_aoscx", "eos01.conf": "arista_eos", "allied01.conf": "alliedware_plus", "vyos01.set": "vyos"}
    for filename, expected in cases.items():
        assert ParserRegistry.detect(SAMPLES[filename])[0].parser_id == expected
