from pathlib import Path

from app.parsers import ParserRegistry
from app.parsers.junos_hier import hierarchical_to_set


FIXTURE = Path(__file__).parent / "fixtures" / "juniper_srx_hierarchical.conf"


def test_hierarchical_srx_is_detected_and_parsed():
    raw = FIXTURE.read_text()
    config, ranked = ParserRegistry.parse(raw, FIXTURE.name)

    assert ranked[0].parser_id == "juniper_srx"
    assert config.device.hostname == "branch-srx"
    assert config.device.network_os == "srx"
    assert {zone.name for zone in config.zones} == {"trust", "untrust"}
    assert {segment.name: segment.networks for segment in config.segments} == {
        "TRUST": ["10.10.0.0/24"],
        "UNTRUST": ["203.0.113.0/29"],
    }

    policy = config.policies[0]
    assert policy.name == "WEB-OUT"
    assert policy.src == ["APP-SERVER", "any"]
    assert policy.dst == ["any"]
    assert policy.protocol == ["tcp", "udp"]
    assert policy.dst_ports == ["443", "5353", "22"]
    assert policy.action == "permit"
    assert policy.trace.line_start == 26

    assert [(route.destination, route.next_hop) for route in config.routes] == [
        ("0.0.0.0/0", "203.0.113.1")
    ]
    assert [(obj.name, obj.values) for obj in config.address_objects] == [
        ("APP-SERVER", ["10.10.0.10/32"])
    ]
    assert any(
        service.name == "CUSTOM-UDP" and service.protocol == "udp" and service.ports == ["5353"]
        for service in config.service_objects
    )


def test_hierarchical_normalizer_skips_inactive_subtrees():
    normalized = hierarchical_to_set(
        """system {\n host-name edge;\n}\ninterfaces {\n inactive: ge-0/0/0 {\n  unit 0 {\n   family inet {\n    address 192.0.2.1/24;\n   }\n  }\n }\n}\n"""
    )

    assert [line.text for line in normalized] == ["set system host-name edge"]


def test_junos_version_is_not_a_cisco_detection_signal():
    raw = FIXTURE.read_text()
    scores = {item.parser_id: item.confidence for item in ParserRegistry.detect(raw)}

    assert scores["cisco_ios"] == 0
    assert scores["cisco_iosxe"] == 0
