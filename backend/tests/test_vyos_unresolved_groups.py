import pytest

from app.analyzer import build_matrix
from app.models import Confidence
from app.parsers import ParserRegistry
from app.topology import analyze_reachability


GROUP_MATCHES = [
    f"{side} group {kind} MISSING"
    for side in ("source", "destination")
    for kind in ("address-group", "network-group", "port-group")
] + [f"{side}-interface group MISSING" for side in ("inbound", "outbound")]


def parse_rule(match, action="accept", extra=""):
    raw = f"""set system host-name edge
set interfaces ethernet eth0 address 10.0.1.1/24
set interfaces ethernet eth1 address 10.0.2.1/24
set firewall ipv4 forward filter default-action accept
set firewall ipv4 forward filter rule 10 action {action}
set firewall ipv4 forward filter rule 10 {match}
set firewall ipv4 forward filter rule 20 action accept
{extra}
"""
    config, _ = ParserRegistry.parse(raw, "groups.conf", parser_id="vyos")
    return config


def results(config):
    source, destination = [segment.id for segment in config.segments]
    path = analyze_reachability([config], source, destination, "tcp", 443, source_port=12345)
    cell = next(cell for cell in build_matrix([config])
                if cell.source == source and cell.destination == destination)
    return path["result"], cell.result


@pytest.mark.parametrize("match", GROUP_MATCHES)
@pytest.mark.parametrize("negated", [False, True])
@pytest.mark.parametrize("action", ["accept", "drop"])
def test_missing_group_is_partial_and_preserves_diagnostic(match, negated, action):
    if negated:
        match = match.replace("MISSING", "!MISSING")
    config = parse_rule(match, action)
    rule = config.policies[0]
    assert rule.confidence == Confidence.PARTIAL
    assert any(match in value for value in rule.unsupported_matches)
    assert any("MISSING" in warning.reason and warning.line == 6
               for warning in config.warnings)
    assert results(config) == ("PARTIAL", "PARTIAL")


@pytest.mark.parametrize("match,definition", [
    ("source group network-group CLIENTS", "network-group CLIENTS network 10.0.1.0/24"),
    ("destination group port-group WEB", "port-group WEB port 443"),
    ("inbound-interface group LAN", "interface-group LAN interface eth0"),
])
def test_defined_groups_remain_exact(match, definition):
    config = parse_rule(match, extra=f"set firewall group {definition}")
    assert config.policies[0].confidence == Confidence.EXACT
    assert results(config) == ("ALLOW", "ALLOW")


def test_negated_missing_deny_does_not_fall_through_to_allow():
    config = parse_rule("source group network-group !MISSING", "drop")
    assert results(config) == ("PARTIAL", "PARTIAL")


def test_other_known_nonmatching_condition_can_skip_unresolved_rule():
    config = parse_rule("source group network-group MISSING", "drop",
                        "set firewall ipv4 forward filter rule 10 protocol udp")
    assert results(config)[0] == "ALLOW"


def test_group_of_different_type_does_not_resolve_reference():
    config = parse_rule("source group network-group MISSING", extra=
                        "set firewall group address-group MISSING address 10.0.1.0/24")
    assert results(config) == ("PARTIAL", "PARTIAL")


@pytest.mark.parametrize("match,definition", [
    ("destination group port-group !WEB", "port-group WEB port 80"),
    ("inbound-interface group !WAN", "interface-group WAN interface eth1"),
])
def test_unsupported_negated_membership_does_not_skip_deny(match, definition):
    config = parse_rule(match, "drop", f"set firewall group {definition}")
    assert results(config) == ("PARTIAL", "PARTIAL")


def test_hierarchical_ipv6_missing_group():
    raw = """system {
    host-name edge
}
interfaces {
    ethernet eth0 {
        address 2001:db8:1::1/64
    }
    ethernet eth1 {
        address 2001:db8:2::1/64
    }
}
firewall {
    ipv6 {
        forward {
            filter {
                default-action accept
                rule 10 {
                    action drop
                    source {
                        group {
                            ipv6-network-group !MISSING
                        }
                    }
                }
            }
        }
    }
}
"""
    config, _ = ParserRegistry.parse(raw, "groups.conf", parser_id="vyos")
    assert results(config) == ("PARTIAL", "PARTIAL")
    assert any("ipv6-network-group !MISSING" in warning.reason for warning in config.warnings)


def test_missing_group_in_jump_target_is_partial():
    config = parse_rule("jump-target CHECK", "jump", """set firewall ipv4 name CHECK rule 10 action drop
set firewall ipv4 name CHECK rule 10 source group network-group !MISSING
set firewall ipv4 name CHECK default-action accept""")
    assert results(config)[0] == "PARTIAL"


def test_disabled_missing_group_does_not_affect_result():
    config = parse_rule("source group network-group MISSING", "drop",
                        "set firewall ipv4 forward filter rule 10 disable")
    assert results(config) == ("ALLOW", "ALLOW")
    assert not any("unresolved" in warning.reason for warning in config.warnings)
