import pytest

from app.models import NATRule, Policy, Route, Segment
from app.nat_pipeline import apply_nat_stage
from app.parsers import ParserRegistry
from app.reachability import analyze_reachability
from app.reachability_models import Packet
from test_flow_reachability import network_path, trace


def snat(config, **changes):
    rule = NATRule(device=config.device.id, name="SNAT", type="source", original_src="10.0.1.0/24",
                   translated_src="203.0.113.10", in_interfaces=["eth0"], out_interfaces=["eth1"])
    rule = rule.model_copy(update=changes)
    config.nat = [rule]
    return rule


def public_path():
    configs = network_path(2)
    configs[0].segments.append(Segment(id="public", device="r0", name="VIP", type="interface", networks=["203.0.113.0/24"]))
    configs[0].nat = [NATRule(device="r0", name="DNAT", type="destination", original_dst="203.0.113.10",
                               translated_dst="10.0.9.20", protocol="tcp", destination_ports=["8443"],
                               translated_port=443, in_interfaces=["eth0"])]
    return configs


def inbound(configs, **kwargs):
    return analyze_reachability(configs, "r0-in", "public", "tcp", 8443, source_port=12345,
                                source_ip="10.0.1.10", destination_ip="203.0.113.10", **kwargs)


def test_dnat_reroutes_public_destination_and_translated_port_across_hops():
    result = inbound(public_path())
    assert result["result"] == "ALLOW"
    assert result["path"][-1] == "segment:r1-out"
    assert len(result["steps"]) == 2
    assert result["flow"]["original"]["destination_addresses"] == ["203.0.113.10/32"]
    assert result["flow"]["original"]["destination_port"] == 8443
    assert result["flow"]["current"]["destination_addresses"] == ["10.0.9.20/32"]
    assert result["flow"]["current"]["destination_port"] == 443
    first = result["steps"][0]
    assert first["packet_in"]["destination_port"] == 8443
    assert first["flow"]["current"]["destination_port"] == 443
    assert first["nat"][0]["applied"] is True
    assert result["steps"][1]["packet_in"] == first["packet_out"]


def test_dnat_to_blackhole_is_no_route_with_translation_evidence():
    configs = public_path()
    configs[0].routes.insert(0, Route(device="r0", destination="10.0.9.20/32", route_type="blackhole"))
    result = inbound(configs)
    assert result["result"] == "NO_ROUTE"
    assert result["steps"][0]["nat"][0]["applied"]


def test_dnat_policy_uses_internal_port_not_original_port():
    configs = public_path()
    configs[0].policies[0].dst_ports = ["8443"]
    result = inbound(configs)
    assert result["result"] == "DENY"
    assert len(result["steps"]) == 1


def test_snat_policy_before_translation_next_device_after_translation():
    configs = network_path()
    snat(configs[1], translated_port=45678)
    configs[2].policies[0].src = ["203.0.113.10/32"]
    configs[2].policies[0].src_ports = ["45678"]
    result = trace(configs)
    assert result["result"] == "ALLOW"
    assert result["steps"][1]["flow"]["current"]["source_addresses"] == ["10.0.1.0/24"]
    assert result["steps"][2]["packet_in"]["source_port"] == 45678
    assert result["flow"]["current"]["source_port"] == 45678
    assert result["flow"]["original"]["source_port"] == 12345


def test_dnat_then_snat_matches_translated_destination():
    configs = public_path()
    configs[0].nat.append(NATRule(device="r0", name="SNAT", type="source", original_dst="10.0.9.20", translated_src="192.0.2.1"))
    configs[1].policies[0].src = ["192.0.2.1/32"]
    result = inbound(configs)
    assert result["result"] == "ALLOW"
    assert [e["stage"] for e in result["steps"][0]["nat"]] == ["destination", "source"]


@pytest.mark.parametrize("stage", ["source", "destination"])
def test_exclude_terminates_only_its_stage(stage):
    configs = public_path()
    configs[0].nat.insert(0, NATRule(device="r0", name="exclude", type="exclude", stage=stage, sequence=0))
    if stage == "source":
        configs[0].nat.append(NATRule(device="r0", name="bad-snat", type="source", translated_src="invalid"))
        assert inbound(configs)["result"] == "ALLOW"
    else:
        result = inbound(configs)
        assert result["result"] == "UNKNOWN"
        assert result["flow"]["current"]["destination_port"] == 8443
        assert result["steps"][0]["nat"][0]["name"] == "exclude"


@pytest.mark.parametrize("changes", [
    {"translated_src": "203.0.113.1-203.0.113.20"},
    {"translated_src": "POOL-MISSING"},
    {"translated_src": "203.0.113.0/24"},
    {"original_src": "UNKNOWN-GROUP"},
    {"original_src": "10.0.1.10"},
    {"unsupported_matches": ["random"]},
    {"translated_src": "masquerade"},
])
def test_ambiguous_nat_stops_without_falling_through(changes):
    configs = network_path()
    snat(configs[0], **changes)
    configs[0].nat.append(NATRule(device="r0", name="later", type="source", translated_src="203.0.113.20"))
    result = trace(configs)
    assert result["result"] == "PARTIAL"
    assert len(result["steps"]) == 1
    assert result["steps"][0]["nat"][0]["applied"] is False
    assert result["flow"]["original"] == result["flow"]["current"]


def test_nat_rule_order_disabled_nonmatching_and_first_match():
    configs = network_path(2)
    rule = snat(configs[0])
    configs[0].nat = [rule.model_copy(update={"sequence": 1, "disabled": True}),
                      rule.model_copy(update={"sequence": 2, "original_dst": "172.16.0.0/16"}),
                      rule.model_copy(update={"sequence": 3, "name": "chosen"}),
                      rule.model_copy(update={"sequence": 4, "translated_src": "203.0.113.20"})]
    configs[1].policies[0].src = ["203.0.113.10"]
    result = trace(configs)
    assert result["result"] == "ALLOW"
    assert result["steps"][0]["nat"][0]["name"] == "chosen"


def test_dynamic_pat_does_not_invent_source_port():
    configs = network_path(2)
    snat(configs[0], dynamic_port=True)
    configs[1].policies[0].src = ["203.0.113.10"]
    result = trace(configs)
    assert result["result"] == "PARTIAL"
    assert result["steps"][1]["packet_in"]["source_port"] is None


def test_interface_masquerade_uses_configured_ip_only():
    configs = network_path(2)
    snat(configs[0], translated_src="masquerade")
    configs[0].interfaces[1].addresses = ["192.0.2.1/30"]
    configs[1].policies[0].src = ["192.0.2.1"]
    assert trace(configs)["result"] == "ALLOW"


def test_unknown_vendor_order_and_existing_sessions_are_not_guessed():
    configs = network_path(2)
    snat(configs[0])
    configs[0].device.network_os = "panos"
    assert trace(configs)["result"] == "PARTIAL"
    configs[0].device.network_os = "vyos"
    configs[0].policies[0].states = []
    result = trace(configs, state="established", assume_session=True)
    assert result["result"] == "PARTIAL"
    assert "セッション" in result["steps"][0]["nat"][0]["note"]


def test_srx_static_prefix_mapping_and_reverse_before_source_nat():
    config = network_path(2)[0]
    config.device.network_os = "srx"
    config.nat = [NATRule(device="r0", name="static", type="static", original_dst="203.0.113.0/24", translated_dst="10.0.9.0/24"),
                  NATRule(device="r0", name="source", type="source", translated_src="192.0.2.99")]
    packet = Packet(source_addresses=("10.0.1.10/32",), destination_addresses=("203.0.113.20/32",), protocol="tcp", ip_version=4)
    forward = apply_nat_stage(config, packet, config.segments[0], None, "destination")
    assert forward.packet.destination_addresses == ("10.0.9.20/32",)
    reverse_packet = packet.model_copy(update={"source_addresses": ("10.0.9.20/32",), "destination_addresses": ("10.0.1.10/32",)})
    reverse = apply_nat_stage(config, reverse_packet, config.segments[1], config.segments[0], "source")
    assert reverse.packet.source_addresses == ("203.0.113.20/32",)
    assert "reverse static" in reverse.effects[0].name


def test_vyos_parser_retains_exclusion_stage_and_unknown_nat_conditions():
    raw = """set system host-name nat-test
set nat destination rule 10 exclude
set nat destination rule 10 inbound-interface group MISSING
set nat source rule 20 translation address 203.0.113.1
set nat source rule 20 load-balance hash random
"""
    config, _ = ParserRegistry.parse(raw, "synthetic.conf", parser_id="vyos")
    assert config.nat[0].type == "exclude"
    assert config.nat[0].stage == "destination"
    assert config.nat[0].unsupported_matches
    assert config.nat[1].unsupported_matches == ["load-balance hash random"]


def test_routeros_parser_ports_exclusion_and_unknown_action():
    raw = """# RouterOS
/ip firewall nat
add chain=dstnat action=dst-nat dst-address=203.0.113.10 protocol=tcp dst-port=8443 to-addresses=10.0.9.20 to-ports=443
add chain=srcnat action=accept src-address=10.0.0.0/8
add chain=dstnat action=redirect to-ports=22
"""
    config, _ = ParserRegistry.parse(raw, "synthetic.rsc", parser_id="mikrotik_routeros")
    assert config.nat[0].translated_port == 443
    assert config.nat[1].type == "exclude"
    assert config.nat[2].unsupported_matches


def test_srx_parser_preserves_context_and_static_prefix():
    raw = """set system host-name nat-test
set security nat static rule-set IN from zone untrust
set security nat static rule-set IN rule WEB match destination-address 203.0.113.0/24
set security nat static rule-set IN rule WEB then static-nat prefix 10.0.9.0/24
"""
    config, _ = ParserRegistry.parse(raw, "synthetic.conf", parser_id="juniper_srx")
    assert config.nat[0].in_interfaces == ["untrust"]
    assert config.nat[0].translated_dst == "10.0.9.0/24"
    assert not config.nat[0].unsupported_matches


def test_api_returns_original_evaluation_and_output_packets(tmp_path, monkeypatch):
    from fastapi.testclient import TestClient
    from app import main
    from app.storage import SnapshotStore
    store = SnapshotStore(str(tmp_path / "nat.db"))
    monkeypatch.setattr(main, "store", store)
    store.create("nat", [(c.device.source_file, "", c) for c in public_path()])
    response = TestClient(main.app).get("/api/reachability", params=dict(src="r0-in", dst="public", protocol="tcp", port=8443,
        source_port=12345, source_ip="10.0.1.10", destination_ip="203.0.113.10"))
    assert response.status_code == 200
    data = response.json()
    assert data["result"] == "ALLOW"
    assert data["steps"][0]["nat"][0]["before"]["destination_port"] == 8443
    assert data["steps"][0]["nat"][0]["after"]["destination_port"] == 443


def test_parsed_vyos_dnat_is_applied_end_to_end():
    raw = """set system host-name edge
set interfaces ethernet eth0 address 10.0.1.1/24
set interfaces ethernet eth1 address 10.0.9.1/24
set interfaces ethernet eth2 address 203.0.113.1/24
set firewall ipv4 forward filter default-action drop
set firewall ipv4 forward filter rule 10 action accept
set firewall ipv4 forward filter rule 10 protocol tcp
set firewall ipv4 forward filter rule 10 destination address 10.0.9.20
set firewall ipv4 forward filter rule 10 destination port 443
set nat destination rule 10 inbound-interface name eth0
set nat destination rule 10 destination address 203.0.113.10
set nat destination rule 10 destination port 8443
set nat destination rule 10 protocol tcp
set nat destination rule 10 translation address 10.0.9.20
set nat destination rule 10 translation port 443
"""
    config, _ = ParserRegistry.parse(raw, "synthetic.conf", parser_id="vyos")
    by_network = {s.networks[0]: s.id for s in config.segments}
    result = analyze_reachability([config], by_network["10.0.1.0/24"], by_network["203.0.113.0/24"], "tcp", 8443,
                                  destination_ip="203.0.113.10")
    assert result["result"] == "ALLOW"
    assert result["path"][-1] == "segment:" + by_network["10.0.9.0/24"]


def test_legacy_nat_snapshots_request_reimport():
    from app.models import Trace
    configs = network_path(2)
    snat(configs[0], trace=Trace(source_file="old.conf", line_start=1, raw_config="synthetic"))
    result = trace(configs)
    assert result["result"] == "PARTIAL"
    assert "再取り込み" in result["route_reason"]


@pytest.mark.parametrize("ports,expected", [(["443,8443"], True), (["1024-65535"], True), (["443"], False), (["MISSING"], False)])
def test_nat_port_lists_and_unknown_services(ports, expected):
    configs = public_path()
    configs[0].nat[0].destination_ports = ports
    result = inbound(configs)
    assert (result["result"] == "ALLOW") == expected
    if ports == ["MISSING"]:
        assert result["result"] == "PARTIAL"


def test_no_snat_when_local_policy_denies():
    configs = network_path(2)
    snat(configs[0])
    configs[0].policies[0].action = "deny"
    result = trace(configs)
    assert result["result"] == "DENY"
    assert not result["steps"][0]["nat"]
    assert result["flow"]["current"] == result["flow"]["original"]


def test_fortios_snat_only_follows_the_selected_policy():
    configs = network_path(2)
    configs[0].device.network_os = "fortios"
    snat(configs[0], policy_id="nonmatching-policy")
    assert trace(configs)["flow"]["current"]["source_addresses"] == ["10.0.1.0/24"]
    configs[0].nat[0].policy_id = configs[0].policies[0].id
    configs[1].policies[0].src = ["203.0.113.10"]
    assert trace(configs)["result"] == "ALLOW"


def test_nat_ecmp_and_partial_route_ranges_are_not_arbitrarily_allowed():
    configs = public_path()
    configs[0].routes.append(Route(device="r0", destination="10.0.9.0/24", interface="eth0"))
    assert inbound(configs)["result"] == "PARTIAL"
    configs = network_path(2)
    snat(configs[0])
    configs[0].routes.append(Route(device="r0", destination="10.0.9.20/32", route_type="blackhole"))
    assert trace(configs)["result"] == "PARTIAL"


def test_srx_off_scope_and_pool_options_never_become_unconditional_translation():
    raw = """set system host-name nat-test
set security nat destination rule-set IN from zone outside
set security nat destination rule-set IN rule SKIP match destination-address 203.0.113.10
set security nat destination rule-set IN rule SKIP then destination-nat off
set security nat source pool PUB address 203.0.113.1 to 203.0.113.10
set security nat source rule-set OUT rule SNAT match source-address 10.0.1.0/24
set security nat source rule-set OUT rule SNAT then source-nat pool PUB
"""
    config, _ = ParserRegistry.parse(raw, "synthetic.conf", parser_id="juniper_srx")
    assert config.nat[0].stage == "destination"
    assert config.nat[0].type == "exclude"
    assert config.nat[1].unsupported_matches


@pytest.mark.parametrize("parser_id,raw", [
    ("vyos", "set system host-name edge\nset nat destination rule 10 load-balance hash random"),
    ("juniper_srx", "set system host-name edge\nset security nat destination rule-set IN rule UNKNOWN match source-address-name MISSING"),
])
def test_unsupported_only_nat_rules_are_not_dropped(parser_id, raw):
    config, _ = ParserRegistry.parse(raw, "synthetic.conf", parser_id=parser_id)
    assert len(config.nat) == 1
    assert config.nat[0].unsupported_matches


def test_srx_multiple_match_addresses_do_not_hide_an_uncertain_candidate():
    raw = """set system host-name edge
set security nat destination rule-set IN rule WEB match destination-address 203.0.113.10
set security nat destination rule-set IN rule WEB match destination-address 203.0.113.20
set security nat destination rule-set IN rule WEB then destination-nat pool PRIVATE
set security nat destination pool PRIVATE address 10.0.9.20
"""
    config, _ = ParserRegistry.parse(raw, "synthetic.conf", parser_id="juniper_srx")
    packet = Packet(source_addresses=("10.0.1.10/32",), destination_addresses=("203.0.113.10/32",), protocol="tcp", ip_version=4)
    ingress = network_path(2)[0].segments[0]
    assert apply_nat_stage(config, packet, ingress, None, "destination").blocked
