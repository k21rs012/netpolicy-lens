import pytest

from app.models import CanonicalConfig, Device, Interface, Policy, Route, Segment
from app.topology import analyze_reachability


def network_path(hops=3, version=4, transit_source=False):
    networks = (["10.0.1.0/24", "192.0.2.0/30", "198.51.100.0/30", "10.0.9.0/24"]
                if version == 4 else
                ["2001:db8:1::/64", "2001:db8:2::/64", "2001:db8:3::/64", "2001:db8:9::/64"])
    if hops == 2:
        networks.pop(2)
    configs = []
    for index in range(hops):
        device = f"r{index}"
        segments = [Segment(id=f"{device}-{side}", name=side, type="zone", device=device,
                            networks=[networks[index + offset]])
                    for offset, side in enumerate(("in", "out"))]
        rule = Policy(id=f"{device}-permit", device=device, name="forward", sequence=10,
                      direction="zone", from_zone="inside", to_zone="outside",
                      src_segments=[segments[0].id], dst_segments=[segments[1].id],
                      src=[networks[index] if transit_source and index else networks[0]],
                      dst=[networks[-1]], action="permit", protocol=["tcp"],
                      src_ports=["12345"], dst_ports=["443"], states=["new"],
                      ip_version=version, default_action="deny")
        configs.append(CanonicalConfig(
            device=Device(id=device, hostname=device, vendor="vyos", network_os="vyos", source_file=device),
            segments=segments,
            interfaces=[Interface(device=device, name=side, zone=zone, segment_id=segment.id)
                        for side, zone, segment in zip(("eth0", "eth1"), ("inside", "outside"), segments)],
            routes=[Route(device=device, destination=networks[-1], interface="eth1")],
            policies=[rule],
        ))
    return configs


def trace(configs, **kwargs):
    return analyze_reachability(configs, "r0-in", f"r{len(configs)-1}-out", "tcp", 443,
                                source_port=12345, **kwargs)


@pytest.mark.parametrize("hops", [2, 3])
@pytest.mark.parametrize("version", [4, 6])
def test_endpoints_and_transport_are_preserved_through_all_hops(hops, version):
    configs = network_path(hops, version)
    result = trace(configs, ip_version=version)
    assert result["result"] == "ALLOW"
    assert len(result["steps"]) == hops
    original = result["flow"]["original"]
    assert original["source_addresses"] == configs[0].segments[0].networks
    assert original["destination_addresses"] == configs[-1].segments[-1].networks
    assert original["source_port"] == 12345
    assert original["destination_port"] == 443
    assert original["state"] == "new"
    assert original["ip_version"] == version
    for index, step in enumerate(result["steps"]):
        assert step["ingress"] == f"r{index}-in"
        assert step["egress"] == f"r{index}-out"
        assert step["flow"]["original"] == original
        assert step["flow"]["current"] == original


def test_transit_subnet_permit_does_not_allow_remote_source():
    assert trace(network_path(transit_source=True))["result"] == "DENY"


def test_hop_zone_binding_still_applies():
    configs = network_path()
    configs[1].policies[0].src_segments = ["r1-out"]
    assert trace(configs)["result"] != "ALLOW"


def test_segment_scope_is_not_replaced_by_representative_host():
    configs = network_path()
    configs[1].policies[0].src = ["10.0.1.10/32"]
    assert trace(configs)["result"] == "PARTIAL"
    exact = trace(configs, source_ip="10.0.1.10", destination_ip="10.0.9.20")
    assert exact["result"] == "ALLOW"
    assert exact["flow"]["current"]["source_addresses"] == ["10.0.1.10/32"]
    assert trace(configs, source_ip="10.0.1.11")["result"] == "DENY"


@pytest.mark.parametrize("kwargs", [
    {"source_ip": "invalid"}, {"source_ip": "10.99.0.1"},
    {"destination_ip": "10.0.1.5"},
    {"source_ip": "10.0.1.5", "ip_version": 6},
])
def test_invalid_host_selection_is_rejected(kwargs):
    with pytest.raises(ValueError):
        trace(network_path(), **kwargs)


def test_jump_preserves_remote_packet_and_negated_addresses():
    configs = network_path()
    original = configs[1].policies[0]
    configs[1].policies = [
        original.model_copy(update={"action": "jump", "jump_target": "child", "chain_id": "parent"}),
        original.model_copy(update={"id": "child", "chain_id": "child", "entrypoint": False,
                                    "src": ["192.0.2.0/30"], "src_negate": True}),
    ]
    assert trace(configs)["result"] == "ALLOW"


def test_explicit_destination_ip_selects_host_route():
    configs = network_path()
    configs[0].routes.insert(0, Route(device="r0", destination="10.0.9.20/32", route_type="blackhole"))
    assert trace(configs, destination_ip="10.0.9.20")["result"] == "NO_ROUTE"
    assert trace(configs, destination_ip="10.0.9.21")["result"] == "ALLOW"


def test_nat_candidate_uses_remote_addresses_but_local_interfaces():
    from app.models import NATRule

    configs = network_path()
    configs[1].nat = [NATRule(device="r1", name="remote-source", type="source",
                              original_src="10.0.1.0/24", original_dst="10.0.9.0/24",
                              in_interfaces=["eth0"], out_interfaces=["eth1"],
                              translated_src="203.0.113.1")]
    result = trace(configs)
    assert result["steps"][1]["nat"][0]["name"] == "remote-source"
    assert result["steps"][2]["flow"]["current"] == result["flow"]["original"]


def test_api_returns_flow_and_validates_ip_inputs(tmp_path, monkeypatch):
    from fastapi.testclient import TestClient
    from app import main
    from app.storage import SnapshotStore

    store = SnapshotStore(str(tmp_path / "flow.db"))
    monkeypatch.setattr(main, "store", store)
    store.create("flow", [(config.device.source_file, "", config) for config in network_path()])
    client = TestClient(main.app)
    params = dict(src="r0-in", dst="r2-out", protocol="tcp", port=443, source_port=12345,
                  source_ip="10.0.1.10", destination_ip="10.0.9.20")
    response = client.get("/api/reachability", params=params)
    assert response.status_code == 200
    assert response.json()["result"] == "ALLOW"
    assert response.json()["steps"][1]["flow"]["current"]["source_addresses"] == ["10.0.1.10/32"]
    for invalid in ("bad", "10.9.0.1", "2001:db8::1"):
        assert client.get("/api/reachability", params={**params, "source_ip": invalid}).status_code == 422
    assert client.get("/api/reachability", params={**params, "src": "missing"}).status_code == 404


def test_ipv4_query_cannot_use_ipv6_only_adjacency():
    configs = network_path(2)
    configs[0].segments[1].networks = ["2001:db8:2::/64"]
    configs[1].segments[0].networks = ["2001:db8:2::/64"]
    assert trace(configs, ip_version=4)["result"] == "NO_ROUTE"


def test_dual_stack_query_requires_family_to_avoid_mixing_verdicts():
    configs = network_path(2)
    configs[0].segments[0].networks.append("2001:db8:1::/64")
    configs[-1].segments[-1].networks.append("2001:db8:9::/64")
    assert trace(configs)["result"] == "UNKNOWN"
    assert trace(configs, ip_version=4)["result"] == "ALLOW"


def test_remote_source_deny_wins_over_later_permit():
    configs = network_path()
    deny = configs[1].policies[0].model_copy(update={"action": "deny", "id": "remote-deny"})
    configs[1].policies = [deny, deny.model_copy(update={"id": "later", "sequence": 20,
                                                       "src": ["any"], "action": "permit"})]
    result = trace(configs)
    assert result["result"] == "DENY"
    assert result["steps"][1]["policy"] == "remote-deny"


def test_ipv6_specific_hosts_are_preserved():
    result = trace(network_path(version=6), source_ip="2001:db8:1::10", destination_ip="2001:db8:9::20")
    assert result["result"] == "ALLOW"
    assert result["ip_version"] == 6
    assert result["steps"][-1]["flow"]["current"]["source_addresses"] == ["2001:db8:1::10/128"]
