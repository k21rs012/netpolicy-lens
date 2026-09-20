"""Synthetic AlliedWare Plus fixtures; no customer configuration or credentials."""
import pytest

from app.analyzer import build_matrix
from app.parsers import ParserRegistry
from app.topology import analyze_reachability


CONFIG = """hostname access-switch
switch 1 provision x540L-28
atmf network-name lab
vlan database
 vlan 101 name MGMT
 vlan 102 name GUEST
 vlan 103 name UPLINK
 vlan 104 name APP
 vlan 101-104 state enable
!
access-list 10 permit 10.20.1.100
access-list 10 permit 10.20.1.101
access-list 20 permit 10.20.1.0 0.0.0.255
!
access-list hardware GUEST_IN
 permit udp any eq 68 any eq 67
 permit udp 10.20.4.0/22 10.20.1.53/32 eq 53
 permit tcp 10.20.4.0/22 10.20.1.53/32 eq 53
 permit udp 10.20.4.0/22 10.20.1.54/32 eq 53
 permit tcp 10.20.4.0/22 10.20.1.54/32 eq 53
 permit icmp 10.20.4.0/22 10.20.1.0/24 icmp-type 0
 deny ip 10.20.4.0/22 10.20.1.0/24
 deny ip 10.20.4.0/22 10.20.0.0/29
 deny ip 10.20.4.0/22 192.0.2.0/24
!
vlan access-map GUEST_FILTER
 match access-group GUEST_IN
!
interface port1.0.1
 switchport mode trunk
 switchport trunk allowed vlan add 101-102,104
interface port1.0.2-1.0.4
 switchport mode access
 shutdown
interface vlan101
 ip address 10.20.1.1/24
interface vlan102
 ip address 10.20.4.1/22
interface vlan103
 ip address 10.20.0.2/29
interface vlan104
 ip address 192.0.2.254/24
!
vlan filter GUEST_FILTER vlan-list 102 input
ip route 0.0.0.0/0 10.20.0.1
vty access-class 20
"""


def parse(raw=CONFIG):
    return ParserRegistry.parse(raw, "synthetic-allied.conf")[0]


def trace(config, vlan=101, protocol="tcp", port=443, **kwargs):
    return analyze_reachability([config], "access-switch-vlan-102", f"access-switch-vlan-{vlan}",
                                protocol, port, **kwargs)


def test_detect_and_bind_allied_vlan_access_map():
    config = parse()
    assert config.device.network_os == "alliedware-plus"
    assert config.device.confidence >= .5
    bound = [p for p in config.policies if p.name == "GUEST_IN" and p.direction == "in"]
    assert len(bound) == 9
    assert all(p.src_segments == ["access-switch-vlan-102"] for p in bound)
    assert all(p.default_action == "permit" for p in bound)
    assert all(p.trace.raw_config.strip() in CONFIG for p in bound)
    assert any(c.result != "UNKNOWN" for c in build_matrix([config]) if c.source != c.destination)


@pytest.mark.parametrize("vlan", [101, 103, 104])
def test_guest_tcp_to_protected_network_is_denied(vlan):
    assert trace(parse(), vlan)["result"] == "DENY"


@pytest.mark.parametrize("protocol", ["tcp", "udp"])
@pytest.mark.parametrize("host", ["10.20.1.53", "10.20.1.54"])
def test_dns_exceptions_match_only_dns_hosts(protocol, host):
    assert trace(parse(), protocol=protocol, port=53, source_port=40000,
                 source_ip="10.20.4.10", destination_ip=host)["result"] == "ALLOW"
    assert trace(parse(), protocol=protocol, port=53, source_port=40000,
                 destination_ip="10.20.1.55")["result"] == "DENY"


def test_dhcp_exception_keeps_source_port():
    assert trace(parse(), protocol="udp", port=67, source_port=68)["result"] == "ALLOW"
    assert trace(parse(), protocol="udp", port=67, source_port=69)["result"] == "DENY"
    assert trace(parse(), protocol="udp", port=67)["result"] == "PARTIAL"


def test_echo_reply_is_not_echo_request():
    config = parse()
    assert trace(config, protocol="icmp", port=None, icmp_type=0)["result"] == "ALLOW"
    assert trace(config, protocol="icmp", port=None, icmp_type=8)["result"] == "DENY"
    assert trace(config, protocol="icmp", port=None)["result"] == "PARTIAL"


def test_hardware_default_is_permit_not_implicit_deny():
    config = parse(CONFIG.replace(" deny ip 10.20.4.0/22 192.0.2.0/24\n", ""))
    assert trace(config, 104)["result"] == "ALLOW"


def test_numbered_management_acls_are_standard_and_not_transit_filters():
    config = parse()
    rules = [p for p in config.policies if p.name in {"10", "20"}]
    assert len(rules) == 3
    assert all(p.protocol == ["ip"] and p.dst == ["any"] and p.direction == "unknown" for p in rules)
    assert rules[0].src == ["10.20.1.100"]


@pytest.mark.parametrize("old,new", [("match access-group GUEST_IN", "match access-group MISSING"),
                                      ("vlan filter GUEST_FILTER", "vlan filter MISSING")])
def test_missing_references_never_allow(old, new):
    config = parse(CONFIG.replace(old, new))
    assert trace(config)["result"] in {"UNKNOWN", "PARTIAL"}
    assert any("MISSING" in w.reason for w in config.warnings)


def test_binding_multiple_vlans_does_not_overwrite_previous_binding():
    config = parse(CONFIG.replace("vlan-list 102 input", "vlan-list 102-103 input"))
    bound = [p for p in config.policies if p.name == "GUEST_IN" and p.direction == "in"]
    assert {tuple(p.src_segments) for p in bound} == {("access-switch-vlan-102",), ("access-switch-vlan-103",)}
    assert len({p.id for p in config.policies}) == len(config.policies)


def test_port_ranges_and_trunk_vlan_ranges_expand():
    config = parse()
    assert {i.name for i in config.interfaces} >= {"port1.0.1", "port1.0.2", "port1.0.3", "port1.0.4"}
    assert next(i.trunk_vlans for i in config.interfaces if i.name == "port1.0.1") == [101, 102, 104]
    interface = next(i for i in config.interfaces if i.name == "port1.0.4")
    assert interface.trace.raw_config == "interface port1.0.2-1.0.4"


@pytest.mark.parametrize("change", [
    (" permit udp any eq 68 any eq 67", " copy-to-cpu ip any any"),
    ("match access-group GUEST_IN", "match access-group 10"),
    ("vlan-list 102 input", "vlan-list 102 output"),
    ("match access-group GUEST_IN", "match access-group GUEST_IN\n unsupported match"),
])
def test_unsupported_filter_semantics_do_not_fall_through_to_allow(change):
    config = parse(CONFIG.replace(*change))
    assert trace(config, port=53, destination_ip="10.20.1.53")["result"] in {"PARTIAL", "UNKNOWN"}
    assert config.warnings


def test_empty_acl_does_not_become_unconditional_permit():
    config = parse(CONFIG.replace("access-list hardware GUEST_IN", "access-list hardware UNUSED")
                   + "\naccess-list hardware GUEST_IN\n")
    assert trace(config)["result"] in {"PARTIAL", "UNKNOWN"}


def test_interleaved_numbered_acl_entries_keep_their_acl():
    config = parse(CONFIG + "\naccess-list 10 permit 10.20.1.102\n")
    assert len([p for p in config.policies if p.name == "10"]) == 3
    assert len({p.id for p in config.policies}) == len(config.policies)
    assert not any(p.src == ["10.20.1.102"] and p.direction != "unknown" for p in config.policies)


def test_filter_order_combination_is_not_claimed_exact():
    config = parse(CONFIG + "\naccess-group GLOBAL\n")
    assert trace(config, port=53, destination_ip="10.20.1.53")["result"] == "PARTIAL"


def test_unbound_vlan_does_not_inherit_guest_acl():
    config = parse()
    result = analyze_reachability([config], "access-switch-vlan-101", "access-switch-vlan-102", "tcp", 443)
    assert result["result"] == "UNKNOWN"


def test_import_preview_matrix_and_icmp_api(tmp_path, monkeypatch):
    from fastapi.testclient import TestClient
    from app import main
    from app.storage import SnapshotStore

    monkeypatch.setattr(main, "store", SnapshotStore(str(tmp_path / "allied.db")))
    client = TestClient(main.app)
    files = {"files": ("synthetic-allied.conf", CONFIG, "text/plain")}
    preview = client.post("/api/configs/preview", files=files)
    assert preview.status_code == 200
    assert preview.json()["items"][0]["detected"]["parser_id"] == "alliedware_plus"
    assert not preview.json()["items"][0]["needs_confirmation"]
    imported = client.post("/api/configs/import", files=files)
    assert imported.status_code == 200
    assert not imported.json()["errors"]
    matrix = client.get("/api/matrix").json()
    assert len(matrix["segments"]) == 4
    assert any(cell["result"] == "PARTIAL" for cell in matrix["cells"])
    params = dict(src="access-switch-vlan-102", dst="access-switch-vlan-101", protocol="icmp", icmp_type=0)
    reply = client.get("/api/reachability", params=params)
    assert reply.status_code == 200
    assert reply.json()["result"] == "ALLOW"
    assert reply.json()["flow"]["current"]["icmp_type"] == 0
    assert client.get("/api/reachability", params={**params, "icmp_type": 8}).json()["result"] == "DENY"
    for value in (-1, 256):
        assert client.get("/api/reachability", params={**params, "icmp_type": value}).status_code == 422
    assert client.get("/api/reachability", params={**params, "protocol": "tcp"}).status_code == 422
