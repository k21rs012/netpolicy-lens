from app.analyzer import build_matrix
from app.models import CanonicalConfig, Device, Interface, Policy, Segment
from app.topology import analyze_reachability


def config_with_policies(*policies: Policy) -> CanonicalConfig:
    device = Device(id="edge", hostname="edge", vendor="cisco", network_os="ios-xe", source_file="edge.conf")
    segments = [
        Segment(id="edge-user", name="USER", type="vlan", device="edge", networks=["10.0.1.0/24"]),
        Segment(id="edge-server", name="SERVER", type="vlan", device="edge", networks=["10.0.2.0/24"]),
    ]
    interfaces = [
        Interface(device="edge", name="Vlan10", segment_id="edge-user", acl_in=["EDGE-IN"]),
        Interface(device="edge", name="Vlan20", segment_id="edge-server"),
    ]
    return CanonicalConfig(device=device, interfaces=interfaces, segments=segments, policies=list(policies))


def policy(sequence: int, action: str, destination: str = "10.0.2.0/24", port: str = "443") -> Policy:
    return Policy(
        id=f"edge:EDGE-IN:{sequence}", device="edge", name="EDGE-IN", sequence=sequence,
        src=["10.0.1.0/24"], dst=[destination], src_segments=["edge-user"],
        protocol=["tcp"], dst_ports=[port], action=action, direction="in", interface="Vlan10",
    )


def matrix_cell(config: CanonicalConfig):
    return next(cell for cell in build_matrix([config]) if cell.source == "edge-user" and cell.destination == "edge-server")


def test_first_matching_rule_wins_for_same_acl_and_service():
    cell = matrix_cell(config_with_policies(policy(10, "deny"), policy(20, "permit")))

    assert cell.result == "DENY"
    assert cell.allowed == []
    assert cell.denied == ["TCP/443"]
    assert cell.policy_ids == ["edge:EDGE-IN:10"]


def test_host_scoped_permit_is_partial_for_a_whole_segment():
    cell = matrix_cell(config_with_policies(policy(10, "permit", "10.0.2.10/32")))

    assert cell.result == "PARTIAL"
    assert cell.allowed == ["TCP/443"]
    assert cell.traces[0]["coverage"] == "PARTIAL"


def test_network_scoped_permit_covers_the_whole_segment():
    cell = matrix_cell(config_with_policies(policy(10, "permit")))

    assert cell.result == "ALLOW"
    assert cell.traces[0]["coverage"] == "FULL"


def test_unresolved_address_object_is_partial_not_full_allow():
    cell = matrix_cell(config_with_policies(policy(10, "permit", "SERVER-OBJECT")))

    assert cell.result == "PARTIAL"


def test_applied_acl_without_matching_service_is_implicit_deny():
    config = config_with_policies(policy(10, "permit", port="443"))
    result = analyze_reachability(configs=[config], source="edge-user", destination="edge-server", protocol="tcp", port=22)

    assert result["result"] == "DENY"
    assert result["steps"][0]["reason"] == "適用Policyの暗黙deny"
