from fastapi.testclient import TestClient

from app import main
from app.parsers import ParserRegistry
from app.sample import SAMPLES
from app.storage import SnapshotStore
from app.topology import analyze_reachability, build_topology


def sample_configs():
    return [ParserRegistry.parse(SAMPLES[name], name)[0] for name in ("cisco01.conf", "rtx01.conf")]


def test_topology_infers_shared_subnet_adjacency():
    topology = build_topology(sample_configs())
    edge = next(x for x in topology["edges"] if x["type"] == "adjacent")
    assert edge["confidence"] == "INFERRED"
    assert edge["label"] == "192.168.20.0/24"


def test_multidevice_path_denies_ssh_at_cisco():
    result = analyze_reachability(sample_configs(), "cisco01-vlan-10", "rtx01-lan1", "tcp", 22)
    assert result["result"] == "DENY"
    assert "device:cisco01" in result["path"] and "device:rtx01" in result["path"]
    assert result["steps"][0]["result"] == "DENY"
    assert result["steps"][0]["reason"] == "USER-IN / Rule 20"


def test_multidevice_https_stays_unknown_without_second_device_evidence():
    result = analyze_reachability(sample_configs(), "cisco01-vlan-10", "rtx01-lan1", "tcp", 443)
    assert result["steps"][0]["result"] == "ALLOW"
    assert result["steps"][1]["result"] == "UNKNOWN"
    assert result["result"] == "UNKNOWN"


def test_no_route_is_explicit():
    configs = sample_configs() + [ParserRegistry.parse(SAMPLES["srx01.conf"], "srx01.conf")[0]]
    result = analyze_reachability(configs, "cisco01-vlan-10", "srx01-zone-trust", "tcp", 443)
    assert result["result"] == "NO_ROUTE"


def test_topology_and_reachability_api(tmp_path):
    main.store = SnapshotStore(str(tmp_path / "topology.db")); configs = sample_configs()
    snapshot_id = main.store.create("topology", [(x.device.source_file, SAMPLES[x.device.source_file], x) for x in configs])
    client = TestClient(main.app)
    topology = client.get(f"/api/topology?snapshot_id={snapshot_id}")
    assert topology.status_code == 200 and topology.json()["summary"]["devices"] == 2
    reachability = client.get(f"/api/reachability?src=cisco01-vlan-10&dst=rtx01-lan1&protocol=tcp&port=22&snapshot_id={snapshot_id}")
    assert reachability.status_code == 200 and reachability.json()["result"] == "DENY"
