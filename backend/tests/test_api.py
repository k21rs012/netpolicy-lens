from pathlib import Path

from fastapi.testclient import TestClient

from app import main
from app.sample import SAMPLES
from app.storage import SnapshotStore


def test_sample_end_to_end(tmp_path: Path):
    main.store = SnapshotStore(str(tmp_path / "test.db"))
    client = TestClient(main.app)
    response = client.post("/api/sample/load")
    assert response.status_code == 200
    assert response.json()["imported"] == 9
    devices = client.get("/api/devices").json()["items"]
    assert len(devices) == 9
    matrix = client.get("/api/matrix").json()
    assert matrix["segments"]
    assert any(c["result"] == "PARTIAL" for c in matrix["cells"])


def test_capabilities_include_phase_two_firewalls(tmp_path: Path):
    main.store = SnapshotStore(str(tmp_path / "test.db"))
    data = TestClient(main.app).get("/api/parser/capabilities").json()
    assert any(c["parser_id"] == "yamaha_rtx" and c["status"] == "available" for c in data)
    assert any(c["parser_id"] == "fortinet_fortios" and c["status"] == "available" for c in data)
    assert any(c["parser_id"] == "paloalto_panos" and c["status"] == "available" for c in data)
    assert any(c["parser_id"] == "aruba_aoscx" and c["status"] == "available" for c in data)
    assert any(c["parser_id"] == "arista_eos" and c["status"] == "available" for c in data)
    assert any(c["parser_id"] == "alliedware_plus" and c["status"] == "available" for c in data)
    assert any(c["parser_id"] == "vyos" and c["status"] == "available" for c in data)
    assert any(c["parser_id"] == "cisco_nxos" and c["status"] == "planned" for c in data)


def test_import_multiple_pasted_device_configs_as_one_snapshot(tmp_path: Path):
    main.store = SnapshotStore(str(tmp_path / "pasted.db"))
    client = TestClient(main.app)
    response = client.post(
        "/api/configs/import",
        data={"snapshot_name": "pasted-devices"},
        files=[
            ("files", ("core-switch.conf", SAMPLES["cisco01.conf"], "text/plain")),
            ("files", ("edge-router.conf", SAMPLES["rtx01.conf"], "text/plain")),
        ],
    )
    assert response.status_code == 200
    assert [item["hostname"] for item in response.json()["imported"]] == ["cisco01", "rtx01"]
    snapshots = client.get("/api/snapshots").json()
    assert snapshots[0]["name"] == "pasted-devices"
    assert snapshots[0]["device_count"] == 2
