from pathlib import Path
import json

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
    for parser_id in ("cisco_nxos", "cisco_asa", "cisco_ftd", "extreme_exos", "extreme_voss", "mikrotik_routeros"):
        assert any(c["parser_id"] == parser_id and c["status"] == "available" for c in data)


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


def test_preview_and_per_file_parser_override(tmp_path: Path):
    main.store = SnapshotStore(str(tmp_path / "preview.db"))
    client = TestClient(main.app)
    files = [
        ("files", ("known.conf", SAMPLES["cisco01.conf"], "text/plain")),
        ("files", ("manual.conf", "hostname manual-only\n", "text/plain")),
    ]
    preview = client.post("/api/configs/preview", files=files)
    assert preview.status_code == 200
    assert preview.json()["items"][0]["detected"]["parser_id"] in ("cisco_ios", "cisco_iosxe")
    assert preview.json()["items"][1]["needs_confirmation"] is True

    response = client.post(
        "/api/configs/import",
        data={"parser_ids": json.dumps({"manual.conf": "cisco_ios"}),
              "sites": json.dumps({"known.conf": "Tokyo-DC", "manual.conf": "Osaka-Branch"})},
        files=files,
    )
    assert response.status_code == 200
    assert len(response.json()["imported"]) == 2
    assert response.json()["results"][1]["parser_id"] == "cisco_ios"
    devices = client.get("/api/devices").json()["items"]
    assert {item["site"] for item in devices} == {"Tokyo-DC", "Osaka-Branch"}


def test_import_reports_partial_failures_without_dropping_success(tmp_path: Path):
    main.store = SnapshotStore(str(tmp_path / "partial.db"))
    response = TestClient(main.app).post(
        "/api/configs/import",
        files=[
            ("files", ("good.conf", SAMPLES["rtx01.conf"], "text/plain")),
            ("files", ("bad.conf", "this is not a network config", "text/plain")),
        ],
    )
    body = response.json()
    assert response.status_code == 200
    assert len(body["imported"]) == 1
    assert body["errors"][0]["source_file"] == "bad.conf"
    assert [item["status"] for item in body["results"]] == ["imported", "error"]


def test_import_rejects_invalid_zip_and_oversized_upload(monkeypatch):
    client = TestClient(main.app)
    invalid = client.post("/api/configs/preview", files=[("files", ("bad.zip", b"not-a-zip", "application/zip"))])
    assert invalid.status_code == 422

    monkeypatch.setattr(main, "MAX_UPLOAD_BYTES", 4)
    oversized = client.post("/api/configs/preview", files=[("files", ("large.conf", b"12345", "text/plain"))])
    assert oversized.status_code == 413
