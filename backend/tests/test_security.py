import sqlite3

from fastapi.testclient import TestClient

from app import main
from app.models import ParserWarning
from app.parsers import ParserRegistry
from app.sample import SAMPLES
from app.security import mask_config
from app.storage import SnapshotStore


def test_mask_config_preserves_command_but_removes_credentials():
    raw = """enable secret 9 supersecret
username admin password 7 hiddenvalue
snmp-server community public RO
set password fortipass
interface Vlan10"""
    masked = mask_config(raw)
    assert "supersecret" not in masked
    assert "hiddenvalue" not in masked
    assert " public " not in masked
    assert "fortipass" not in masked
    assert masked.count("<masked>") == 4
    assert "interface Vlan10" in masked


def test_snapshot_masks_raw_trace_and_warning_and_exposes_warning_api(tmp_path):
    raw = SAMPLES["cisco01.conf"] + "\nenable secret 9 supersecret\n"
    config = ParserRegistry.parse(raw, "secure.conf")[0]
    config.policies[0].trace.raw_config = "username admin secret trace-secret"
    config.warnings.append(ParserWarning(device=config.device.id, line=99,
        config="snmp-server community private RW", reason="test warning", parser="cisco_iosxe"))
    store = SnapshotStore(str(tmp_path / "secure.db"))
    snapshot_id = store.create("secure", [("secure.conf", raw, config)])

    with sqlite3.connect(store.path) as connection:
        raw_saved, canonical = connection.execute(
            "SELECT raw_config, canonical_json FROM configs WHERE snapshot_id=?", (snapshot_id,)
        ).fetchone()
    for secret in ("supersecret", "trace-secret", "private"):
        assert secret not in raw_saved + canonical
    assert raw_saved.count("<masked>") == 1

    main.store = store
    response = TestClient(main.app).get(f"/api/parser/warnings?snapshot_id={snapshot_id}")
    assert response.status_code == 200
    assert response.json()["count"] == 1
    assert response.json()["items"][0]["config"] == "snmp-server community <masked> RW"
