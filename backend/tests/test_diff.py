from fastapi.testclient import TestClient

from app import main
from app.diff import compare_snapshots
from app.parsers import ParserRegistry
from app.sample import SAMPLES
from app.storage import SnapshotStore


def versions():
    before_raw = SAMPLES["cisco01.conf"]
    after_raw = before_raw.replace(
        "20 deny tcp 192.168.10.0 0.0.0.255 192.168.20.0 0.0.0.255 eq 22",
        "20 permit tcp 192.168.10.0 0.0.0.255 192.168.20.0 0.0.0.255 eq 22",
    ).replace("name SERVER", "name SERVER-RENAMED")
    before = ParserRegistry.parse(before_raw, "cisco01.conf")[0]
    after = ParserRegistry.parse(after_raw, "cisco01.conf")[0]
    return before_raw, after_raw, before, after


def test_diff_highlights_new_allow_and_changed_rule():
    _, _, before, after = versions()
    result = compare_snapshots([before], [after])
    assert result["summary"]["new_allow"] == 1
    assert result["summary"]["removed_rules"] == 0
    assert result["summary"]["changed_rules"] == 1
    communication = next(x for x in result["communications"] if x["new_allow"])
    assert communication["new_allow"] == ["TCP/22"]
    assert communication["removed_deny"] == ["TCP/22"]
    assert any(x["kind"] == "vlan" and x["change"] == "CHANGED" for x in result["network"])


def test_diff_api_defaults_to_latest_pair(tmp_path):
    main.store = SnapshotStore(str(tmp_path / "diff.db"))
    before_raw, after_raw, before, after = versions()
    before_id = main.store.create("before", [("cisco01.conf", before_raw, before)])
    after_id = main.store.create("after", [("cisco01.conf", after_raw, after)])
    response = TestClient(main.app).get("/api/diff")
    assert response.status_code == 200
    data = response.json()
    assert data["before"]["id"] == before_id
    assert data["after"]["id"] == after_id
    assert data["summary"]["new_allow"] == 1


def test_diff_requires_distinct_snapshots(tmp_path):
    main.store = SnapshotStore(str(tmp_path / "diff.db"))
    raw, _, config, _ = versions()
    snapshot_id = main.store.create("only", [("cisco01.conf", raw, config)])
    response = TestClient(main.app).get(f"/api/diff?before={snapshot_id}&after={snapshot_id}")
    assert response.status_code == 422
