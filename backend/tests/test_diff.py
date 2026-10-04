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


def test_conditioned_diff_only_reports_affected_traffic():
    _, _, before, after = versions()
    changed = compare_snapshots([before], [after], "tcp", 22)
    assert changed["evaluation"] == "path"
    row = next(row for row in changed["communications"] if row["new_allow"])
    assert row["before_result"] == "DENY"
    assert row["after_result"] == "ALLOW"
    assert row["before_reason"] and row["after_reason"]
    unrelated = compare_snapshots([before], [after], "tcp", 443)
    assert unrelated["communications"] == []
    assert unrelated["summary"]["changed_rules"] == 1
    reverse = compare_snapshots([after], [before], "tcp", 22)
    assert reverse["summary"]["new_deny"] == 1


def test_diff_conditions_validate_and_match_matrix(tmp_path, monkeypatch):
    store = SnapshotStore(str(tmp_path / "conditions.db"))
    monkeypatch.setattr(main, "store", store)
    raw, changed_raw, before, after = versions()
    store.create("before", [("cisco01.conf", raw, before)])
    after_id = store.create("after", [("cisco01.conf", changed_raw, after)])
    client = TestClient(main.app)
    for query in ("protocol=tcp&port=22", "port=22", "protocol=TCP", "protocol=udp&port=0"):
        response = client.get(f"/api/diff?{query}")
        assert response.status_code == 200
        data = response.json()
        assert data["evaluation"] == "path"
        cells = client.get(f"/api/matrix?snapshot_id={after_id}&{query}").json()["cells"]
        for row in data["communications"]:
            cell = next(c for c in cells if c["source"] == row["source"] and c["destination"] == row["destination"])
            assert row["after_result"] == cell["result"]
    for query in ("protocol=invalid", "protocol=icmp&port=22", "port=-1", "port=65536", "port=1.5"):
        assert client.get(f"/api/diff?{query}").status_code == 422


def test_route_only_change_is_not_reported_as_new_deny():
    from app.models import Route
    _, _, before, _ = versions()
    after = before.model_copy(deep=True)
    destination = next(s for s in after.segments if any("192.168.20." in n for n in s.networks))
    after.routes.append(Route(device=after.device.id, destination="192.168.20.0/25", next_hop="192.0.2.99"))
    result = compare_snapshots([before], [after], "tcp", 443)
    rows = [r for r in result["communications"] if r["destination"] == destination.id and r["before_result"] == "ALLOW"]
    assert rows
    assert any(r["after_result"] == "PARTIAL" for r in rows)
    assert all(not r["new_deny"] for r in rows)
    assert result["policies"] == []
