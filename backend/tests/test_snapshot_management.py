import sqlite3
import pytest
from fastapi.testclient import TestClient
from app import main
from app.storage import SnapshotStore
from test_scale import synthetic


@pytest.fixture
def setup(tmp_path, monkeypatch):
    store = SnapshotStore(str(tmp_path / 'snapshots.db'))
    cfg = synthetic(1)[0]
    first = store.create('before', [('before.conf', '', cfg)])
    cfg.policies[0].action = 'deny'
    second = store.create('after', [('after.conf', '', cfg)])
    monkeypatch.setattr(main, 'store', store)
    return TestClient(main.app), store, first, second


def test_rename_preserves_identity_order_config_and_created_time(setup):
    client, store, first, second = setup
    before, configs = store.get(first), store.load(first)
    response = client.patch(f'/api/snapshots/{first}', json={'name': '  変更前の構成  '})
    assert response.status_code == 200
    assert response.json() == {**before, 'name': '変更前の構成'}
    assert store.load(first) == configs and store.latest_id() == second
    assert SnapshotStore(str(store.path)).get(first)['name'] == '変更前の構成'
    assert client.get('/api/diff', params={'before': first, 'after': second}).json()['before']['name'] == '変更前の構成'


@pytest.mark.parametrize('name', ['', '   ', 'x' * 129, None])
def test_invalid_name_does_not_change_snapshot(setup, name):
    client, store, first, _ = setup
    assert client.patch(f'/api/snapshots/{first}', json={'name': name}).status_code == 422
    assert store.get(first)['name'] == 'before'


def test_delete_clears_configs_and_cannot_serve_cached_result(setup):
    client, store, first, second = setup
    client.get('/api/matrix', params={'snapshot_id': second, 'limit': 25})
    assert client.delete(f'/api/snapshots/{second}').status_code == 204
    assert store.latest_id() == first
    assert store.load(second) == [] and store.get(second) is None
    assert store.get(first) is not None
    for endpoint in ['/api/matrix?limit=25&', '/api/topology?', '/api/devices?', '/api/policies?', '/api/parser/debug?']:
        assert client.get(endpoint + f'snapshot_id={second}').status_code == 404
    assert client.get('/api/matrix?limit=25').json()['snapshot_id'] == first
    assert client.get('/api/diff', params={'before': first, 'after': second}).status_code == 404
    assert client.delete(f'/api/snapshots/{second}').status_code == 404
    assert client.patch(f'/api/snapshots/{second}', json={'name': 'gone'}).status_code == 404
    assert client.delete(f'/api/snapshots/{first}').status_code == 204
    assert client.get('/api/snapshots').json() == []
    empty = client.get('/api/matrix?limit=25').json()
    assert empty['snapshot_id'] is None and empty['cells'] == []
    with store.connect() as con:
        assert con.execute('SELECT COUNT(*) FROM configs').fetchone()[0] == 0


def test_delete_is_atomic_if_snapshot_delete_fails(setup):
    _, store, first, _ = setup
    original = store.load(first)
    with store.connect() as con:
        con.execute("CREATE TRIGGER prevent_delete BEFORE DELETE ON snapshots BEGIN SELECT RAISE(ABORT, 'test failure'); END")
    with pytest.raises(sqlite3.IntegrityError):
        store.delete(first)
    assert store.load(first) == original and store.get(first) is not None
