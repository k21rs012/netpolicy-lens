import json
import sqlite3
import pytest
from fastapi.testclient import TestClient
from app import main
from app.parsers import ParserRegistry
from app.sample import SAMPLES
from app.snapshot_backup import checksum
from app.storage import SnapshotStore


@pytest.fixture
def saved(tmp_path, monkeypatch):
    store = SnapshotStore(str(tmp_path / 'backup.db'))
    items = [(name, raw, ParserRegistry.parse(raw, name)[0]) for name, raw in SAMPLES.items()]
    snapshot_id = store.create('移行元', items, parser_version='original-parser')
    monkeypatch.setattr(main, 'store', store)
    return TestClient(main.app), store, snapshot_id


def upload(client, payload, endpoint='/api/snapshots/restore', name=None):
    data = json.dumps(payload, ensure_ascii=False).encode() if isinstance(payload, dict) else payload
    return client.post(endpoint, files={'file': ('backup.json', data, 'application/json')}, data={'name': name} if name is not None else {})


def test_backup_restore_roundtrip_and_preview_are_non_destructive(saved):
    client, store, original = saved
    response = client.get(f'/api/snapshots/{original}/backup')
    assert response.status_code == 200, response.text
    assert 'attachment' in response.headers['content-disposition']
    data = response.json()
    assert data['checksum'] == checksum(data)
    expected = store.load(original)
    matrix = client.get(f'/api/matrix?snapshot_id={original}&protocol=tcp&port=443').json()['cells']
    preview = upload(client, data, '/api/snapshots/restore/preview')
    assert preview.status_code == 200
    assert len(store.list()) == 1
    restored = upload(client, data, name=' 復元した構成 ')
    assert restored.status_code == 201, restored.text
    meta = restored.json()
    assert meta['id'] != original and meta['name'] == '復元した構成'
    assert meta['created_at'] != data['snapshot']['created_at']
    assert meta['parser_version'] == 'original-parser'
    assert meta['restored_from']['id'] == original
    assert len(store.list()) == 2 and store.load(original) == expected
    assert store.load(meta['id']) == expected
    assert client.get(f'/api/matrix?snapshot_id={meta["id"]}&protocol=tcp&port=443').json()['cells'] == matrix
    assert SnapshotStore(str(store.path)).get(meta['id']) == meta
    second_backup = client.get(f'/api/snapshots/{meta["id"]}/backup')
    assert second_backup.status_code == 200
    client.delete(f'/api/snapshots/{original}')
    assert upload(client, data).status_code == 201


@pytest.mark.parametrize('mutation', ['version', 'schema', 'type', 'count', 'unknown', 'missing', 'device', 'duplicate', 'bad_action', 'invalid_network'])
def test_incompatible_or_invalid_model_never_writes(saved, mutation):
    client, store, original = saved
    data = client.get(f'/api/snapshots/{original}/backup').json()
    cfg = data['configs'][0]['canonical']
    if mutation == 'version': data['format_version'] = 2
    elif mutation == 'schema': data['canonical_schema_version'] = 2
    elif mutation == 'type': data['format_version'] = True
    elif mutation == 'count': data['snapshot']['device_count'] += 1
    elif mutation == 'unknown': cfg['device']['future_feature'] = True
    elif mutation == 'missing': del cfg['policies']
    elif mutation == 'device': cfg['segments'][0]['device'] = 'other-device'
    elif mutation == 'duplicate':
        data['configs'].append(data['configs'][0]); data['snapshot']['device_count'] += 1
    elif mutation == 'invalid_network': cfg['segments'][0]['networks'] = ['not-a-network']
    elif mutation == 'bad_action': cfg['policies'][0]['action'] = 'bogus'
    data['checksum'] = checksum(data)
    for endpoint in ('/api/snapshots/restore/preview', '/api/snapshots/restore'):
        assert upload(client, data, endpoint).status_code == 422
    assert len(store.list()) == 1


def test_corruption_limits_and_invalid_name(saved, monkeypatch):
    client, store, original = saved
    data = client.get(f'/api/snapshots/{original}/backup').json()
    data['snapshot']['name'] = 'tampered'
    assert upload(client, data).status_code == 422
    for raw in (b'not JSON', b'[]', b'{"x":1,"x":2}', b'\xff', b'[' * 2000):
        assert upload(client, raw).status_code == 422
    data = client.get(f'/api/snapshots/{original}/backup').json()
    assert upload(client, data, name='  ').status_code == 422
    assert upload(client, data, name='a' * 129).status_code == 422
    monkeypatch.setattr(main, 'MAX_BACKUP_BYTES', 10)
    assert upload(client, data).status_code == 413
    assert len(store.list()) == 1
    assert client.get('/api/snapshots/missing/backup').status_code == 404


def test_export_and_restore_remask_credentials(saved):
    client, store, original = saved
    with store.connect() as con:
        con.execute('UPDATE configs SET raw_config=? WHERE snapshot_id=?', ('snmp-server community unique-secret RO', original))
    response = client.get(f'/api/snapshots/{original}/backup')
    assert 'unique-secret' not in response.text and '<masked>' in response.text
    data = response.json()
    data['configs'][0]['raw_config'] = 'snmp-server community injected-secret RO'
    data['configs'][0]['canonical']['warnings'].append({'device': data['configs'][0]['canonical']['device']['id'], 'line': 1,
        'config': 'snmp-server community injected-secret RO', 'reason': 'test', 'parser': 'test'})
    data['checksum'] = checksum(data)
    restored = upload(client, data)
    assert restored.status_code == 201
    response = client.get(f'/api/snapshots/{restored.json()["id"]}/backup')
    assert 'injected-secret' not in response.text


def test_restore_rolls_back_on_insert_failure(saved):
    client, store, original = saved
    data = client.get(f'/api/snapshots/{original}/backup').content
    with store.connect() as con:
        con.execute("CREATE TRIGGER fail_config BEFORE INSERT ON configs BEGIN SELECT RAISE(ABORT, 'test failure'); END")
    with pytest.raises(sqlite3.IntegrityError):
        upload(client, data)
    assert len(store.list()) == 1


def test_existing_database_migration_preserves_snapshot(tmp_path):
    path = str(tmp_path / 'old.db')
    with sqlite3.connect(path) as con:
        con.execute('CREATE TABLE snapshots (id TEXT PRIMARY KEY, name TEXT NOT NULL, created_at TEXT NOT NULL, parser_version TEXT NOT NULL)')
        con.execute("INSERT INTO snapshots VALUES ('old', 'existing', '2026-10-05T00:00:00+00:00', '0.1.0')")
    store = SnapshotStore(path)
    assert store.get('old')['name'] == 'existing'
    assert store.get('old')['restored_from'] is None
    assert SnapshotStore(path).get('old') == store.get('old')
