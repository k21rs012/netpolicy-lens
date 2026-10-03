"""Cross-feature regressions using parser output and persisted snapshots."""
import io
import json
import zipfile
import pytest
from fastapi.testclient import TestClient
from app import main
from app.models import Route
from app.reachability import analyze_reachability
from app.sample import SAMPLES
from app.storage import SnapshotStore
from test_ecmp import diamond


@pytest.mark.parametrize("destination", ["r0-out", "r1-in"])
def test_static_host_route_on_destination_segment_must_visit_gateway(destination):
    configs = diamond()
    configs[0].routes = [Route(device='r0', destination='192.0.2.100/32', next_hop='192.0.2.2')]
    configs[1].policies[0].action = 'deny'
    configs[1].policies[0].dst_segments = ['r1-in']
    configs[1].policies[0].to_zone = 'inside'
    result = analyze_reachability(configs, 'r0-in', destination, 'tcp', 443, destination_ip='192.0.2.100')
    assert result['result'] == 'DENY'
    assert [s['device'] for s in result['steps']] == ['r0', 'r1']


def test_invalid_explicit_gateway_does_not_crash_path_evaluation():
    configs = diamond()
    configs[0].routes = [Route(device='r0', destination='10.0.9.0/24', interface='out', next_hop='unresolved-object')]
    result = analyze_reachability(configs, 'r0-in', 'r3-out', 'tcp', 443)
    assert result['result'] == 'UNKNOWN'


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setattr(main, 'store', SnapshotStore(str(tmp_path / 'workflow.db')))
    return TestClient(main.app)


def test_zip_import_persistence_matrix_path_diff_export(client, monkeypatch):
    raw = SAMPLES['cisco01.conf'] + '\nenable secret 9 synthetic-audit-secret\n'
    archive = io.BytesIO()
    with zipfile.ZipFile(archive, 'w') as z:
        z.writestr('lab/core.conf', raw)
        z.writestr('bad.conf', 'not a config')
    files = [('files', ('lab.zip', archive.getvalue(), 'application/zip'))]
    preview = client.post('/api/configs/preview', files=files)
    assert preview.status_code == 200
    assert len(preview.json()['items']) == 2
    imported = client.post('/api/configs/import', files=files, data={'snapshot_name': 'before', 'sites': json.dumps({'lab/core.conf': 'Test'})})
    assert imported.status_code == 200
    before = imported.json()['snapshot_id']
    assert len(imported.json()['errors']) == 1
    monkeypatch.setattr(main, 'store', SnapshotStore(str(main.store.path)))
    assert client.get('/api/devices').json()['items'][0]['site'] == 'Test'
    for endpoint in ('/api/devices/cisco01', '/api/policies', '/api/parser/debug', '/api/parser/warnings', '/api/topology', '/api/matrix'):
        response = client.get(endpoint, params={'snapshot_id': before})
        assert response.status_code == 200, endpoint
        assert 'synthetic-audit-secret' not in response.text
    src, dst = 'cisco01-vlan-10', 'cisco01-vlan-20'
    for port, expected in [(22, 'DENY'), (443, 'ALLOW')]:
        path = client.get('/api/reachability', params={'src': src, 'dst': dst, 'protocol': 'tcp', 'port': port}).json()
        cell = client.get(f'/api/matrix/{src}/{dst}', params={'protocol': 'tcp', 'port': port}).json()
        assert path['result'] == expected
        assert cell['result'] == path['result']
    after = client.post('/api/configs/import', files=[('files', ('core.conf', raw.replace('20 deny tcp', '20 permit tcp'), 'text/plain'))]).json()['snapshot_id']
    diff = client.get('/api/diff', params={'before': before, 'after': after}).json()
    assert diff['summary']['new_allow'] == 1
    assert client.get(f'/api/matrix/{src}/{dst}', params={'protocol': 'tcp', 'port': 22}).json()['result'] == 'ALLOW'
    assert client.get(f'/api/matrix/{src}/{dst}', params={'protocol': 'tcp', 'port': 22, 'snapshot_id': before}).json()['result'] == 'DENY'
    assert client.post('/api/configs/import', files=[('files', ('bad.conf', 'invalid', 'text/plain'))]).status_code == 422
    assert client.get('/api/snapshots').json()[0]['id'] == after


@pytest.mark.parametrize('protocol,port', [('tcp', 443), ('udp', 53), ('icmp', None)])
def test_all_sample_pairs_return_valid_shared_path_results(client, protocol, port):
    assert client.post('/api/sample/load').status_code == 200
    response = client.get('/api/matrix', params={'protocol': protocol, **({'port': port} if port else {})})
    assert response.status_code == 200
    data = response.json()
    assert len(data['cells']) == len(data['segments']) ** 2
    for cell in data['cells']:
        assert cell['result'] in {'ALLOW', 'DENY', 'PARTIAL', 'UNKNOWN', 'NO_ROUTE', 'SAME_SEGMENT'}
        assert cell['evaluation'] == 'path'
