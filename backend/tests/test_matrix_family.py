from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from app import main
from app.storage import SnapshotStore

LAB = Path(__file__).resolve().parents[2] / 'lab/scenarios'


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setattr(main, 'store', SnapshotStore(str(tmp_path / 'family.db')))
    return TestClient(main.app)


def snapshots(client, scenario='cisco'):
    ids = {}
    for version in ('before', 'after'):
        file = next((LAB / scenario / version).iterdir())
        response = client.post('/api/configs/import', files={'files': (file.name, file.read_bytes())})
        assert response.status_code == 200
        ids[version] = response.json()['snapshot_id']
    return ids


@pytest.mark.parametrize('scenario,src,dst', [
    ('cisco', 'cisco-lab-vlan-10', 'cisco-lab-vlan-90'),
    ('vyos', 'vyos-lab-if-eth0', 'vyos-lab-if-eth2'),
])
def test_matrix_family_matches_path_and_cache_is_separate(client, scenario, src, dst):
    ids = snapshots(client, scenario)
    query = {'snapshot_id': ids['after'], 'protocol': 'tcp', 'port': 443}
    for family, expected in [(4, 'DENY'), (6, 'ALLOW'), (4, 'DENY'), (None, 'UNKNOWN')]:
        params = {**query, **({'ip_version': family} if family else {})}
        full = client.get('/api/matrix', params={**params, 'limit': 25}).json()
        assert full['ip_version'] == family
        cell = next(c for c in full['cells'] if c['source'] == src and c['destination'] == dst)
        assert cell['result'] == expected
        detail = client.get(f'/api/matrix/{src}/{dst}', params=params).json()
        path = client.get('/api/reachability', params={**params, 'src': src, 'dst': dst}).json()
        assert detail['result'] == path['result'] == expected
        window = client.get('/api/matrix', params={**params, 'source_ids': src, 'destination_ids': dst}).json()
        assert len(window['cells']) == 1 and window['cells'][0] == cell
        if family:
            assert cell['query'].startswith(f'IPv{family} / ')
            assert all((':' in address) == (family == 6) for r in cell['destination_ranges'] for address in r['addresses'])


def test_diff_family_reports_only_changed_communications(client):
    ids = snapshots(client)
    for family, expected in [(4, [('ALLOW', 'DENY')]), (6, [])]:
        response = client.get('/api/diff', params={**ids, 'protocol': 'tcp', 'port': 443, 'ip_version': family})
        assert response.status_code == 200
        data = response.json()
        assert data['ip_version'] == family and data['evaluation'] == 'path'
        rows = [r for r in data['communications'] if r['source'] == 'cisco-lab-vlan-10' and r['destination'] == 'cisco-lab-vlan-90']
        assert [(r['before_result'], r['after_result']) for r in rows] == expected
        # Configuration changes remain visible even under an IPv6 traffic filter.
        assert data['summary']['changed_rules'] == 1


@pytest.mark.parametrize('extra', [{'ip_version': 5}, {'ip_version': 'x'},
                                 {'ip_version': 6, 'protocol': 'icmp'},
                                 {'ip_version': 4, 'protocol': 'icmpv6'}])
def test_invalid_family_and_protocol_are_rejected_everywhere(client, extra):
    for endpoint in ('/api/matrix', '/api/matrix/a/b', '/api/diff'):
        assert client.get(endpoint, params=extra).status_code == 422


def test_family_only_is_explicit_transport_evaluation(client):
    ids = snapshots(client)
    params = {'snapshot_id': ids['after'], 'ip_version': 6}
    data = client.get('/api/matrix', params=params).json()
    assert data['evaluation'] == 'path' and data['ip_version'] == 6
    assert data['cells'][0]['query'] == 'IPv6 / TCP/ANY + UDP/ANY + SCTP/ANY'
    assert client.get('/api/diff', params={**ids, 'ip_version': 6}).json()['evaluation'] == 'path'
    # Omission retains the policy summary for backward compatibility.
    assert client.get('/api/matrix', params={'snapshot_id': ids['after']}).json()['evaluation'] == 'policy_summary'


def test_missing_family_cannot_be_same_segment_or_allow(client):
    ids = snapshots(client)
    params = {'snapshot_id': ids['before'], 'protocol': 'tcp', 'port': 443, 'ip_version': 6}
    for dst in ('cisco-lab-vlan-20', 'cisco-lab-vlan-90'):
        src = 'cisco-lab-vlan-20'  # IPv4 only
        matrix = client.get(f'/api/matrix/{src}/{dst}', params=params).json()
        path = client.get('/api/reachability', params={**params, 'src': src, 'dst': dst}).json()
        assert matrix['result'] == path['result'] == 'UNKNOWN'
        assert 'IP family' in matrix['reason']
