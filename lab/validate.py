"""Run the authored acceptance contract against HTTP APIs and an isolated DB."""
from __future__ import annotations

import argparse
import hashlib
import io
import json
import os
import shutil
from pathlib import Path
import sys
import tempfile
import zipfile

ROOT = Path(__file__).resolve().parents[1]
SCENARIOS = ROOT / 'lab/scenarios'


def checked(response):
    assert response.status_code < 300, (response.status_code, response.text[:300])
    return response.json()


def validate_scenario(client, directory: Path):
    contract = json.loads((directory / 'expected.json').read_text())
    saved = {}
    outcomes = []
    for version in ('before', 'after'):
        files = sorted((directory / version).iterdir())
        archive = io.BytesIO()
        with zipfile.ZipFile(archive, 'w') as bundle:
            for file in files:
                bundle.writestr(file.name, file.read_bytes())
        uploads = [('files', (f'{directory.name}.zip', archive.getvalue(), 'application/zip'))]
        preview = checked(client.post('/api/configs/preview', files=uploads))
        assert all(item['detected'] and item['detected']['confidence'] >= .5 for item in preview['items']), preview
        imported = checked(client.post('/api/configs/import', files=uploads, data={'snapshot_name': f'{directory.name}-{version}'}))
        assert not imported['errors'], imported['errors']
        snapshot = imported['snapshot_id']
        saved[version] = snapshot
        devices = checked(client.get('/api/devices', params={'snapshot_id': snapshot}))['items']
        assert {d['id'] for d in devices} == set(contract['inventory'])
        for device in devices:
            for key, expected in contract['inventory'][device['id']].items():
                assert device['counts'][key] == expected, (device['id'], key, device['counts'][key], expected)
        for endpoint in ('/api/topology', '/api/policies', '/api/parser/debug', '/api/parser/warnings'):
            data = checked(client.get(endpoint, params={'snapshot_id': snapshot}))
            if contract['name'] == 'unsupported' and endpoint == '/api/parser/warnings':
                flag_warnings = [item for item in data['items'] if 'tcp flags' in item['config']]
                assert bool(flag_warnings) == (version == 'before'), (version, data)
        version_paths = []
        for case in contract['cases']:
            expected = case['expected' if version == 'before' else 'after']
            path = checked(client.get('/api/reachability', params={'snapshot_id': snapshot, **case['query']}))
            assert path['result'] == expected, (directory.name, version, case['name'], path['result'], expected)
            if case.get('path_count'):
                assert len(path['paths']) == case['path_count']
            if version == 'after' and case.get('after_verdicts'):
                assert sorted(p['result'] for p in path['paths']) == case['after_verdicts']
            if expected == 'ALLOW' and case.get('translated_ip'):
                assert path['flow']['current']['destination_addresses'] == [case['translated_ip']]
                assert path['flow']['current']['destination_port'] == case['translated_port']
            q = case['query']
            matrix = checked(client.get(f'/api/matrix/{q["src"]}/{q["dst"]}', params={'snapshot_id': snapshot, 'protocol': q['protocol'], 'port': q['port']}))
            matrix_expected = case.get('matrix_expected' if version == 'before' else 'matrix_after', expected)
            assert matrix['result'] == matrix_expected, (directory.name, version, case['name'], 'matrix', matrix['result'], matrix_expected)
            version_paths.append(path)
            outcomes.append({'version': version, 'case': case['name'], 'expected': expected, 'path': path['result'], 'matrix': matrix['result']})
        backup = client.get(f'/api/snapshots/{snapshot}/backup')
        assert backup.status_code == 200, backup.text[:300]
        payload = [('file', ('snapshot.json', backup.content, 'application/json'))]
        checked(client.post('/api/snapshots/restore/preview', files=payload))
        restored = checked(client.post('/api/snapshots/restore', files=payload))
        assert restored['id'] != snapshot
        for case, old in zip(contract['cases'], version_paths):
            new = checked(client.get('/api/reachability', params={'snapshot_id': restored['id'], **case['query']}))
            assert new['result'] == old['result'] and new['paths'] == old['paths']
    changed = [c for c in contract['cases'] if c['expected'] != c['after']]
    assert changed
    for case in changed:
        q = case['query']
        diff = checked(client.get('/api/diff', params={**saved, 'protocol': q['protocol'], 'port': q['port']}))
        if case.get('matrix_expected', case['expected']) == case.get('matrix_after', case['after']):
            assert diff['policies'], (directory.name, 'missing policy diff', case['name'])
            continue
        assert any(row['source'] == q['src'] and row['destination'] == q['dst'] for row in diff['communications']), (directory.name, 'missing diff', case['name'])
    return {'scenario': directory.name, 'status': 'passed', 'checks': outcomes}


def validate_native(client, directory: Path):
    """Compare actual CHR exports and packet observations to the authored contract."""
    native = json.loads((directory / 'native.json').read_text())
    assert native['status'] == 'passed'
    for version in ('before', 'after'):
        assert hashlib.sha256((directory / f'routeros-{version}.rsc').read_bytes()).hexdigest() == native['export_sha256'][version]
    assert hashlib.sha256((SCENARIOS / 'routeros/before/routeros.rsc').read_bytes()).hexdigest() == native['fixture_sha256']
    with tempfile.TemporaryDirectory(prefix='netpolicy-export-') as folder:
        scenario = Path(folder) / 'routeros-export'
        scenario.mkdir()
        shutil.copyfile(SCENARIOS / 'routeros/expected.json', scenario / 'expected.json')
        for version in ('before', 'after'):
            (scenario / version).mkdir()
            shutil.copyfile(directory / f'routeros-{version}.rsc', scenario / version / 'routeros.rsc')
        result = validate_scenario(client, scenario)
    observations = {item['case']: item for item in native['checks']}
    expected_names = {'office-https', 'office-ssh', 'guest-isolation', 'dnat', 'after-office-https', 'after-dnat'}
    assert set(observations) == expected_names
    for item in result['checks']:
        name = ('after-' if item['version'] == 'after' else '') + item['case']
        if name in observations:
            assert observations[name]['result'] == item['path'], (name, observations[name], item)
    return {**result, 'native_version': native['version'], 'native_checks': len(observations)}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--report', type=Path)
    parser.add_argument('--native-results', type=Path, help='Directory containing CHR exports and native.json')
    args = parser.parse_args()
    sys.path.insert(0, str(ROOT / 'backend'))
    with tempfile.TemporaryDirectory(prefix='netpolicy-acceptance-') as folder:
        os.environ['DATABASE_PATH'] = str(Path(folder) / 'lab.db')
        from fastapi.testclient import TestClient
        from app.main import app
        client = TestClient(app)
        results = []
        for directory in sorted(SCENARIOS.iterdir()):
            try:
                results.append(validate_scenario(client, directory))
                print(f'{directory.name}: passed', flush=True)
            except AssertionError as exc:
                results.append({'scenario': directory.name, 'status': 'failed', 'error': str(exc)})
                print(f'{directory.name}: FAILED {exc}', flush=True)
        if args.native_results:
            results.append(validate_native(client, args.native_results))
            print('routeros-export: passed (native packet results agree)', flush=True)
        if args.report:
            args.report.parent.mkdir(parents=True, exist_ok=True)
            args.report.write_text(json.dumps(results, ensure_ascii=False, indent=2) + '\n')
        return int(any(row['status'] != 'passed' for row in results))


if __name__ == '__main__':
    raise SystemExit(main())
