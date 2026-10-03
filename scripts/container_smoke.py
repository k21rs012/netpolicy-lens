"""Exercise a dedicated test deployment through its nginx URL (stdlib only).

Writes a synthetic snapshot unless --verify-existing is supplied. Do not run
against a user deployment: the new snapshot becomes its latest snapshot.
"""
import argparse
import json
import time
from urllib.error import HTTPError, URLError
from pathlib import Path
from urllib.request import Request, urlopen

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('url', help='URL of the isolated test deployment')
parser.add_argument('--verify-existing', action='store_true')
args = parser.parse_args()
base = args.url.rstrip('/')


def get(path):
    with urlopen(base + path, timeout=30) as response:
        return json.load(response)


for attempt in range(30):
    try:
        assert get('/api/health')['status'] == 'ok'
        break
    except URLError:
        if attempt == 29:
            raise
        time.sleep(0.5)
with urlopen(base + '/', timeout=30) as response:
    assert b'<html' in response.read()
if not args.verify_existing:
    fixture = Path(__file__).resolve().parents[1] / 'frontend/integration/fixtures/audit.conf'
    # Above nginx's default 1 MiB, within the backend's 20 MiB file limit.
    raw = fixture.read_bytes() + b'\n! ' + b'x' * (1024 * 1024)
    boundary = 'NetPolicySyntheticSmokeBoundary'
    body = (f'--{boundary}\r\nContent-Disposition: form-data; name="files"; filename="audit.conf"\r\n'
            'Content-Type: text/plain\r\n\r\n').encode() + raw + f'\r\n--{boundary}--\r\n'.encode()
    request = Request(base + '/api/configs/import', data=body,
                      headers={'Content-Type': f'multipart/form-data; boundary={boundary}'})
    with urlopen(request, timeout=30) as response:
        assert len(json.load(response)['imported']) == 1
    oversized = body.replace(raw, b"x" * (20 * 1024 * 1024 + 1))
    request = Request(base + '/api/configs/preview', data=oversized,
                      headers={'Content-Type': f'multipart/form-data; boundary={boundary}'})
    try:
        urlopen(request, timeout=30)
    except HTTPError as error:
        assert error.code == 413 and b'upload limit' in error.read()
    else:
        raise AssertionError('The API accepted a file above its 20 MiB limit')
snapshots = get('/api/snapshots')
assert snapshots and snapshots[0]['device_count'] == 1
cell = get('/api/matrix/audit-vlan-10/audit-vlan-20?protocol=tcp&port=443')
path = get('/api/reachability?src=audit-vlan-10&dst=audit-vlan-20&protocol=tcp&port=443')
assert cell['result'] == path['result'] == 'ALLOW'
assert 'synthetic-test-community' not in json.dumps(get('/api/parser/debug'))
print('PASS: UI, health, >1 MiB import/persistence, Matrix, Path, masked export')
