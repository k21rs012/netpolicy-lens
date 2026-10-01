import pytest
from fastapi.testclient import TestClient

from app import main
from app.matrix_query import build_query_matrix
from app.models import CanonicalConfig, Device, Segment
from app.parsers import ParserRegistry
from app.storage import SnapshotStore
from app.topology import analyze_reachability
from tests.test_analyzer_semantics import config_with_policies, policy


def query(config, protocol='tcp', port=443):
    return next(c for c in build_query_matrix([config], protocol, port)
                if c.source == 'edge-user' and c.destination == 'edge-server')


@pytest.mark.parametrize('rules,port,expected,rule', [
    ([policy(10, 'permit', port='any')], 443, 'ALLOW', 10),
    ([policy(10, 'permit', port='400-500')], 443, 'ALLOW', 10),
    ([policy(10, 'permit', port='https')], 443, 'ALLOW', 10),
    ([policy(10, 'permit', port='8443')], 443, 'DENY', None),
    ([policy(10, 'deny', port='any'), policy(20, 'permit')], 443, 'DENY', 10),
    ([policy(10, 'permit', port='any'), policy(20, 'deny')], 443, 'ALLOW', 10),
    ([policy(10, 'permit'), policy(20, 'deny', port='any')], 443, 'ALLOW', 10),
    ([policy(10, 'permit'), policy(20, 'deny', port='any')], 80, 'DENY', 20),
    ([policy(10, 'permit', port='0')], 0, 'ALLOW', 10),
    ([policy(10, 'permit', port='gt 1023')], 8443, 'ALLOW', 10),
    ([policy(10, 'permit', port='lt 1024')], 8443, 'DENY', None),
    ([policy(10, 'permit', port='neq 443')], 443, 'DENY', None),
    ([policy(10, 'permit')], None, 'PARTIAL', 10),
    ([policy(10, 'permit', destination='10.0.2.10/32')], 443, 'PARTIAL', 10),
    ([policy(10, 'permit', destination='UNRESOLVED')], 443, 'PARTIAL', 10),
])
def test_query_matches_path_and_preserves_decisive_rule(rules, port, expected, rule):
    cfg = config_with_policies(*rules)
    cell = query(cfg, port=port)
    path = analyze_reachability([cfg], 'edge-user', 'edge-server', 'tcp', port)
    assert cell.result == expected == path['result']
    assert cell.policy_ids == ([f'edge:EDGE-IN:{rule}'] if rule else [])
    assert cell.traces[0]['result'] == expected
    assert cell.traces[0]['reason'] == path['steps'][0]['reason']
    assert cell.evaluation == 'path'
    if expected == 'PARTIAL':
        assert not cell.allowed and not cell.denied


def test_any_protocol_and_unresolved_source_port():
    any_rule = policy(10, 'permit', port='any').model_copy(update={'protocol': ['ip']})
    assert query(config_with_policies(any_rule), protocol='udp').result == 'ALLOW'
    source_port_rule = any_rule.model_copy(update={'src_ports': ['1024-65535']})
    assert query(config_with_policies(source_port_rule)).result == 'PARTIAL'


def test_port_only_aggregates_transports_without_overriding_deny():
    cfg = config_with_policies(policy(10, 'deny'), policy(20, 'permit', port='any').model_copy(update={'protocol': ['ip']}))
    cell = query(cfg, protocol=None)
    assert cell.result == 'PARTIAL'
    assert cell.denied == ['TCP/443']
    assert cell.allowed == ['UDP/443', 'SCTP/443']


def test_egress_deny_is_not_hidden_by_ingress_allow():
    egress = policy(20, 'deny').model_copy(update={'direction': 'out', 'interface': 'Vlan20', 'chain_id': 'out'})
    cell = query(config_with_policies(policy(10, 'permit'), egress))
    assert cell.result == 'DENY'
    assert {t['result'] for t in cell.traces} == {'ALLOW', 'DENY'}


def test_no_route_preserved_and_distinct_from_policy_deny():
    cfg = config_with_policies(policy(10, 'permit'))
    remote = CanonicalConfig(device=Device(id='remote', hostname='remote', vendor='vyos', network_os='vyos', source_file='test'),
                            segments=[Segment(id='remote-net', name='REMOTE', type='interface', device='remote', networks=['203.0.113.0/24'])])
    cell = build_query_matrix([cfg, remote], 'tcp', 443, 'edge-user', 'remote-net')[0]
    assert cell.result == 'NO_ROUTE'
    assert cell.allowed == cell.denied == []
    assert 'NO_ROUTE' in cell.reason


VYOS = '''set system host-name edge
set interfaces ethernet eth0 address 10.0.1.1/24
set interfaces ethernet eth1 address 10.0.2.1/24
set firewall ipv4 forward filter default-action drop
set firewall ipv4 forward filter rule 10 action jump
set firewall ipv4 forward filter rule 10 jump-target WEB
set firewall ipv4 name WEB rule 10 action accept
set firewall ipv4 name WEB rule 10 protocol tcp
set firewall ipv4 name WEB rule 10 destination port 443
set firewall ipv4 input filter default-action drop
'''


def test_jump_local_and_nat_use_shared_evaluator():
    raw = VYOS + '''set nat destination rule 1 destination address 10.0.2.0/24
set nat destination rule 1 translation address 10.0.2.20
set nat destination rule 1 translation port 443
'''
    cfg = ParserRegistry.parse(raw, 'test.set', parser_id='vyos')[0]
    cell = build_query_matrix([cfg], 'tcp', 8443, 'edge-if-eth0', 'edge-if-eth1')[0]
    assert cell.result == 'ALLOW'
    assert cell.allowed == ['TCP/8443']  # Query is before NAT.
    assert cell.traces[0]['policy'] == 'WEB'
    local = build_query_matrix([cfg], 'tcp', 22, 'edge-if-eth0', 'edge-local')[0]
    assert local.result == 'PARTIAL'  # DNAT covers only part of the local address set.
    plain = ParserRegistry.parse(VYOS, 'test.set', parser_id='vyos')[0]
    assert build_query_matrix([plain], 'tcp', 22, 'edge-if-eth0', 'edge-local')[0].result == 'DENY'


def test_dual_family_uncertainty_is_not_replaced_with_allow():
    cfg = config_with_policies(policy(10, 'permit', port='any'))
    cfg.segments[0].networks.append('2001:db8:1::/64')
    cfg.segments[1].networks.append('2001:db8:2::/64')
    cell = query(cfg)
    assert cell.result == 'UNKNOWN'
    assert 'IP family' in cell.reason


@pytest.fixture
def client(tmp_path, monkeypatch):
    store = SnapshotStore(str(tmp_path / 'matrix.db'))
    cfg = config_with_policies(policy(10, 'permit', port='400-500'))
    store.create('matrix', [('test.conf', 'synthetic fixture', cfg)])
    monkeypatch.setattr(main, 'store', store)
    return TestClient(main.app)


def test_api_cell_detail_and_path_have_identical_conditions(client):
    params = {'protocol': 'TCP', 'port': 443}
    response = client.get('/api/matrix', params=params)
    assert response.status_code == 200
    data = response.json()
    assert data['evaluation'] == 'path'
    cell = next(c for c in data['cells'] if c['source'] == 'edge-user' and c['destination'] == 'edge-server')
    assert cell['result'] == 'ALLOW'
    assert client.get('/api/matrix/edge-user/edge-server', params=params).json() == cell
    assert client.get('/api/matrix').json()['evaluation'] == 'policy_summary'
    assert client.get('/api/matrix/missing/edge-server', params=params).status_code == 404
    path = client.get('/api/reachability', params={'src': 'edge-user', 'dst': 'edge-server', 'protocol': 'tcp', 'port': 443}).json()
    assert cell['result'] == path['result']


@pytest.mark.parametrize('params', [
    {'port': -1}, {'port': 65536}, {'port': 'abc'}, {'port': '1.5'},
    {'protocol': 'typo'}, {'protocol': 'icmp', 'port': 80},
])
def test_invalid_query_is_rejected_for_list_and_detail(client, params):
    assert client.get('/api/matrix', params=params).status_code == 422
    assert client.get('/api/matrix/edge-user/edge-server', params=params).status_code == 422
