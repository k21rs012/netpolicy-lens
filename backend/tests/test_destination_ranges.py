import ipaddress
import pytest
from app import destination_ranges
from app.matrix_query import build_query_matrix
from app.models import NATRule, Route, RouteOption, Segment
from app.reachability import analyze_reachability
from test_ecmp import diamond
from test_flow_reachability import network_path, trace
from test_nat_pipeline import snat


def assert_cover(result, network):
    ranges = [ipaddress.ip_network(v) for p in result['paths'] for v in p['destination_ranges']]
    assert sum(n.num_addresses for n in ranges) == ipaddress.ip_network(network).num_addresses
    assert list(ipaddress.collapse_addresses(ranges)) == [ipaddress.ip_network(network)]
    assert all(not a.overlaps(b) for i, a in enumerate(ranges) for b in ranges[i + 1:])


@pytest.mark.parametrize('version,subnet', [(4, '10.0.9.128/25'), (6, '2001:db8:9:0:8000::/65')])
def test_downstream_split_replays_policy(version, subnet):
    configs = network_path(3, version)
    configs[1].routes.append(Route(device='r1', destination=subnet, route_type='blackhole'))
    result = trace(configs, ip_version=version)
    assert result['result'] == 'PARTIAL' and result['paths_complete']
    assert {p['result'] for p in result['paths']} == {'ALLOW', 'NO_ROUTE'}
    assert_cover(result, configs[-1].segments[-1].networks[0])
    for p in result['paths']:
        assert p['steps'][0]['flow']['current']['destination_addresses'] == p['destination_ranges']


def test_nested_routes_and_earlier_policy():
    configs = network_path(2)
    configs[0].routes += [Route(device='r0', destination='10.0.9.128/25', interface='eth1'), Route(device='r0', destination='10.0.9.192/26', route_type='blackhole')]
    configs[0].policies[0].dst = ['10.0.9.0/25']
    result = trace(configs)
    assert {p['result'] for p in result['paths']} == {'ALLOW', 'DENY', 'NO_ROUTE'}
    assert_cover(result, '10.0.9.0/24')


def test_same_outcomes_disabled_and_other_vrf():
    configs = network_path(2)
    configs[0].routes += [Route(device='r0', destination='10.0.9.128/25', interface='eth1'), Route(device='r0', destination='10.0.9.1/32', options=[RouteOption(disabled=True)]), Route(device='r0', destination='10.0.9.2/32', vrf='other')]
    result = trace(configs)
    assert result['result'] == 'ALLOW' and len(result['paths']) == 2
    assert_cover(result, '10.0.9.0/24')


def test_snat_preserves_partition():
    configs = network_path(2)
    snat(configs[0])
    configs[1].policies[0].src = ['203.0.113.10/32']
    configs[0].routes.append(Route(device='r0', destination='10.0.9.128/25', interface='eth1'))
    result = trace(configs)
    assert result['result'] == 'ALLOW'
    assert all(p['steps'][1]['packet_in']['source_addresses'] == ['203.0.113.10/32'] for p in result['paths'])


@pytest.mark.parametrize('version,public,private,half', [(4, '203.0.113.0/24', '10.0.9.0/24', '10.0.9.128/25'), (6, '2001:db8:a::/64', '2001:db8:9::/64', '2001:db8:9:0:8000::/65')])
def test_static_dnat_projects_split_back(version, public, private, half):
    configs = network_path(2, version)
    configs[0].segments.append(Segment(id='public', device='r0', name='public', type='interface', networks=[public]))
    configs[0].nat = [NATRule(device='r0', name='map', type='static', original_dst=public, translated_dst=private)]
    configs[1].routes.append(Route(device='r1', destination=half, route_type='blackhole'))
    result = analyze_reachability(configs, 'r0-in', 'public', 'tcp', 443, source_port=12345, ip_version=version)
    assert {p['result'] for p in result['paths']} == {'ALLOW', 'NO_ROUTE'}
    assert_cover(result, public)
    assert result['flow']['original']['destination_addresses'] == [public]
    for p in result['paths']:
        assert p['flow']['original']['destination_addresses'] == p['destination_ranges']
        assert p['steps'][0]['nat'][0]['applied']
        assert ipaddress.ip_network(p['flow']['current']['destination_addresses'][0]).subnet_of(ipaddress.ip_network(private))


def test_ecmp_matrix_all_branches():
    configs = diamond()
    configs[1].routes.append(Route(device='r1', destination='10.0.9.128/25', route_type='blackhole'))
    result = analyze_reachability(configs, 'r0-in', 'r3-out', 'tcp', 443)
    assert len(result['paths']) == 4 and result['result'] == 'PARTIAL'
    assert sum(p['result'] == 'ALLOW' for p in result['paths']) == 3
    cell = build_query_matrix(configs, 'tcp', 443, 'r0-in', 'r3-out')[0]
    assert cell.result == result['result']
    assert [(r['addresses'], r['result']) for r in cell.destination_ranges] == [(p['destination_ranges'], p['result']) for p in result['paths']]


@pytest.mark.parametrize('limit', ['MAX_REFINEMENTS', 'MAX_RANGE_PATHS'])
def test_limits_keep_remainder(monkeypatch, limit):
    monkeypatch.setattr(destination_ranges, limit, 1)
    configs = network_path(2)
    configs[0].routes.append(Route(device='r0', destination='10.0.9.128/25', route_type='blackhole'))
    result = trace(configs)
    assert result['result'] == 'PARTIAL' and not result['paths_complete']
    assert result['paths'][-1]['result'] == 'PARTIAL'
    assert '上限' in result['paths'][-1]['route_reason']
    assert_cover(result, '10.0.9.0/24')


def test_connected_boundary_and_multiple_destination_networks():
    configs = network_path(2)
    configs[0].segments.append(Segment(id='discard', device='r0', name='discard', type='interface', networks=['10.0.9.128/25']))
    configs[-1].segments[-1].networks = ['10.0.9.0/24', '10.0.9.128/25']
    result = trace(configs)
    assert len(result['paths']) == 2
    assert_cover(result, '10.0.9.0/24')
    assert any('segment:discard' in p['path'] for p in result['paths'])


def test_ipv6_host_boundary_does_not_enumerate_hosts():
    configs = network_path(2, 6)
    configs[0].routes.append(Route(device='r0', destination='2001:db8:9::abcd/128', route_type='blackhole'))
    result = trace(configs, ip_version=6)
    assert result['paths_complete']
    assert len(result['paths']) == 65
    assert_cover(result, '2001:db8:9::/64')


def test_ecmp_limit_marks_affected_range_partial(monkeypatch):
    from app import path_traversal
    monkeypatch.setattr(path_traversal, 'MAX_PATHS', 1)
    result = analyze_reachability(diamond(), 'r0-in', 'r3-out', 'tcp', 443)
    assert not result['paths_complete']
    assert result['paths'][-1]['result'] == 'PARTIAL'
    assert result['paths'][-1]['destination_ranges'] == ['10.0.9.0/24']
