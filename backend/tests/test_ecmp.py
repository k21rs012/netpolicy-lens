import pytest
from fastapi.testclient import TestClient

from app import main, path_traversal
from app.matrix_query import build_query_matrix
from app.models import CanonicalConfig, Device, Interface, NATRule, Policy, Route, Segment
from app.parsers import ParserRegistry
from app.reachability import analyze_reachability
from app.routing import route_candidates
from app.storage import SnapshotStore


def diamond():
    configs = []
    links = [
        [('in', '10.0.1.1/24'), ('out', '192.0.2.1/24')],
        [('in', '192.0.2.2/24'), ('out', '198.51.100.1/30')],
        [('in', '192.0.2.3/24'), ('out', '198.51.100.5/30')],
        [('in', '198.51.100.2/30'), ('in2', '198.51.100.6/30'), ('out', '10.0.9.1/24')],
    ]
    import ipaddress
    for i, ports in enumerate(links):
        name = f'r{i}'
        segments = [Segment(id=f'{name}-{side}', device=name, name=side, type='zone',
                            networks=[str(ipaddress.ip_interface(ip).network)]) for side, ip in ports]
        interfaces = [Interface(device=name, name=side, segment_id=f'{name}-{side}', addresses=[ip],
                                zone='outside' if side == 'out' else 'inside') for side, ip in ports]
        policy = Policy(id=f'{name}-allow', device=name, name='forward', sequence=10, direction='zone',
                        from_zone='inside', to_zone='outside', src_segments=[s.id for s in segments if s.name != 'out'],
                        dst_segments=[f'{name}-out'], src=['any'], dst=['any'], action='permit',
                        protocol=['tcp'], dst_ports=['443'], default_action='deny')
        configs.append(CanonicalConfig(device=Device(id=name, hostname=name, vendor='vyos', network_os='vyos', source_file=name),
                                       segments=segments, interfaces=interfaces, policies=[policy]))
    configs[0].routes = [Route(device='r0', destination='10.0.9.0/24', next_hops=['192.0.2.2', '192.0.2.3'])]
    configs[1].routes = [Route(device='r1', destination='10.0.9.0/24', next_hop='198.51.100.2')]
    configs[2].routes = [Route(device='r2', destination='10.0.9.0/24', next_hop='198.51.100.6')]
    return configs


def trace(configs):
    return analyze_reachability(configs, 'r0-in', 'r3-out', 'tcp', 443,
                                source_ip='10.0.1.10', destination_ip='10.0.9.20')


def test_same_interface_gateways_and_converging_paths_are_distinct():
    result = trace(diamond())
    assert result['result'] == 'ALLOW'
    assert result['paths_complete']
    assert len(result['paths']) == 2
    assert {p['steps'][0]['next_hop'] for p in result['paths']} == {'192.0.2.2', '192.0.2.3'}
    assert [[s['device'] for s in p['steps']] for p in result['paths']] == [['r0', 'r1', 'r3'], ['r0', 'r2', 'r3']]


@pytest.mark.parametrize('left,right,expected', [('deny', 'deny', 'DENY'), ('permit', 'deny', 'PARTIAL')])
def test_policy_outcomes_are_aggregated(left, right, expected):
    configs = diamond()
    configs[1].policies[0].action, configs[2].policies[0].action = left, right
    result = trace(configs)
    assert result['result'] == expected
    assert len(result['paths']) == 2
    denied = [p for p in result['paths'] if p['result'] == 'DENY']
    assert all(len(p['steps']) == 2 for p in denied)
    cell = build_query_matrix(configs, 'tcp', 443, 'r0-in', 'r3-out')[0]
    assert cell.result == expected
    assert {t['path_index'] for t in cell.traces} == {1, 2}
    assert cell.allowed == []


@pytest.mark.parametrize('kind', ['blackhole', 'missing', 'loop', 'dynamic', 'pbr'])
def test_broken_alternative_cannot_be_hidden_by_allow(kind):
    configs = diamond()
    if kind == 'blackhole':
        configs[2].routes[0].route_type = 'blackhole'
    elif kind == 'missing':
        configs[0].routes[0].next_hops[1] = '192.0.2.99'
    elif kind == 'loop':
        configs[2].routes[0].next_hop = '192.0.2.1'
    elif kind == 'dynamic':
        configs[2].routes = []
        configs[2].device.features['dynamic_routing'] = True
    else:
        configs[2].interfaces[0].policy_route_map = 'PBR'
    result = trace(configs)
    assert result['result'] == 'PARTIAL'
    assert {p['result'] for p in result['paths']} == {'ALLOW', 'NO_ROUTE' if kind == 'blackhole' else 'UNKNOWN'}


def test_backup_route_is_excluded_and_more_specific_wins():
    configs = diamond()
    configs[0].routes = [Route(device='r0', destination='10.0.9.0/24', next_hop=hop, metric=metric)
                         for hop, metric in [('192.0.2.2', 10), ('192.0.2.3', 20)]]
    configs[2].policies[0].action = 'deny'
    assert trace(configs)['result'] == 'ALLOW'
    assert len(trace(configs)['paths']) == 1
    configs[0].routes.append(Route(device='r0', destination='10.0.9.20/32', next_hop='192.0.2.3', metric=100))
    assert trace(configs)['result'] == 'DENY'


def test_recursive_ecmp_and_vrf_isolation():
    configs = diamond()
    configs[0].routes = [Route(device='r0', destination='10.0.9.0/24', next_hop='203.0.113.1'),
                         Route(device='r0', destination='203.0.113.1/32', next_hops=['192.0.2.2', '192.0.2.3'])]
    for cfg in configs:
        for item in [*cfg.segments, *cfg.interfaces, *cfg.routes]:
            item.vrf = 'blue'
    configs[0].routes.append(Route(device='r0', destination='10.0.9.20/32', vrf='red', route_type='blackhole'))
    result = trace(configs)
    assert result['result'] == 'ALLOW'
    assert len(result['paths']) == 2
    configs[0].routes[1].next_hops = ['203.0.113.1']
    assert trace(configs)['result'] == 'UNKNOWN'


@pytest.mark.parametrize('limit', ['MAX_PATHS', 'MAX_STATES', 'MAX_HOPS'])
def test_exploration_limits_never_claim_all_allow(monkeypatch, limit):
    monkeypatch.setattr(path_traversal, limit, 1)
    result = trace(diamond())
    assert result['result'] == 'PARTIAL'
    assert not result['paths_complete']
    assert '上限' in result['route_reason']


def test_nat_state_is_separate_on_each_branch():
    configs = diamond()
    for index, address in [(1, '203.0.113.10'), (2, '203.0.113.20')]:
        configs[index].nat = [NATRule(device=f'r{index}', name='SNAT', type='source', original_src='10.0.1.0/24',
                                     translated_src=address, out_interfaces=['out'])]
    configs[3].policies[0].src = ['203.0.113.10/32']
    result = trace(configs)
    assert result['result'] == 'PARTIAL'
    assert {p['flow']['current']['source_addresses'][0] for p in result['paths']} == {'203.0.113.10/32', '203.0.113.20/32'}
    assert {p['result'] for p in result['paths']} == {'ALLOW', 'DENY'}
    assert all(p['steps'][0]['packet_out']['source_addresses'] == ['10.0.1.10/32'] for p in result['paths'])


@pytest.mark.parametrize('vrf,version', [('', 4), ('vrf name blue ', 4), ('', 6), ('vrf name blue ', 6)])
def test_vyos_per_gateway_distance_and_disable(vrf, version):
    prefix, hops = ('10.0.9.0/24', ['192.0.2.2', '192.0.2.3', '192.0.2.4']) if version == 4 else ('2001:db8:9::/64', ['2001:db8:2::2', '2001:db8:2::3', '2001:db8:2::4'])
    suffix = '6' if version == 6 else ''
    raw = 'set system host-name edge\n' + '\n'.join(f'set {vrf}protocols static route{suffix} {prefix} next-hop {hop} {option}'
          for hop, option in [(hops[0], 'distance 10'), (hops[1], 'distance 20'), (hops[2], 'disable')])
    cfg = ParserRegistry.parse(raw, 'ecmp.set', parser_id='vyos')[0]
    options = cfg.routes[0].options
    assert [o.metric for o in options] == [10, 20, None]
    assert options[-1].disabled
    network = '192.0.2.0/24' if version == 4 else '2001:db8:2::/64'
    ingress = Segment(id='wan', name='wan', device='edge', type='interface', networks=[network], vrf='blue' if vrf else None)
    cfg.segments = [ingress]
    target = ingress.model_copy(update={'networks': [prefix]})
    assert [c.next_hop for c in route_candidates(cfg, target, ingress, version)] == [hops[0]]
    options[0].metric = 255
    assert [c.next_hop for c in route_candidates(cfg, target, ingress, version)] == [hops[1]]


def test_api_serializes_all_paths(tmp_path, monkeypatch):
    store = SnapshotStore(str(tmp_path / 'ecmp.db'))
    monkeypatch.setattr(main, 'store', store)
    configs = diamond()
    snapshot = store.create('ecmp', [(c.device.source_file, '', c) for c in configs])
    response = TestClient(main.app).get('/api/reachability', params={
        'snapshot_id': snapshot, 'src': 'r0-in', 'dst': 'r3-out', 'protocol': 'tcp', 'port': 443,
    })
    assert response.status_code == 200
    assert response.json()['result'] == 'ALLOW'
    assert len(response.json()['paths']) == 2


def test_ipv6_scoped_ecmp_paths():
    import ipaddress
    base = int(ipaddress.ip_address('2001:db8::'))

    def address(raw):
        return str(ipaddress.ip_address(base + int(ipaddress.ip_address(raw))))

    def network(raw):
        ip, prefix = raw.split('/')
        return f'{address(ip)}/{int(prefix) + 96}'

    configs = diamond()
    for cfg in configs:
        for segment in cfg.segments:
            segment.networks = [network(raw) for raw in segment.networks]
        for interface in cfg.interfaces:
            interface.addresses = [network(raw) for raw in interface.addresses]
        for route in cfg.routes:
            route.destination = network(route.destination)
            route.next_hop = address(route.next_hop) if route.next_hop else None
            route.next_hops = [address(hop) + '%out' for hop in route.next_hops]
    result = analyze_reachability(configs, 'r0-in', 'r3-out', 'tcp', 443, ip_version=6,
                                  source_ip=address('10.0.1.10'), destination_ip=address('10.0.9.20'))
    assert result['result'] == 'ALLOW'
    assert len(result['paths']) == 2
    assert all(p['flow']['current']['ip_version'] == 6 for p in result['paths'])


def test_destination_on_neighbor_segment_stops_before_another_forward_hook():
    configs = diamond()
    result = analyze_reachability(configs, 'r0-in', 'r1-in', 'tcp', 443, destination_ip='192.0.2.100')
    # Traffic ends on the shared destination LAN, not behind r1's firewall.
    assert result['result'] == 'ALLOW'
    assert any(p['path'][-1] == 'segment:r1-in' and len(p['steps']) == 1 for p in result['paths'])


def test_all_terminal_routes_and_disabled_interface_options():
    configs = diamond()
    for cfg in configs[1:3]:
        cfg.routes[0].route_type = 'blackhole'
    assert trace(configs)['result'] == 'NO_ROUTE'
    raw = '''set system host-name edge
set protocols static route 10.0.9.0/24 interface out distance 10
set protocols static route 10.0.9.0/24 interface backup distance 10
set protocols static route 10.0.9.0/24 interface backup disable
set protocols static route 10.0.9.0/24 blackhole distance 200
'''
    cfg = ParserRegistry.parse(raw, 'interfaces.set', parser_id='vyos')[0]
    cfg.segments = configs[0].segments
    cfg.interfaces = configs[0].interfaces
    candidates = route_candidates(cfg, configs[-1].segments[-1], configs[0].segments[0], 4)
    assert len(candidates) == 1 and candidates[0].egress == 'r0-out'


def test_dnat_branch_destinations_remain_independent():
    configs = diamond()
    configs[0].segments.append(Segment(id='vip', name='VIP', type='logical', device='r0', networks=['203.0.113.0/24']))
    configs[0].routes[0].destination = '203.0.113.10/32'
    for index, host in [(1, '10.0.9.20'), (2, '10.0.9.30')]:
        configs[index].nat = [NATRule(device=f'r{index}', name='DNAT', type='destination', original_dst='203.0.113.10', translated_dst=host)]
    result = analyze_reachability(configs, 'r0-in', 'vip', 'tcp', 443, source_ip='10.0.1.10', destination_ip='203.0.113.10')
    # The more-specific static VIP route wins over its connected subnet.
    assert result['result'] == 'ALLOW'
    assert len(result['paths']) == 2
    assert {p['flow']['current']['destination_addresses'][0] for p in result['paths']} == {'10.0.9.20/32', '10.0.9.30/32'}


@pytest.mark.parametrize('os,default', [('ios-xe', 1), ('fortios', 10)])
def test_implicit_and_explicit_default_distance_are_equal(os, default):
    configs = diamond()
    configs[0].device.network_os = os
    configs[0].routes = [Route(device='r0', destination='10.0.9.0/24', next_hop='192.0.2.2'),
                         Route(device='r0', destination='10.0.9.0/24', next_hop='192.0.2.3', metric=default)]
    assert len(trace(configs)['paths']) == 2
