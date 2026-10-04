import ipaddress
import pytest
from app.diff import compare_snapshots
from app.models import AddressObject, NATRule, Segment
from app.reachability import analyze_reachability
from test_destination_ranges import assert_cover
from test_flow_reachability import network_path, trace
from test_nat_pipeline import snat


@pytest.mark.parametrize('version,half', [(4, '10.0.9.0/25'), (6, '2001:db8:9::/65')])
@pytest.mark.parametrize('negate', [False, True])
def test_policy_object_boundary_and_negation(version, half, negate):
    configs = network_path(3, version)
    cfg = configs[1]
    cfg.address_objects = [AddressObject(device='r1', name='outer', values=['inner']), AddressObject(device='r1', name='inner', values=[half])]
    cfg.policies[0].dst = ['outer']
    cfg.policies[0].dst_negate = negate
    result = trace(configs, ip_version=version)
    assert result['result'] == 'PARTIAL' and result['paths_complete']
    assert {p['result'] for p in result['paths']} == {'ALLOW', 'DENY'}
    assert result['paths'][0]['result'] == ('DENY' if negate else 'ALLOW')
    assert_cover(result, configs[-1].segments[-1].networks[0])
    for path in result['paths']:
        assert path['steps'][0]['packet_in']['destination_addresses'] == path['destination_ranges']


def test_rule_order_does_not_split_shadowed_or_unrelated_conditions():
    configs = network_path(2)
    first = configs[0].policies[0]
    configs[0].policies.append(first.model_copy(update={'id': 'shadowed', 'sequence': 20, 'dst': ['10.0.9.1/32'], 'action': 'deny'}))
    assert len(trace(configs)['paths']) == 1
    first.dst = ['10.0.9.0/25']
    result = trace(configs)
    assert {p['result'] for p in result['paths']} == {'ALLOW', 'DENY'}
    assert len(result['paths']) == 2


def test_ip_range_and_unknown_source_remain_conservative():
    configs = network_path(2)
    configs[0].policies[0].dst = ['10.0.9.10-10.0.9.20']
    result = trace(configs)
    assert_cover(result, '10.0.9.0/24')
    allowed = [ipaddress.ip_network(v) for p in result['paths'] if p['result'] == 'ALLOW' for v in p['destination_ranges']]
    assert sum(n.num_addresses for n in allowed) == 11
    configs[0].policies[0].src = ['missing-object']
    uncertain = trace(configs)
    assert 'ALLOW' not in {p['result'] for p in uncertain['paths']}


@pytest.mark.parametrize('version,public,private,half', [(4, '203.0.113.0/24', '10.0.9.0/24', '10.0.9.0/25'), (6, '2001:db8:a::/64', '2001:db8:9::/64', '2001:db8:9::/65')])
def test_post_dnat_policy_projects_to_original_destination(version, public, private, half):
    configs = network_path(2, version)
    configs[0].segments.append(Segment(id='public', device='r0', name='public', type='interface', networks=[public]))
    configs[0].nat = [NATRule(device='r0', name='map', type='static', original_dst=public, translated_dst=private)]
    configs[1].policies[0].dst = [half]
    result = analyze_reachability(configs, 'r0-in', 'public', 'tcp', 443, source_port=12345, ip_version=version)
    assert {p['result'] for p in result['paths']} == {'ALLOW', 'DENY'}
    assert_cover(result, public)
    assert all(p['steps'][0]['nat'][0]['applied'] for p in result['paths'])


def test_partial_dnat_and_exclusion_keep_untranslated_branch():
    configs = network_path(2)
    configs[0].nat = [NATRule(device='r0', name='exclude', type='exclude', stage='destination', original_dst='10.0.9.0/25', sequence=1),
                      NATRule(device='r0', name='map', type='destination', original_dst='10.0.9.0/24', translated_dst='10.0.9.20', sequence=2)]
    result = trace(configs)
    assert result['result'] == 'ALLOW' and len(result['paths']) == 2
    assert_cover(result, '10.0.9.0/24')
    assert {p['steps'][0]['nat'][0]['name'] for p in result['paths']} == {'exclude', 'map'}
    assert result['paths'][1]['flow']['current']['destination_addresses'] == ['10.0.9.20/32']


def test_destination_condition_on_snat_splits_downstream_source_policy():
    configs = network_path(2)
    snat(configs[0], original_dst='10.0.9.0/25')
    configs[1].policies[0].src = ['203.0.113.10/32']
    result = trace(configs)
    assert [p['result'] for p in result['paths']] == ['ALLOW', 'DENY']
    assert_cover(result, '10.0.9.0/24')


def test_diff_detects_changed_ranges_when_both_totals_are_partial():
    before = network_path(2)
    for cfg in before:
        cfg.policies[0].src_ports = ['any']
    before[0].policies[0].dst = ['10.0.9.0/25']
    after = [cfg.model_copy(deep=True) for cfg in before]
    after[0].policies[0].dst_negate = True
    diff = compare_snapshots(before, after, 'tcp', 443)
    row = next(r for r in diff['communications'] if r['source'] == 'r0-in' and r['destination'] == 'r1-out')
    assert row['before_result'] == row['after_result'] == 'PARTIAL'
    assert row['before_ranges'] != row['after_ranges']
    assert row['new_allow'] == row['new_deny'] == []


def test_ecmp_policy_split_replays_every_branch():
    from test_ecmp import diamond
    configs = diamond()
    configs[1].policies[0].dst = ['10.0.9.0/25']
    result = analyze_reachability(configs, 'r0-in', 'r3-out', 'tcp', 443)
    assert result['result'] == 'PARTIAL' and result['paths_complete']
    assert len(result['paths']) == 4
    assert [p['result'] for p in result['paths']].count('ALLOW') == 3


def test_policy_limit_keeps_unexamined_addresses(monkeypatch):
    from app import destination_ranges
    monkeypatch.setattr(destination_ranges, 'MAX_REFINEMENTS', 1)
    configs = network_path(2)
    configs[0].policies[0].dst = ['10.0.9.0/25']
    result = trace(configs)
    assert not result['paths_complete'] and result['result'] == 'PARTIAL'
    assert_cover(result, '10.0.9.0/24')


def test_disjoint_vips_are_split_before_overlap_check():
    configs = network_path(2)
    cfg = configs[0]
    cfg.device.network_os = 'fortios'
    cfg.nat = [NATRule(device='r0', name=f'vip-{index}', type='destination', fortios_kind='vip',
                       original_dst=f'10.0.9.{index}', translated_dst='10.0.9.20') for index in (10, 11)]
    result = trace(configs)
    for host in (10, 11):
        path = next(p for p in result['paths'] if p['destination_ranges'] == [f'10.0.9.{host}/32'])
        assert path['steps'][0]['nat'][0]['applied']
    cfg.nat[1].original_dst = '10.0.9.10'
    overlapping = trace(configs, destination_ip='10.0.9.10')
    assert overlapping['result'] == 'PARTIAL'
    assert '重複' in overlapping['route_reason']


def test_range_signature_ignores_equivalent_partition_shape():
    from app.diff import _range_signature
    from app.models import MatrixCell
    def cell(networks):
        return MatrixCell(source='a', destination='b', result='ALLOW', destination_ranges=[
            {'addresses': networks, 'result': 'ALLOW', 'protocol': 'tcp'}])
    assert _range_signature(cell(['10.0.9.0/24'])) == _range_signature(cell(['10.0.9.0/25', '10.0.9.128/25']))


def test_jump_target_boundary_preserves_return_and_rule_order():
    configs = network_path(2)
    cfg = configs[0]
    base = cfg.policies[0]
    base.chain_id = 'base'
    base.action = 'jump'
    base.jump_target = 'child'
    returned = base.model_copy(update={'id': 'after-return', 'sequence': 20, 'action': 'deny', 'jump_target': None})
    child = base.model_copy(update={'id': 'child-permit', 'chain_id': 'child', 'entrypoint': False, 'action': 'permit',
                                  'jump_target': None, 'dst': ['10.0.9.0/25'], 'default_action': 'return'})
    cfg.policies = [base, returned, child]
    result = trace(configs)
    assert [p['result'] for p in result['paths']] == ['ALLOW', 'DENY']
    assert result['paths'][1]['steps'][0]['policy'] == 'after-return'
