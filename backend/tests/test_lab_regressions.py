from pathlib import Path

import pytest
from app.diff import compare_snapshots
from app.parsers import ParserRegistry
from app.reachability import analyze_reachability

SCENARIOS = Path(__file__).resolve().parents[2] / 'lab/scenarios'


def parse(scenario, version='before'):
    file = next((SCENARIOS / scenario / version).iterdir())
    return ParserRegistry.parse(file.read_text(), file.name)[0]


def test_dual_stack_acl_keeps_each_family_separate():
    config = parse('cisco', 'after')
    assert {p.ip_version for p in config.policies if p.name == 'OFFICE'} == {4}
    assert {p.ip_version for p in config.policies if p.name == 'OFFICE6'} == {6}
    for version, expected in ((4, 'DENY'), (6, 'ALLOW')):
        result = analyze_reachability([config], 'cisco-lab-vlan-10', 'cisco-lab-vlan-90', 'tcp', 443, ip_version=version)
        assert result['result'] == expected
        assert len(result['steps'][0]['chains']) == 1


@pytest.mark.parametrize('scenario', ['vyos', 'routeros'])
def test_interface_match_does_not_remove_chain_default(scenario):
    config = parse(scenario)
    permit = next(p for p in config.policies if p.action == 'permit' and p.in_interfaces and p.ip_version != 6)
    permit.default_action = 'deny'
    config.policies = [permit]
    guest = 'vyos-lab-if-eth1' if scenario == 'vyos' else 'routeros-lab-ether3'
    office = 'vyos-lab-if-eth0' if scenario == 'vyos' else 'routeros-lab-ether1'
    result = analyze_reachability([config], guest, office, 'tcp', 443, ip_version=4)
    assert result['result'] == 'DENY'
    assert result['steps'][0]['chains'][0]['policy'] is None


def test_diff_retains_both_families_and_unsupported_match_changes():
    result = compare_snapshots([parse('vyos')], [parse('vyos', 'after')], 'tcp', 443)
    assert result['summary']['changed_rules'] == 1
    assert result['policies'][0]['before']['ip_version'] == 4
    assert any(field['field'] == 'action' for field in result['policies'][0]['fields'])
    result = compare_snapshots([parse('unsupported')], [parse('unsupported', 'after')], 'tcp', 443)
    assert result['summary']['changed_rules'] == 1
    assert {field['field'] for field in result['policies'][0]['fields']} == {'unsupported_matches', 'confidence'}


def test_routeros_export_preserves_wrapped_state_and_nat_values():
    file = SCENARIOS.parent / 'evidence/routeros/routeros-before.rsc'
    config, _ = ParserRegistry.parse(file.read_text(), file.name)
    assert config.device.network_os == 'routeros'
    assert config.policies[0].states == ['established', 'related']
    assert config.policies[1].in_interfaces == ['ether1']
    assert config.nat[0].translated_dst == '10.44.9.20'
    assert config.nat[0].translated_port == 443
