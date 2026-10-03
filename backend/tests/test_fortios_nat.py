import pytest

from app.matrix_query import build_query_matrix
from app.parsers import ParserRegistry
from app.reachability import analyze_reachability
from app.models import CanonicalConfig

BASE = '''config system global
 set hostname fg
end
config system interface
 edit "wan"
  set ip 198.51.100.1 255.255.255.0
 next
 edit "lan"
  set ip 10.0.9.1 255.255.255.0
 next
end
'''
VIP = '''config firewall vip
 edit "WEB"
  set extip 198.51.100.10
  set mappedip "10.0.9.20"
  set extintf "wan"
  set portforward enable
  set protocol tcp
  set extport 8443
  set mappedport 443
 next
end
'''
POLICY = '''config firewall policy
 edit 10
  set srcintf "wan"
  set dstintf "lan"
  set srcaddr "all"
  set dstaddr "WEB"
  set action accept
  set schedule "always"
  set service "HTTPS"
 next
end
'''
POOL = '''config firewall ippool
 edit "PUBLIC"
  set type overload
  set startip 198.51.100.99
  set endip 198.51.100.99
 next
end
'''
OUT = POLICY.replace('"wan"', '"TMP"').replace('"lan"', '"wan"').replace('"TMP"', '"lan"').replace('"WEB"', '"all"')
CENTRAL = '''config system settings
 set central-nat enable
end
config firewall central-snat-map
 edit 1
  set srcintf "lan"
  set dstintf "wan"
  set orig-addr "all"
  set dst-addr "all"
  set protocol 6
  set orig-port 12345
  set nat-port 45678
  set nat-ippool "PUBLIC"
 next
end
'''


def parse(raw):
    config, _ = ParserRegistry.parse(BASE + raw, 'fortigate.conf', parser_id='fortinet_fortios')
    # Persistence must retain the new policy and NAT relationships.
    return CanonicalConfig.model_validate_json(config.model_dump_json())


def inbound(config, port=8443, **kwargs):
    return analyze_reachability([config], 'fg-if-wan', 'fg-if-wan', 'tcp', port,
                                source_ip='198.51.100.55', destination_ip='198.51.100.10', **kwargs)


def outbound(config, **kwargs):
    return analyze_reachability([config], 'fg-if-lan', 'fg-if-wan', 'tcp', 443,
                                source_ip='10.0.9.20', destination_ip='198.51.100.55', source_port=12345, **kwargs)


def test_vip_reroutes_and_policy_matches_mapped_service():
    result = inbound(parse(VIP + POLICY))
    assert result['result'] == 'ALLOW'
    assert result['path'][-1] == 'segment:fg-if-lan'
    assert result['flow']['current']['destination_addresses'] == ['10.0.9.20/32']
    assert result['flow']['current']['destination_port'] == 443
    assert result['steps'][0]['nat'][0]['name'] == 'WEB'
    assert inbound(parse(VIP + POLICY.replace('HTTPS', 'SSH')))['result'] == 'DENY'


def test_vip_identity_not_just_mapped_ip():
    cfg = parse(VIP + POLICY)
    direct = analyze_reachability([cfg], 'fg-if-wan', 'fg-if-lan', 'tcp', 443,
                                  source_ip='198.51.100.55', destination_ip='10.0.9.20')
    assert direct['result'] == 'DENY'
    assert inbound(cfg, 443)['result'] != 'ALLOW'


def test_vip_group_reference():
    group = 'config firewall vipgrp\n edit "SERVERS"\n set member "WEB"\n next\nend\n'
    assert inbound(parse(VIP + group + POLICY.replace('"WEB"', '"SERVERS"')))['result'] == 'ALLOW'


@pytest.mark.parametrize('change', [
    ('set mappedip "10.0.9.20"', 'set mappedip "10.0.9.20-10.0.9.30"'),
    ('set extport 8443', 'set extport 8443-8445'),
    ('set extintf "wan"', 'set extintf "wan"\n set src-filter 198.51.100.55'),
    ('set mappedport 443', 'set mappedport 443\n set type server-load-balance'),
])
def test_unsupported_vips_are_partial(change):
    result = inbound(parse(VIP.replace(*change) + POLICY))
    assert result['result'] == 'PARTIAL'
    assert not result['steps'][0]['nat'][0]['applied']


def test_overlapping_or_unreferenced_vip_not_arbitrarily_selected():
    assert inbound(parse(VIP + VIP.replace('WEB', 'OTHER') + POLICY))['result'] == 'PARTIAL'
    assert inbound(parse(VIP + POLICY.replace('"WEB"', '"all"')))['result'] == 'PARTIAL'


def test_match_vip_deny_and_disabled_policy():
    deny = POLICY.replace('edit 10', 'edit 1').replace('"WEB"', '"all"').replace('action accept', 'action deny\n  set match-vip enable')
    assert inbound(parse(VIP + deny + POLICY))['result'] == 'DENY'
    assert inbound(parse(VIP + deny.replace('match-vip enable', 'match-vip disable') + POLICY))['result'] == 'ALLOW'
    assert inbound(parse(VIP + deny.replace('  set match-vip enable', '') + POLICY))['result'] == 'PARTIAL'
    assert inbound(parse(VIP + POLICY.replace('set action accept', 'set action accept\n set status disable')))['result'] != 'ALLOW'


def test_policy_pool_fixedport_and_dynamic_pat():
    nat = OUT.replace('set action accept', 'set action accept\n set nat enable\n set ippool enable\n set poolname "PUBLIC"\n set fixedport enable')
    result = outbound(parse(POOL + nat))
    assert result['result'] == 'ALLOW'
    assert result['flow']['current']['source_addresses'] == ['198.51.100.99/32']
    assert result['flow']['current']['source_port'] == 12345
    result = outbound(parse(POOL + nat.replace('fixedport enable', 'fixedport disable')))
    assert result['result'] == 'PARTIAL'
    assert result['flow']['current']['source_port'] is None


@pytest.mark.parametrize('pool', [POOL.replace('set endip 198.51.100.99', 'set endip 198.51.100.100'), '', POOL.replace('type overload', 'type port-block-allocation')])
def test_pool_ambiguity_stops_translation(pool):
    nat = OUT.replace('set action accept', 'set action accept\n set nat enable\n set ippool enable\n set poolname "PUBLIC"')
    result = outbound(parse(pool + nat))
    assert result['result'] == 'PARTIAL'
    assert result['flow']['current']['source_addresses'] == ['10.0.9.20/32']


def test_central_snat_overrides_policy_nat_and_explicit_port():
    cfg = parse(POOL + OUT.replace('set action accept', 'set action accept\n set nat enable') + CENTRAL)
    assert len([r for r in cfg.nat if r.stage == 'source']) == 1
    result = outbound(cfg)
    assert result['result'] == 'ALLOW'
    assert result['flow']['current']['source_addresses'] == ['198.51.100.99/32']
    assert result['flow']['current']['source_port'] == 45678
    assert result['steps'][0]['nat'][0]['name'] == 'central-snat-1'


def test_central_disabled_no_match_exclusion_and_policy_deny():
    for central in [CENTRAL.replace('orig-port 12345', 'orig-port 12346'), CENTRAL.replace('edit 1', 'edit 1\n set status disable')]:
        result = outbound(parse(POOL + OUT + central))
        assert result['result'] == 'ALLOW'
        assert not result['steps'][0]['nat']
    result = outbound(parse(POOL + OUT + CENTRAL.replace('edit 1', 'edit 1\n set nat disable')))
    assert result['result'] == 'ALLOW'
    assert result['steps'][0]['nat'][0]['type'] == 'exclude'
    result = outbound(parse(POOL + OUT.replace('action accept', 'action deny') + CENTRAL))
    assert result['result'] == 'DENY' and not result['steps'][0]['nat']


def test_central_dnat_uses_real_address_policy_without_vip_reference():
    cfg = parse(VIP + POLICY.replace('"WEB"', '"10.0.9.20"') + 'config system settings\n set central-nat enable\nend\n')
    assert inbound(cfg)['result'] == 'ALLOW'


def test_matrix_uses_same_nat_pipeline_and_port_uncertainty():
    cfg = parse(POOL + OUT + CENTRAL)
    cell = build_query_matrix([cfg], 'tcp', 443, 'fg-if-lan', 'fg-if-wan')[0]
    assert cell.result == 'PARTIAL'  # source port unspecified
    assert 'NAT条件' in cell.reason


def test_nat_packets_continue_to_next_device():
    from test_flow_reachability import network_path
    raw = VIP + POLICY.replace('set action accept', 'set action accept\n set nat enable\n set ippool enable\n set poolname "PUBLIC"\n set fixedport enable') + POOL
    route = 'config router static\n edit 1\n set dst 10.0.9.0 255.255.255.0\n set gateway 192.0.2.2\n set device lan\n next\nend\n'
    fg, _ = ParserRegistry.parse((BASE + raw + route).replace('set ip 10.0.9.1 255.255.255.0', 'set ip 192.0.2.1 255.255.255.252'), 'fortigate.conf', parser_id='fortinet_fortios')
    downstream = network_path(2)[1]
    downstream.interfaces[0].addresses = ['192.0.2.2/30']
    downstream.policies[0].src = ['198.51.100.99/32']
    downstream.policies[0].src_ports = ['any']
    result = analyze_reachability([fg, downstream], 'fg-if-wan', 'fg-if-wan', 'tcp', 8443,
                                  source_ip='198.51.100.55', destination_ip='198.51.100.10')
    assert result['result'] == 'ALLOW'
    assert len(result['steps']) == 2
    assert result['steps'][1]['packet_in']['destination_addresses'] == ['10.0.9.20/32']
    assert result['steps'][1]['packet_in']['source_addresses'] == ['198.51.100.99/32']
    assert result['steps'][1]['packet_in']['destination_port'] == 443


def test_central_rule_order_move_and_no_nat_exclusion():
    central = CENTRAL.replace(' next\nend', ' next\n edit 2\n set srcintf lan\n set dstintf wan\n set nat disable\n next\n move 2 before 1\nend')
    result = outbound(parse(POOL + OUT + central))
    assert result['result'] == 'ALLOW'
    assert result['steps'][0]['nat'][0]['name'] == 'central-snat-2'
    assert result['flow']['current']['source_addresses'] == ['10.0.9.20/32']


def test_central_nat_disabled_ignores_table_and_any_interface_policy():
    raw = OUT.replace('set srcintf "lan"', 'set srcintf "any"').replace('set dstintf "wan"', 'set dstintf "any"')
    result = outbound(parse(raw + POOL + CENTRAL.replace('central-nat enable', 'central-nat disable')))
    assert result['result'] == 'ALLOW'
    assert not result['steps'][0]['nat']


def test_unresolved_central_address_and_dynamic_port_are_partial():
    for central in [CENTRAL.replace('"all"', '"MISSING"'), CENTRAL.replace('  set nat-port 45678\n', '')]:
        assert outbound(parse(OUT + POOL + central))['result'] == 'PARTIAL'


def test_vip_static_reverse_snat_is_explicitly_partial():
    static = '\n'.join(line for line in VIP.splitlines() if not any(field in line for field in ['portforward', 'protocol', 'extport', 'mappedport'])) + '\n'
    raw = static + POLICY + OUT.replace('edit 10', 'edit 11').replace('set action accept', 'set action accept\n set nat enable\n set fixedport enable')
    result = outbound(parse(raw))
    assert result['result'] == 'PARTIAL'
    assert '逆方向SNAT' in result['steps'][0]['nat'][-1]['note']


@pytest.mark.parametrize('change', [('set dstaddr "WEB"', 'set dstaddr "WEB" "all"'), ('set dstaddr "WEB"', 'set dstaddr "WEB"\n set dstaddr-negate enable')])
def test_vip_mixed_and_negated_identity_remains_partial(change):
    assert inbound(parse(VIP + POLICY.replace(*change)))['result'] == 'PARTIAL'


def test_ngfw_policy_based_is_not_silently_treated_as_profile_mode():
    cfg = parse(VIP + POLICY + 'config system settings\n set ngfw-mode policy-based\nend\n')
    assert inbound(cfg)['result'] == 'PARTIAL'


def test_central_vip_reference_is_not_treated_as_an_ordinary_address():
    cfg = parse(VIP + POLICY + 'config system settings\n set central-nat enable\nend\n')
    assert inbound(cfg)['result'] == 'PARTIAL'


def test_routed_public_vip_outside_interface_subnet_is_selectable():
    cfg = parse(VIP.replace('set extip 198.51.100.10', 'set extip 203.0.113.10') + POLICY)
    vip = next(s for s in cfg.segments if s.type == 'logical')
    assert vip.networks == ['203.0.113.10/32']
    result = analyze_reachability([cfg], 'fg-if-wan', vip.id, 'tcp', 8443, source_ip='198.51.100.55')
    assert result['result'] == 'ALLOW'
    assert result['path'][-1] == 'segment:fg-if-lan'
