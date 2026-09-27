import pytest
from app.parsers import ParserRegistry
from app.topology import analyze_reachability
from app.topology_graph import build_topology_model

BASE = '''set system host-name edge
set interfaces ethernet eth0 address 10.0.1.1/24
set interfaces ethernet eth0 address 2001:db8:1::1/64
set interfaces ethernet eth1 address 10.0.2.1/24
set interfaces ethernet eth1 address 2001:db8:2::1/64
'''


def parse(extra='', base=BASE):
    return ParserRegistry.parse(base + extra, 'local.set', parser_id='vyos')[0]


def trace(cfg, src, dst, **kw):
    return analyze_reachability([cfg], src, dst, 'tcp', 22, **kw)


@pytest.mark.parametrize('family,version', [('ipv4', 4), ('ipv6', 6)])
def test_input_output_forward_are_independent(family, version):
    cfg = parse(f'''set firewall {family} input filter default-action drop
set firewall {family} output filter default-action accept
set firewall {family} forward filter default-action accept
''')
    assert trace(cfg, 'edge-if-eth0', 'edge-local', ip_version=version)['result'] == 'DENY'
    assert trace(cfg, 'edge-local', 'edge-if-eth1', ip_version=version)['result'] == 'ALLOW'
    assert trace(cfg, 'edge-if-eth0', 'edge-if-eth1', ip_version=version)['result'] == 'ALLOW'


def test_input_jump_and_explicit_interface_address():
    cfg = parse('''set firewall ipv4 forward filter default-action accept
set firewall ipv4 input filter rule 10 action jump
set firewall ipv4 input filter rule 10 jump-target MGMT
set firewall ipv4 name MGMT default-action drop
''')
    result = trace(cfg, 'edge-if-eth0', 'edge-if-eth0', destination_ip='10.0.1.1')
    assert result['result'] == 'DENY'
    assert result['path'][-1] == 'segment:edge-local'
    assert result['steps'][0]['chains'][0]['chain'] == 'vyos:ipv4:MGMT'


ZONES = '''set firewall zone LAN interface eth0
set firewall zone WAN interface eth1
set firewall zone LOCAL local-zone
set firewall zone LOCAL from LAN firewall name MGMT
set firewall zone WAN from LOCAL firewall name MGMT
set firewall zone WAN from LAN firewall name MGMT
set firewall ipv4 name MGMT default-action accept
'''


def test_reused_ruleset_all_pairs_and_family_defaults():
    cfg = parse(ZONES)
    for src, dst in [('lan', 'local'), ('local', 'wan'), ('lan', 'wan')]:
        assert trace(cfg, f'edge-zone-{src}', f'edge-zone-{dst}', ip_version=4)['result'] == 'ALLOW'
        assert trace(cfg, f'edge-zone-{src}', f'edge-zone-{dst}', ip_version=6)['result'] == 'DENY'
    assert trace(cfg, 'edge-zone-wan', 'edge-zone-local', ip_version=4)['result'] == 'DENY'
    assert len({p.id for p in cfg.policies}) == len(cfg.policies)


def test_base_input_deny_overrides_zone_accept():
    cfg = parse(ZONES + 'set firewall ipv4 input filter default-action drop\n')
    assert trace(cfg, 'edge-zone-lan', 'edge-zone-local', ip_version=4)['result'] == 'DENY'
    assert trace(cfg, 'edge-zone-lan', 'edge-zone-wan', ip_version=4)['result'] == 'ALLOW'


def test_undefined_zone_ruleset_is_not_allow():
    cfg = parse(ZONES.replace('set firewall ipv4 name MGMT default-action accept\n', ''))
    assert trace(cfg, 'edge-zone-lan', 'edge-zone-local', ip_version=4)['result'] == 'PARTIAL'
    assert any('undefined zone ruleset' in w.reason for w in cfg.warnings)


@pytest.mark.parametrize('nat', [False, True])
def test_local_input_not_affected_by_snat(nat):
    cfg = parse('set firewall ipv4 input filter default-action drop\n' + ('''set nat source rule 1 outbound-interface name eth1
set nat source rule 1 translation address masquerade
''' if nat else ''))
    assert trace(cfg, 'edge-if-eth0', 'edge-local', destination_ip='10.0.2.1')['result'] == 'DENY'


def test_local_output_applies_snat_but_not_prerouting_dnat():
    cfg = parse('''set firewall ipv4 output filter default-action accept
set firewall ipv4 input filter default-action drop
set nat destination rule 1 destination address 10.0.2.20
set nat destination rule 1 translation address 203.0.113.20
set nat source rule 1 outbound-interface name eth1
set nat source rule 1 translation address 198.51.100.1
''')
    result = trace(cfg, 'edge-local', 'edge-if-eth1', source_ip='10.0.1.1', destination_ip='10.0.2.20')
    assert result['result'] in {'ALLOW', 'PARTIAL'}
    assert result['flow']['current']['source_addresses'] == ['198.51.100.1/32']
    assert result['flow']['current']['destination_addresses'] == ['10.0.2.20/32']


def test_local_endpoints_do_not_create_inferred_links():
    topology = build_topology_model([parse(), parse(base=BASE.replace('edge', 'other'))])
    assert all('local' not in e.source and 'local' not in e.target for e in topology.edges if e.type == 'adjacent')


def test_local_vrf_addresses_remain_separate():
    cfg = parse('set interfaces ethernet eth1 vrf BLUE\nset firewall ipv4 input filter default-action accept\n')
    local = next(s for s in cfg.segments if s.type == 'local' and s.vrf == 'BLUE')
    assert set(local.networks) == {'10.0.2.1/32', '2001:db8:2::1/128'}
    assert trace(cfg, 'edge-if-eth1', local.id, ip_version=4)['result'] == 'ALLOW'
    assert trace(cfg, 'edge-if-eth0', local.id, ip_version=4)['result'] != 'ALLOW'


def test_api_import_local_trace(tmp_path, monkeypatch):
    from fastapi.testclient import TestClient
    from app import main
    from app.storage import SnapshotStore
    monkeypatch.setattr(main, 'store', SnapshotStore(str(tmp_path / 'local.db')))
    client = TestClient(main.app)
    raw = BASE + 'set firewall ipv4 input filter default-action drop\n'
    response = client.post('/api/configs/import', files=[('files', ('local.set', raw, 'text/plain'))])
    assert response.status_code == 200
    snapshot = response.json()['snapshot_id']
    segments = client.get('/api/matrix', params={'snapshot_id': snapshot}).json()['segments']
    assert any(s['type'] == 'local' and '機器自身' in s['name'] for s in segments)
    result = client.get('/api/reachability', params={'snapshot_id': snapshot, 'src': 'edge-if-eth0',
                        'dst': 'edge-local', 'protocol': 'tcp', 'port': 22, 'destination_ip': '10.0.1.1'})
    assert result.status_code == 200
    assert result.json()['result'] == 'DENY'


def test_hierarchical_input_and_output():
    cfg = parse(base='''system {
 host-name edge
}
interfaces {
 ethernet eth0 {
  address 10.0.1.1/24
 }
}
firewall {
 ipv4 {
  input {
   filter {
    default-action drop
   }
  }
  output {
   filter {
    default-action accept
   }
  }
 }
}
''')
    assert trace(cfg, 'edge-if-eth0', 'edge-local')['result'] == 'DENY'
    assert trace(cfg, 'edge-local', 'edge-if-eth0')['result'] == 'ALLOW'


@pytest.mark.parametrize('nat', [False, True])
def test_multihop_local_destination_preserves_original_source(nat):
    edge = parse('''set protocols static route 203.0.113.0/24 next-hop 10.0.2.2
set firewall ipv4 forward filter default-action accept
''')
    remote = parse(base='''set system host-name remote
set interfaces ethernet eth0 address 10.0.2.2/24
set interfaces loopback lo address 203.0.113.1/32
set firewall ipv4 input filter default-action accept
set firewall ipv4 input filter rule 1 source address 10.0.1.0/24
set firewall ipv4 input filter rule 1 action drop
''' + ('''set nat source rule 1 outbound-interface name eth0
set nat source rule 1 translation address masquerade
''' if nat else ''))
    result = analyze_reachability([edge, remote], 'edge-if-eth0', 'remote-local', 'tcp', 22,
                                  source_ip='10.0.1.20', destination_ip='203.0.113.1')
    assert result['result'] == 'DENY'
    assert result['steps'][-1]['device'] == 'remote'
    assert result['steps'][-1]['flow']['current']['source_addresses'] == ['10.0.1.20/32']


def test_zone_to_unzoned_cannot_bypass_zone_policy():
    cfg = parse('set firewall zone LAN interface eth0\nset firewall ipv4 forward filter default-action accept\n')
    assert trace(cfg, 'edge-zone-lan', 'edge-if-eth1', ip_version=4)['result'] == 'DENY'


def test_local_address_missing_is_unknown():
    cfg = parse(base='''set system host-name edge
set interfaces ethernet eth0 address dhcp
set firewall ipv4 input filter default-action accept
''')
    assert trace(cfg, 'edge-if-eth0', 'edge-local', ip_version=4)['result'] == 'UNKNOWN'


def test_dnat_to_local_uses_input_not_forward():
    cfg = parse('''set firewall ipv4 input filter default-action drop
set firewall ipv4 forward filter default-action accept
set nat destination rule 1 destination address 10.0.2.20
set nat destination rule 1 translation address 10.0.1.1
''')
    result = trace(cfg, 'edge-if-eth0', 'edge-if-eth1', source_ip='10.0.1.20', destination_ip='10.0.2.20')
    assert result['result'] == 'DENY'
    assert result['steps'][-1]['egress'] == 'edge-local'
