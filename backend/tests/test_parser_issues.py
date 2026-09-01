from app.parsers import ParserRegistry


def test_cisco_reports_unparsed_security_lines_as_unsupported():
    raw = """version 17.12
hostname edge
ip nat outside source static 198.51.100.10 10.0.0.10
access-list 101 remark not-a-rule
"""
    config, _ = ParserRegistry.parse(raw, "edge.conf")

    assert len(config.unsupported) == 2
    assert all(item.reason.startswith("unsupported") for item in config.unsupported)


def test_yamaha_reports_unparsed_filter_and_nat_lines():
    raw = """hostname rtx
ip lan1 address 192.0.2.1/24
ip filter 100 pass-log 192.0.2.0/24 * * * *
nat descriptor address outer 1 203.0.113.1
"""
    config, _ = ParserRegistry.parse(raw, "rtx.conf")

    assert {item.line for item in config.unsupported} == {3, 4}


def test_junos_separates_unresolved_references_from_unsupported_statements():
    raw = """set system host-name srx
set interfaces ge-0/0/0 unit 0 family inet address 192.0.2.1/24
set security zones security-zone trust interfaces ge-0/0/0.0
set security policies from-zone trust to-zone missing policy P1 match source-address UNKNOWN-OBJECT
set security policies from-zone trust to-zone missing policy P1 match destination-address any
set security policies from-zone trust to-zone missing policy P1 then permit
set security policies from-zone trust to-zone missing policy P1 then log session-init
"""
    config, _ = ParserRegistry.parse(raw, "srx.conf")

    reasons = {item.reason for item in config.warnings}
    assert "unresolved address reference: UNKNOWN-OBJECT" in reasons
    assert "unresolved zone reference: missing" in reasons
    assert len(config.unsupported) == 1


def test_junos_resolves_address_sets_and_builtin_host_zone():
    raw = """set system host-name srx
set interfaces ge-0/0/0 unit 0 family inet address 192.0.2.1/24
set security zones security-zone trust interfaces ge-0/0/0.0
set security address-book global address DNS1 2001:db8::53/128
set security address-book global address-set DNS-SERVERS address DNS1
set security policies from-zone trust to-zone junos-host policy DNS match source-address DNS-SERVERS
set security policies from-zone trust to-zone junos-host policy DNS match destination-address any
set security policies from-zone trust to-zone junos-host policy DNS match application junos-dns-udp
set security policies from-zone trust to-zone junos-host policy DNS then permit
"""
    config, _ = ParserRegistry.parse(raw, "srx.conf")

    group = next(item for item in config.address_objects if item.name == "DNS-SERVERS")
    assert group.values == ["2001:db8::53/128"]
    assert not config.warnings


def test_panos_reports_missing_policy_objects_and_keeps_unsupported_separate():
    raw = """set deviceconfig system hostname pa
set network interface ethernet ethernet1/1 layer3 ip 192.0.2.1/24
set zone trust network layer3 ethernet1/1
set rulebase security rules P1 from trust
set rulebase security rules P1 to missing-zone
set rulebase security rules P1 source MISSING-ADDR
set rulebase security rules P1 destination any
set rulebase security rules P1 service MISSING-SERVICE
set rulebase security rules P1 action allow
set rulebase security rules P1 log-start yes
"""
    config, _ = ParserRegistry.parse(raw, "pa.set")

    reasons = {item.reason for item in config.warnings}
    assert "unresolved policy reference: MISSING-ADDR" in reasons
    assert "unresolved policy reference: MISSING-SERVICE" in reasons
    assert "unresolved policy reference: missing-zone" in reasons
    assert config.unsupported[0].line == 10


def test_fortios_reports_missing_policy_references():
    raw = """config system global
 set hostname fg
end
config system interface
 edit port1
  set ip 192.0.2.1 255.255.255.0
 next
end
config firewall policy
 edit 1
  set srcintf port1
  set dstintf missing-port
  set srcaddr MISSING-ADDR
  set dstaddr all
  set service MISSING-SERVICE
  set action accept
 next
end
"""
    config, _ = ParserRegistry.parse(raw, "fg.conf")

    reasons = {item.reason for item in config.warnings}
    assert "unresolved policy reference: MISSING-ADDR" in reasons
    assert "unresolved policy reference: MISSING-SERVICE" in reasons
    assert "unresolved policy reference: missing-port" in reasons
