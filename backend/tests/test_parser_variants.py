from app.parsers import ParserRegistry


def test_cisco_iosxe_ipv6_acl_and_binding():
    raw = """version 17.12
hostname edge6
interface GigabitEthernet0/0
 ipv6 address 2001:db8:1::1/64
 ipv6 traffic-filter V6-IN in
ipv6 access-list V6-IN
 10 permit tcp host 2001:db8:1::10 any eq 443
 20 deny ipv6 any any
"""
    config, ranked = ParserRegistry.parse(raw, "edge6.conf")

    assert ranked[0].parser_id == "cisco_iosxe"
    assert config.interfaces[0].acl_in == ["V6-IN"]
    assert config.policies[0].src == ["2001:db8:1::10/128"]
    assert config.policies[0].dst_ports == ["443"]
    assert config.policies[0].src_segments == ["edge6-gigabitethernet0-0"]


def test_yamaha_ipv6_filter_binding_and_default_route():
    raw = """hostname rtx-v6
ipv6 lan1 address 2001:db8:10::1/64
ipv6 filter 200 pass 2001:db8:10::/64 * tcp * 443
ipv6 lan1 secure filter in 200
ipv6 route default gateway fe80::1%lan1
"""
    config, ranked = ParserRegistry.parse(raw, "rtx-v6.conf")

    assert ranked[0].parser_id == "yamaha_rtx"
    assert config.policies[0].interface == "lan1"
    assert config.policies[0].src_segments == ["rtx-v6-lan1"]
    assert config.routes[0].destination == "::/0"
    assert config.routes[0].next_hop == "fe80::1%lan1"


def test_fortios_disabled_policy_does_not_affect_analysis():
    raw = """config system global
    set hostname fg-branch
end
config firewall policy
    edit 10
        set srcintf "lan"
        set dstintf "wan"
        set srcaddr "all"
        set dstaddr "all"
        set action accept
        set service "HTTPS"
    next
    edit 20
        set status disable
        set srcintf "lan"
        set dstintf "wan"
        set srcaddr "all"
        set dstaddr "all"
        set action accept
        set service "SSH"
    next
end
"""
    config, ranked = ParserRegistry.parse(raw, "fg-branch.conf")

    assert ranked[0].parser_id == "fortinet_fortios"
    assert [policy.sequence for policy in config.policies] == [10]
    assert config.policies[0].dst_ports == ["443"]


def test_panos_vsys_scope_and_disabled_policy():
    raw = """set deviceconfig system hostname pa-branch
set network interface ethernet ethernet1/1 layer3 ip 192.0.2.2/29
set vsys vsys1 zone untrust network layer3 ethernet1/1
set vsys vsys1 rulebase security rules ALLOW-WEB from trust
set vsys vsys1 rulebase security rules ALLOW-WEB to untrust
set vsys vsys1 rulebase security rules ALLOW-WEB source any
set vsys vsys1 rulebase security rules ALLOW-WEB destination any
set vsys vsys1 rulebase security rules ALLOW-WEB application ssl
set vsys vsys1 rulebase security rules ALLOW-WEB service application-default
set vsys vsys1 rulebase security rules ALLOW-WEB action allow
set vsys vsys1 rulebase security rules OLD-SSH from trust
set vsys vsys1 rulebase security rules OLD-SSH to untrust
set vsys vsys1 rulebase security rules OLD-SSH source any
set vsys vsys1 rulebase security rules OLD-SSH destination any
set vsys vsys1 rulebase security rules OLD-SSH application ssh
set vsys vsys1 rulebase security rules OLD-SSH action allow
set vsys vsys1 rulebase security rules OLD-SSH disabled yes
"""
    config, ranked = ParserRegistry.parse(raw, "pa-branch.set")

    assert ranked[0].parser_id == "paloalto_panos"
    assert {zone.name for zone in config.zones} == {"untrust"}
    assert [policy.name for policy in config.policies] == ["ALLOW-WEB"]
    assert config.policies[0].protocol == ["tcp"]
    assert config.policies[0].dst_ports == ["443"]
    assert config.policies[0].trace.raw_config.startswith("set vsys vsys1 rulebase")
