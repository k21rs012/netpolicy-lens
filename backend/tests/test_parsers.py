from app.analyzer import build_matrix
from app.parsers import ParserRegistry
from app.sample import SAMPLES


def test_cisco_iosxe_golden():
    cfg, ranked = ParserRegistry.parse(SAMPLES["cisco01.conf"], "cisco01.conf")
    assert cfg.device.network_os == "ios-xe"
    assert cfg.device.hostname == "cisco01"
    assert {v.name for v in cfg.vlans} == {"USER", "SERVER"}
    assert len(cfg.policies) == 3
    assert cfg.policies[0].dst_ports == ["443"]
    assert cfg.policies[0].trace.line_start == 16


def test_juniper_srx_policy_and_zones():
    cfg, _ = ParserRegistry.parse(SAMPLES["srx01.conf"], "srx01.conf")
    assert cfg.device.network_os == "srx"
    assert {z.name for z in cfg.zones} == {"trust", "untrust"}
    assert cfg.policies[0].from_zone == "trust"
    assert cfg.policies[0].protocol == ["tcp"]
    assert cfg.policies[0].dst_ports == ["443"]


def test_yamaha_filter_binding():
    cfg, _ = ParserRegistry.parse(SAMPLES["rtx01.conf"], "rtx01.conf")
    policy = next(p for p in cfg.policies if p.sequence == 100)
    assert policy.interface == "lan1"
    assert policy.direction == "in"
    assert policy.dst_ports == ["22"]


def test_unknown_is_never_assumed_allow():
    cfg, _ = ParserRegistry.parse(SAMPLES["cisco01.conf"], "cisco01.conf")
    matrix = build_matrix([cfg])
    user = next(s for s in cfg.segments if s.name == "USER")
    server = next(s for s in cfg.segments if s.name == "SERVER")
    reverse = next(c for c in matrix if c.source == server.id and c.destination == user.id)
    assert reverse.result == "UNKNOWN"


def test_detection_requires_multiple_signals():
    ranked = ParserRegistry.detect("ip filter 100 pass * * tcp * 443")
    assert ranked[0].confidence < 0.5
