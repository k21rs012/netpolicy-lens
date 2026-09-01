import pytest

from app.analyzer import build_matrix
from app.parsers import ParserRegistry
from app.sample import SAMPLES


EXPECTED = {
    "cisco01.conf": ("cisco_iosxe", {"interfaces": 2, "segments": 2, "policies": 3}),
    "srx01.conf": ("juniper_srx", {"interfaces": 2, "segments": 2, "policies": 1}),
    "rtx01.conf": ("yamaha_rtx", {"interfaces": 2, "segments": 2, "policies": 2}),
    "fortigate01.conf": ("fortinet_fortios", {"interfaces": 2, "segments": 2, "policies": 1}),
    "panos01.set": ("paloalto_panos", {"interfaces": 2, "segments": 2, "policies": 1}),
    "aoscx01.conf": ("aruba_aoscx", {"interfaces": 2, "segments": 1, "policies": 2}),
    "eos01.conf": ("arista_eos", {"interfaces": 2, "segments": 1, "policies": 2}),
    "allied01.conf": ("alliedware_plus", {"interfaces": 2, "segments": 1, "policies": 2}),
    "vyos01.set": ("vyos", {"interfaces": 3, "segments": 3, "policies": 1}),
}


@pytest.mark.parametrize("source", EXPECTED)
def test_all_supported_samples_satisfy_canonical_contract(source):
    raw = SAMPLES[source]
    expected_parser, expected_counts = EXPECTED[source]
    config, ranked = ParserRegistry.parse(raw, source)

    assert ranked[0].parser_id == expected_parser
    assert ranked[0].confidence >= 0.5
    assert config.device.id and config.device.hostname
    for kind, count in expected_counts.items():
        assert len(getattr(config, kind)) == count

    assert len({segment.id for segment in config.segments}) == len(config.segments)
    assert len({policy.id for policy in config.policies}) == len(config.policies)
    segment_ids = {segment.id for segment in config.segments}
    for policy in config.policies:
        assert policy.action != "unknown"
        assert set(policy.src_segments + policy.dst_segments) <= segment_ids

    line_count = len(raw.splitlines())
    traced = [
        item
        for group in (
            config.interfaces, config.vlans, config.zones, config.routes,
            config.policies, config.nat,
        )
        for item in group
        if item.trace
    ]
    assert all(1 <= item.trace.line_start <= item.trace.line_end <= line_count for item in traced)
    assert len(build_matrix([config])) == len(config.segments) ** 2


@pytest.mark.parametrize("source", EXPECTED)
def test_crlf_exports_parse_the_same_as_lf(source):
    raw = SAMPLES[source]
    expected, _ = ParserRegistry.parse(raw, source)
    actual, ranked = ParserRegistry.parse(raw.replace("\n", "\r\n"), source)

    assert ranked[0].parser_id == EXPECTED[source][0]
    assert actual.counts() == expected.counts()
    assert actual.device.hostname == expected.device.hostname


@pytest.mark.parametrize("source", EXPECTED)
def test_utf8_bom_does_not_break_detection(source):
    config, ranked = ParserRegistry.parse("\ufeff" + SAMPLES[source], source)

    assert ranked[0].parser_id == EXPECTED[source][0]
    assert config.device.hostname
