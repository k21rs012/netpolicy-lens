import json
from pathlib import Path

import pytest

from app.parsers import ParserRegistry
from app.sample import SAMPLES


def projection(config):
    return {
        "device": {"id": config.device.id, "vendor": config.device.vendor, "network_os": config.device.network_os},
        "interfaces": [{"name": item.name, "addresses": item.addresses, "segment_id": item.segment_id,
            "acl_in": item.acl_in, "acl_out": item.acl_out} for item in config.interfaces],
        "vlans": [{"id": item.id, "name": item.name, "subnets": item.subnets, "gateway": item.gateway} for item in config.vlans],
        "segments": [{"id": item.id, "name": item.name, "type": item.type, "networks": item.networks} for item in config.segments],
        "routes": [{"destination": item.destination, "next_hop": item.next_hop, "interface": item.interface} for item in config.routes],
        "policies": [{"name": item.name, "sequence": item.sequence, "action": item.action,
            "src": item.src, "dst": item.dst, "protocol": item.protocol, "dst_ports": item.dst_ports,
            "direction": item.direction, "interface": item.interface, "from_zone": item.from_zone,
            "to_zone": item.to_zone} for item in config.policies],
    }


def parser_fingerprint(config, parser_id):
    return {
        "parser": parser_id,
        "vendor_os": f"{config.device.vendor}/{config.device.network_os}",
        "counts": [len(getattr(config, key)) for key in
                   ("interfaces", "vlans", "segments", "zones", "routes", "policies", "nat", "address_objects", "service_objects")],
        "interfaces": [item.name for item in config.interfaces],
        "vlans": [item.id for item in config.vlans],
        "networks": [network for segment in config.segments for network in segment.networks],
        "policies": [f"{item.name}:{item.action}:{','.join(item.protocol)}:{','.join(item.dst_ports)}" for item in config.policies],
        "nat": [f"{item.name}:{item.type}" for item in config.nat],
    }


@pytest.mark.parametrize("source", ["cisco01.conf", "rtx01.conf", "srx01.conf"])
def test_core_parser_golden_output(source):
    expected = json.loads((Path(__file__).parent / "golden" / f"{source}.json").read_text())
    actual = projection(ParserRegistry.parse(SAMPLES[source], source)[0])
    assert actual == expected


def test_all_available_parsers_golden_fingerprints():
    expected = json.loads((Path(__file__).parent / "golden" / "all-parsers.json").read_text())
    actual = {}
    for source, raw in SAMPLES.items():
        config, ranked = ParserRegistry.parse(raw, source)
        actual[source] = parser_fingerprint(config, ranked[0].parser_id)
    assert actual == expected
