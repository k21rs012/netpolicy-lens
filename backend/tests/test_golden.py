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


@pytest.mark.parametrize("source", ["cisco01.conf", "rtx01.conf", "srx01.conf"])
def test_core_parser_golden_output(source):
    expected = json.loads((Path(__file__).parent / "golden" / f"{source}.json").read_text())
    actual = projection(ParserRegistry.parse(SAMPLES[source], source)[0])
    assert actual == expected
