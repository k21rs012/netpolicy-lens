from __future__ import annotations

import ipaddress

from .models import CanonicalConfig, Segment
from .policy_utils import port_matches
from .reachability_models import NatEffect


def _value_overlaps_segment(value: str, segment: Segment) -> bool:
    if value.lower() in {"any", "*", "0.0.0.0/0", "::/0"}:
        return True
    try:
        candidate = ipaddress.ip_network(value, strict=False)
    except ValueError:
        return False
    for raw in segment.networks:
        try:
            network = ipaddress.ip_network(raw, strict=False)
        except ValueError:
            continue
        if candidate.version == network.version and candidate.overlaps(network):
            return True
    return False


def nat_effects(
    config: CanonicalConfig,
    ingress: Segment,
    egress: Segment,
    protocol: str,
    port: int | None,
    source_port: int | None = None,
    ip_version: int | None = None,
) -> list[NatEffect]:
    effects: list[NatEffect] = []
    objects = {item.name: item.values for item in config.address_objects}

    def matches(value: str, segment: Segment, source: bool) -> bool:
        if value.startswith("interface:"):
            name = value.split(":", 1)[1]
            return any(item.segment_id == segment.id and item.name == name for item in config.interfaces)
        candidates = objects.get(value, [])
        if not candidates:
            candidates = [
                address
                for policy in config.policies
                if policy.name == value
                for address in (policy.src if source else policy.dst)
            ]
        return any(_value_overlaps_segment(candidate, segment) for candidate in (candidates or [value]))

    ingress_interfaces = {
        value for item in config.interfaces if item.segment_id == ingress.id
        for value in (item.name, item.zone) if value
    }
    egress_interfaces = {
        value for item in config.interfaces if item.segment_id == egress.id
        for value in (item.name, item.zone) if value
    }
    rules = sorted(config.nat, key=lambda item: item.sequence if item.sequence is not None else 2**31)
    matched_stages: set[str] = set()
    evaluation_order = {
        "srx": "destination NAT → policy → source NAT",
        "fortios": "DNAT/VIP → policy → SNAT",
        "panos": "NAT original packet match; policy uses pre-NAT zones and post-NAT destination",
        "vyos": "destination NAT → filter → source NAT",
        "routeros": "dstnat → filter → srcnat",
        "ios": "interface direction dependent",
        "ios-xe": "interface direction dependent",
        "asa": "NAT before ACL route lookup (platform semantics)",
        "ftd": "NAT before access policy route lookup (platform semantics)",
    }.get(config.device.network_os)
    for rule in rules:
        if rule.disabled:
            continue
        if ip_version and rule.ip_version and rule.ip_version != ip_version:
            continue
        stage = "destination" if rule.type in {"destination", "static"} else "source"
        if stage in matched_stages:
            continue
        if rule.protocol.lower() not in {"any", "ip", "*", protocol.lower()}:
            continue
        destination_ports = rule.destination_ports or (
            [str(rule.original_port)] if rule.original_port is not None else []
        )
        if destination_ports and not port_matches(destination_ports, port):
            continue
        if rule.in_interfaces and not ingress_interfaces.intersection(rule.in_interfaces):
            continue
        if rule.out_interfaces and not egress_interfaces.intersection(rule.out_interfaces):
            continue
        if rule.ip_version:
            versions: set[int] = set()
            for segment in (ingress, egress):
                for raw in segment.networks:
                    try:
                        versions.add(ipaddress.ip_network(raw, strict=False).version)
                    except ValueError:
                        continue
            if versions and rule.ip_version not in versions:
                continue
        if not matches(rule.original_src, ingress, True) or not matches(rule.original_dst, egress, False):
            continue
        if source_port is not None and rule.source_ports and not port_matches(rule.source_ports, source_port):
            continue
        partial = ((source_port is None and bool(rule.source_ports))
                   or (port is None and bool(destination_ports)))
        effects.append(NatEffect(
            name=rule.name,
            type=rule.type,
            translated_src=rule.translated_src,
            translated_dst=rule.translated_dst,
            translated_port=rule.translated_port,
            evaluation_order=evaluation_order,
            confidence="PARTIAL" if partial else "EXACT",
            note="port条件の一部がPath Trace入力にないため未評価" if partial else None,
            trace=rule.trace,
        ))
        matched_stages.add(stage)
    return effects
