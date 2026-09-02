from __future__ import annotations

import ipaddress

from .models import CanonicalConfig, Segment
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

    for rule in config.nat:
        if rule.protocol.lower() not in {"any", "ip", "*", protocol.lower()}:
            continue
        if rule.original_port is not None and port != rule.original_port:
            continue
        if not matches(rule.original_src, ingress, True) or not matches(rule.original_dst, egress, False):
            continue
        effects.append(NatEffect(
            name=rule.name,
            type=rule.type,
            translated_src=rule.translated_src,
            translated_dst=rule.translated_dst,
            translated_port=rule.translated_port,
            trace=rule.trace,
        ))
    return effects
