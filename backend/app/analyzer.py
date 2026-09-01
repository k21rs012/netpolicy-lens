from __future__ import annotations

import ipaddress
from typing import Literal

from .models import CanonicalConfig, MatrixCell, Policy, Segment


def _is_any(value: str) -> bool:
    return value.lower() in {"any", "*", "0.0.0.0/0", "::/0"}


Coverage = Literal["NONE", "FULL", "PARTIAL"]


def _network_coverage(policy_values: list[str], segment: Segment) -> Coverage:
    """Return how much of a segment is covered by policy address values.

    Names that were not resolved to a network are deliberately PARTIAL rather
    than treated as an exact match. This prevents an object-scoped rule from
    turning an entire zone or VLAN green in the matrix.
    """
    if any(_is_any(value) for value in policy_values): return "FULL"
    policy_networks: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
    unresolved = False
    for value in policy_values:
        try: policy_networks.append(ipaddress.ip_network(value, strict=False))
        except ValueError: unresolved = True
    if not segment.networks:
        return "PARTIAL" if policy_values else "NONE"
    segment_networks: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
    for value in segment.networks:
        try: segment_networks.append(ipaddress.ip_network(value, strict=False))
        except ValueError: pass
    if not segment_networks: return "PARTIAL" if policy_values else "NONE"
    overlap = False; fully_covered = True
    for segment_network in segment_networks:
        compatible = [network for network in policy_networks if network.version == segment_network.version]
        if any(segment_network.subnet_of(network) for network in compatible):
            overlap = True
        else:
            fully_covered = False
            if any(segment_network.overlaps(network) for network in compatible): overlap = True
    if fully_covered and not unresolved: return "FULL"
    if overlap or unresolved: return "PARTIAL"
    return "NONE"


def policy_coverage(policy: Policy, src: Segment, dst: Segment) -> Coverage:
    # Until topology/path analysis is available, implicit address matches are
    # evaluated only inside the policy-owning device. This prevents an `any`
    # rule on one device from appearing to permit unrelated remote segments.
    if policy.src_segments and src.id not in policy.src_segments: return "NONE"
    if policy.dst_segments and dst.id not in policy.dst_segments: return "NONE"
    if not policy.src_segments and src.device != policy.device: return "NONE"
    if not policy.dst_segments and dst.device != policy.device: return "NONE"
    src_coverage = _network_coverage(policy.src, src)
    dst_coverage = _network_coverage(policy.dst, dst)
    if "NONE" in (src_coverage, dst_coverage): return "NONE"
    return "PARTIAL" if "PARTIAL" in (src_coverage, dst_coverage) else "FULL"


def _service_labels(policy: Policy) -> list[str]:
    labels: list[str] = []
    for proto in policy.protocol:
        for port in policy.dst_ports:
            if proto in ("ip", "any", "*") and port in ("any", "*"): labels.append("ANY")
            elif port in ("any", "*"): labels.append(proto.upper())
            else: labels.append(f"{proto.upper()}/{port}")
    return list(dict.fromkeys(labels))


def _policy_chain(policy: Policy) -> tuple[str, ...]:
    if policy.direction == "zone":
        return policy.device, "zone", policy.from_zone or "", policy.to_zone or ""
    return policy.device, policy.direction, policy.interface or "", policy.name


def effective_policies(policies: list[Policy], src: Segment, dst: Segment) -> list[tuple[Policy, Coverage, list[str]]]:
    """Apply first-match semantics per policy chain and exact service label."""
    seen: set[tuple[tuple[str, ...], str]] = set()
    effective: list[tuple[Policy, Coverage, list[str]]] = []
    for policy in sorted(policies, key=lambda item: (item.device, _policy_chain(item), item.sequence)):
        coverage = policy_coverage(policy, src, dst)
        if coverage == "NONE": continue
        chain = _policy_chain(policy); labels: list[str] = []
        for label in _service_labels(policy):
            key = chain, label
            if key in seen: continue
            seen.add(key); labels.append(label)
        if labels: effective.append((policy, coverage, labels))
    return effective


def build_matrix(configs: list[CanonicalConfig]) -> list[MatrixCell]:
    segments = [s for cfg in configs for s in cfg.segments]
    policies = [p for cfg in configs for p in cfg.policies]
    cells: list[MatrixCell] = []
    for src in segments:
        for dst in segments:
            if src.id == dst.id:
                cells.append(MatrixCell(source=src.id, destination=dst.id, result="SAME_SEGMENT")); continue
            matching = effective_policies(policies, src, dst)
            allowed = [label for policy, _, labels in matching if policy.action == "permit" for label in labels]
            denied = [label for policy, _, labels in matching if policy.action in ("deny", "reject", "restrict") for label in labels]
            partial = any(coverage == "PARTIAL" for _, coverage, _ in matching)
            result = "PARTIAL" if partial or allowed and denied else "ALLOW" if allowed else "DENY" if denied else "UNKNOWN"
            traces = [{"device": policy.device, "interface": policy.interface, "policy": policy.name, "sequence": policy.sequence,
                       "action": policy.action, "service": ", ".join(labels), "coverage": coverage,
                       "trace": policy.trace.model_dump() if policy.trace else None} for policy, coverage, labels in matching]
            cells.append(MatrixCell(source=src.id, destination=dst.id, result=result, allowed=list(dict.fromkeys(allowed)),
                                    denied=list(dict.fromkeys(denied)), policy_ids=[policy.id for policy, _, _ in matching], traces=traces))
    return cells
