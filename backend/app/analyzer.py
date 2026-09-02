from __future__ import annotations

import ipaddress
from typing import Literal

from .models import CanonicalConfig, MatrixCell, Policy, Segment
from .policy_utils import policy_chain_key, policy_order, service_labels


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
        except ValueError:
            if "-" in value:
                first, last = value.split("-", 1)
                try:
                    policy_networks.extend(ipaddress.summarize_address_range(
                        ipaddress.ip_address(first), ipaddress.ip_address(last)))
                    continue
                except ValueError:
                    pass
            unresolved = True
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
    if policy.src_negate: src_coverage = {"FULL": "NONE", "NONE": "FULL", "PARTIAL": "PARTIAL"}[src_coverage]
    if policy.dst_negate: dst_coverage = {"FULL": "NONE", "NONE": "FULL", "PARTIAL": "PARTIAL"}[dst_coverage]
    if "NONE" in (src_coverage, dst_coverage): return "NONE"
    return "PARTIAL" if "PARTIAL" in (src_coverage, dst_coverage) else "FULL"


def effective_policies(policies: list[Policy], src: Segment, dst: Segment) -> list[tuple[Policy, Coverage, list[str]]]:
    """Apply first-match semantics per policy chain and exact service label."""
    seen: set[tuple[tuple[str, ...], str]] = set()
    effective: list[tuple[Policy, Coverage, list[str]]] = []
    for policy in sorted((item for item in policies if item.enabled),
                         key=lambda item: (item.device, policy_chain_key(item), policy_order(item))):
        coverage = policy_coverage(policy, src, dst)
        if coverage == "NONE": continue
        if policy.action in {"continue", "return"} or not policy.terminal:
            continue
        chain = policy_chain_key(policy); labels: list[str] = []
        for label in service_labels(policy):
            key = chain, label
            if key in seen: continue
            seen.add(key); labels.append(label)
        if labels: effective.append((policy, coverage, labels))
    return effective


def build_matrix(configs: list[CanonicalConfig]) -> list[MatrixCell]:
    segments = [s for cfg in configs for s in cfg.segments]
    definition_only_os = {"ios", "ios-xe", "nx-os", "aos-cx", "eos", "alliedware-plus", "rtx", "exos", "voss"}
    policies = [p for cfg in configs for p in cfg.policies
                if not (p.direction == "unknown" and cfg.device.network_os in definition_only_os)]
    cells: list[MatrixCell] = []
    for src in segments:
        for dst in segments:
            if src.id == dst.id:
                cells.append(MatrixCell(source=src.id, destination=dst.id, result="SAME_SEGMENT")); continue
            matching = effective_policies(policies, src, dst)
            allowed = [label for policy, _, labels in matching if policy.action == "permit" for label in labels]
            denied = [label for policy, _, labels in matching if policy.action in ("deny", "reject", "restrict") for label in labels]
            # A deny in any applied chain overrides a permit for that same
            # service; keep mixed services as PARTIAL.
            allowed = [label for label in allowed if label not in denied]
            partial = any(coverage == "PARTIAL" for _, coverage, _ in matching)
            result = "PARTIAL" if partial or allowed and denied else "ALLOW" if allowed else "DENY" if denied else "UNKNOWN"
            traces = [{"device": policy.device, "interface": policy.interface, "policy": policy.name, "sequence": policy.sequence,
                       "action": policy.action, "service": ", ".join(labels), "coverage": coverage,
                       "trace": policy.trace.model_dump() if policy.trace else None} for policy, coverage, labels in matching]
            cells.append(MatrixCell(source=src.id, destination=dst.id, result=result, allowed=list(dict.fromkeys(allowed)),
                                    denied=list(dict.fromkeys(denied)), policy_ids=[policy.id for policy, _, _ in matching], traces=traces))
    return cells
