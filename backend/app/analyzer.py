from __future__ import annotations

import ipaddress

from .models import CanonicalConfig, MatrixCell, Policy, Segment


def _is_any(value: str) -> bool:
    return value.lower() in {"any", "*", "0.0.0.0/0", "::/0"}


def _matches_network(policy_values: list[str], segment: Segment) -> bool:
    if any(_is_any(v) for v in policy_values):
        return True
    for value in policy_values:
        try:
            pnet = ipaddress.ip_network(value, strict=False)
        except ValueError:
            continue
        for network in segment.networks:
            try:
                snet = ipaddress.ip_network(network, strict=False)
                if pnet.overlaps(snet): return True
            except ValueError:
                pass
    return False


def _applies(policy: Policy, src: Segment, dst: Segment) -> bool:
    # Until topology/path analysis is available, implicit address matches are
    # evaluated only inside the policy-owning device. This prevents an `any`
    # rule on one device from appearing to permit unrelated remote segments.
    src_ok = src.id in policy.src_segments if policy.src_segments else src.device == policy.device and _matches_network(policy.src, src)
    dst_ok = dst.id in policy.dst_segments if policy.dst_segments else dst.device == policy.device and _matches_network(policy.dst, dst)
    return src_ok and dst_ok


def _service_label(policy: Policy) -> str:
    labels: list[str] = []
    for proto in policy.protocol:
        for port in policy.dst_ports:
            if proto in ("ip", "any", "*") and port in ("any", "*"): labels.append("ANY")
            elif port in ("any", "*"): labels.append(proto.upper())
            else: labels.append(f"{proto.upper()}/{port}")
    return ", ".join(dict.fromkeys(labels))


def build_matrix(configs: list[CanonicalConfig]) -> list[MatrixCell]:
    segments = [s for cfg in configs for s in cfg.segments]
    policies = [p for cfg in configs for p in cfg.policies]
    cells: list[MatrixCell] = []
    for src in segments:
        for dst in segments:
            if src.id == dst.id:
                cells.append(MatrixCell(source=src.id, destination=dst.id, result="SAME_SEGMENT")); continue
            matching = [p for p in policies if _applies(p, src, dst)]
            allowed = [_service_label(p) for p in matching if p.action == "permit"]
            denied = [_service_label(p) for p in matching if p.action in ("deny", "reject", "restrict")]
            result = "PARTIAL" if allowed and denied else "ALLOW" if allowed else "DENY" if denied else "UNKNOWN"
            traces = [{"device": p.device, "interface": p.interface, "policy": p.name, "sequence": p.sequence,
                       "action": p.action, "service": _service_label(p), "trace": p.trace.model_dump() if p.trace else None} for p in matching]
            cells.append(MatrixCell(source=src.id, destination=dst.id, result=result, allowed=list(dict.fromkeys(allowed)),
                                    denied=list(dict.fromkeys(denied)), policy_ids=[p.id for p in matching], traces=traces))
    return cells
