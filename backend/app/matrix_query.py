"""Conditioned matrix cells use the same path evaluator as Path trace."""
from __future__ import annotations

from .models import CanonicalConfig, MatrixCell
from .reachability import analyze_reachability
from .path_results import aggregate_verdicts
from .analysis_context import AnalysisContext

PORT_PROTOCOLS = ("tcp", "udp", "sctp")
SUPPORTED_PROTOCOLS = {*PORT_PROTOCOLS, "icmp", "icmpv6", "gre", "esp", "ah", "ospf", "igmp"}


def normalize_query(protocol: str | None, port: int | None, ip_version: int | None = None) -> str | None:
    protocol = (protocol or "").strip().lower()
    if ip_version not in {None, 4, 6}:
        raise ValueError("ip_version must be 4 or 6")
    if (protocol == "icmp" and ip_version == 6) or (protocol == "icmpv6" and ip_version == 4):
        raise ValueError("ICMP protocol and ip_version must use the same family")
    if protocol in {"", "any", "all", "ip", "*"}:
        return None
    if protocol not in SUPPORTED_PROTOCOLS:
        raise ValueError("Unsupported matrix protocol")
    if port is not None and protocol not in PORT_PROTOCOLS:
        raise ValueError("port requires TCP, UDP or SCTP")
    return protocol


def build_query_matrix(
    configs: list[CanonicalConfig], protocol: str | None, port: int | None,
    source: str | None = None, destination: str | None = None,
    *, ip_version: int | None = None, source_ids: list[str] | None = None, destination_ids: list[str] | None = None,
) -> list[MatrixCell]:
    """Evaluate whole segment ranges, new connections, and unspecified source ports.

    Without a protocol, port/family queries cover TCP, UDP and SCTP separately.
    An explicit family scopes every path evaluation. Mixed outcomes stay
    PARTIAL; no branch can turn an uncertain result into a blanket ALLOW.
    """
    context = AnalysisContext(configs)
    segments = [s for cfg in configs for s in cfg.segments]
    policies = {p.id: p for cfg in configs for p in cfg.policies}
    protocols = (protocol,) if protocol else PORT_PROTOCOLS
    cells = []
    sources = [s for s in segments if (source is None or s.id == source) and (source_ids is None or s.id in source_ids)]
    destinations = [s for s in segments if (destination is None or s.id == destination) and (destination_ids is None or s.id in destination_ids)]
    for src in sources:
        for dst in destinations:
            results, reasons, allowed, denied, traces, policy_ids = [], [], [], [], [], []
            ranges = []
            for transport in protocols:
                label = f"{transport.upper()}/{port}" if port is not None else f"{transport.upper()}/ANY"
                result = analyze_reachability(configs, src.id, dst.id, transport, port, ip_version=ip_version, context=context, include_topology=False)
                results.append(result["result"])
                if result["result"] == "ALLOW":
                    allowed.append(label)
                elif result["result"] == "DENY":
                    denied.append(label)
                reason = result["route_reason"] or " / ".join(step["reason"] for step in result["steps"])
                reasons.append(f"{label}: {reason or result['result']}")
                for index, path in enumerate(result.get("paths") or [result], 1):
                    if path.get("destination_ranges"):
                        ranges.append({"addresses": path["destination_ranges"], "result": path["result"],
                                       "protocol": transport, "path_index": index,
                                       "reason": path.get("route_reason")})
                    for step in path["steps"]:
                        for verdict in step["chains"] or [step]:
                            policy = policies.get(verdict.get("policy"))
                            if policy:
                                policy_ids.append(policy.id)
                            traces.append({
                                "device": step["device"], "interface": policy.interface if policy else None,
                                "policy": policy.name if policy else verdict.get("chain") or "既定動作 / 経路",
                                "sequence": policy.sequence if policy else None,
                                "action": policy.action if policy else "unknown",
                                "service": label, "result": verdict["result"], "reason": verdict["reason"],
                                "route": step["route"], "trace": verdict.get("trace"),
                                "path_index": index, "path_result": path["result"], "next_hop": step.get("next_hop"),
                            })
            verdict = aggregate_verdicts(results)
            cells.append(MatrixCell(
                source=src.id, destination=dst.id, result=verdict, evaluation="path",
                query=(f"IPv{ip_version} / " if ip_version else "") + " + ".join(f"{p.upper()}/{port if port is not None else 'ANY'}" for p in protocols),
                reason="; ".join(reasons), allowed=allowed, denied=denied,
                policy_ids=list(dict.fromkeys(policy_ids)), traces=traces, destination_ranges=ranges,
            ))
    return cells
