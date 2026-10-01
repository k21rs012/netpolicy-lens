"""Conditioned matrix cells use the same path evaluator as Path trace."""
from __future__ import annotations

from .models import CanonicalConfig, MatrixCell
from .reachability import analyze_reachability
from .topology_graph import build_topology_model

PORT_PROTOCOLS = ("tcp", "udp", "sctp")
SUPPORTED_PROTOCOLS = {*PORT_PROTOCOLS, "icmp", "icmpv6", "gre", "esp", "ah", "ospf", "igmp"}


def normalize_query(protocol: str | None, port: int | None) -> str | None:
    protocol = (protocol or "").strip().lower()
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
) -> list[MatrixCell]:
    """Evaluate whole segment ranges, new connections, and unspecified source ports.

    A port-only query covers TCP, UDP and SCTP separately. Mixed outcomes stay
    PARTIAL; no branch can turn an uncertain result into a blanket ALLOW.
    """
    topology = build_topology_model(configs)
    segments = [s for cfg in configs for s in cfg.segments]
    policies = {p.id: p for cfg in configs for p in cfg.policies}
    protocols = (protocol,) if protocol else PORT_PROTOCOLS
    cells = []
    for src in segments:
        if source is not None and src.id != source:
            continue
        for dst in segments:
            if destination is not None and dst.id != destination:
                continue
            results, reasons, allowed, denied, traces, policy_ids = [], [], [], [], [], []
            for transport in protocols:
                label = f"{transport.upper()}/{port}" if port is not None else f"{transport.upper()}/ANY"
                result = analyze_reachability(configs, src.id, dst.id, transport, port, topology=topology, include_topology=False)
                results.append(result["result"])
                if result["result"] == "ALLOW":
                    allowed.append(label)
                elif result["result"] == "DENY":
                    denied.append(label)
                reason = result["route_reason"] or " / ".join(step["reason"] for step in result["steps"])
                reasons.append(f"{label}: {reason or result['result']}")
                for step in result["steps"]:
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
                        })
            verdict = results[0] if len(set(results)) == 1 else "PARTIAL"
            cells.append(MatrixCell(
                source=src.id, destination=dst.id, result=verdict, evaluation="path",
                query=" + ".join(f"{p.upper()}/{port if port is not None else 'ANY'}" for p in protocols),
                reason="; ".join(reasons), allowed=allowed, denied=denied,
                policy_ids=list(dict.fromkeys(policy_ids)), traces=traces,
            ))
    return cells
