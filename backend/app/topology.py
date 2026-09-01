from __future__ import annotations

import ipaddress
from collections import deque
from typing import Any

from .models import CanonicalConfig, Policy, Segment


SERVICE_PORTS = {"http": 80, "https": 443, "ssh": 22, "domain": 53, "dns": 53}


def _segment_node(segment_id: str) -> str: return f"segment:{segment_id}"
def _device_node(device_id: str) -> str: return f"device:{device_id}"


def _overlap(left: Segment, right: Segment) -> list[str]:
    overlaps: list[str] = []
    for first in left.networks:
        for second in right.networks:
            try:
                a, b = ipaddress.ip_network(first, strict=False), ipaddress.ip_network(second, strict=False)
                if a.version == b.version and a.overlaps(b): overlaps.append(str(a if a.prefixlen >= b.prefixlen else b))
            except ValueError:
                pass
    return list(dict.fromkeys(overlaps))


def build_topology(configs: list[CanonicalConfig]) -> dict[str, Any]:
    nodes: list[dict[str, Any]] = []; edges: list[dict[str, Any]] = []
    segments = [segment for config in configs for segment in config.segments]
    for config in configs:
        nodes.append({"id": _device_node(config.device.id), "entity_id": config.device.id, "type": "device",
            "label": config.device.hostname, "subtitle": f"{config.device.vendor} · {config.device.network_os}",
            "vendor": config.device.vendor, "network_os": config.device.network_os})
        for segment in config.segments:
            nodes.append({"id": _segment_node(segment.id), "entity_id": segment.id, "type": "segment",
                "label": segment.name, "subtitle": ", ".join(segment.networks) or segment.type,
                "device": segment.device, "segment_type": segment.type})
            interfaces = [iface.name for iface in config.interfaces if iface.segment_id == segment.id]
            edges.append({"id": f"owns:{config.device.id}:{segment.id}", "source": _device_node(config.device.id),
                "target": _segment_node(segment.id), "type": "owns", "label": ", ".join(interfaces) or "logical",
                "confidence": "EXACT"})
    for index, left in enumerate(segments):
        for right in segments[index + 1:]:
            if left.device == right.device: continue
            if networks := _overlap(left, right):
                edges.append({"id": f"adjacent:{left.id}:{right.id}", "source": _segment_node(left.id),
                    "target": _segment_node(right.id), "type": "adjacent", "label": ", ".join(networks),
                    "confidence": "INFERRED"})
    return {"nodes": nodes, "edges": edges, "summary": {
        "devices": sum(node["type"] == "device" for node in nodes),
        "segments": sum(node["type"] == "segment" for node in nodes),
        "adjacencies": sum(edge["type"] == "adjacent" for edge in edges),
    }}


def _port_matches(values: list[str], port: int | None) -> bool:
    if port is None or any(value.lower() in ("any", "*") for value in values): return True
    for raw in values:
        value = raw.lower().replace("eq ", "").strip()
        if value in SERVICE_PORTS and SERVICE_PORTS[value] == port: return True
        if value.isdigit() and int(value) == port: return True
        if value.startswith("range "): value = value.removeprefix("range ")
        if "-" in value:
            parts = value.split("-")
            if len(parts) == 2 and all(x.isdigit() for x in parts) and int(parts[0]) <= port <= int(parts[1]): return True
    return False


def _packet_matches(policy: Policy, protocol: str, port: int | None) -> bool:
    protocols = {value.lower() for value in policy.protocol}
    protocol_ok = protocol.lower() in protocols or bool(protocols & {"ip", "any", "*"})
    return protocol_ok and _port_matches(policy.dst_ports, port)


def _policy_segment_matches(policy: Policy, ingress: Segment, egress: Segment) -> bool:
    def network_match(values: list[str], segment: Segment) -> bool:
        if any(value.lower() in ("any", "*", "0.0.0.0/0", "::/0") for value in values): return True
        for value in values:
            try:
                policy_net = ipaddress.ip_network(value, strict=False)
                if any(policy_net.overlaps(ipaddress.ip_network(network, strict=False)) for network in segment.networks): return True
            except ValueError: continue
        return False
    src_ok = ingress.id in policy.src_segments if policy.src_segments else network_match(policy.src, ingress)
    dst_ok = egress.id in policy.dst_segments if policy.dst_segments else network_match(policy.dst, egress)
    return src_ok and dst_ok


def _evaluate_device(config: CanonicalConfig, ingress: Segment, egress: Segment, protocol: str, port: int | None) -> dict[str, Any]:
    ingress_ifaces = {iface.name for iface in config.interfaces if iface.segment_id == ingress.id}
    egress_ifaces = {iface.name for iface in config.interfaces if iface.segment_id == egress.id}
    candidates: list[Policy] = []
    for policy in sorted(config.policies, key=lambda value: value.sequence):
        if policy.direction == "in" and policy.interface and policy.interface not in ingress_ifaces: continue
        if policy.direction == "out" and policy.interface and policy.interface not in egress_ifaces: continue
        if _policy_segment_matches(policy, ingress, egress) and _packet_matches(policy, protocol, port): candidates.append(policy)
    policy = candidates[0] if candidates else None
    if not policy:
        return {"device": config.device.id, "ingress": ingress.id, "egress": egress.id, "result": "UNKNOWN",
            "reason": "一致する適用Policyを確認できません", "policy": None, "trace": None}
    result = "ALLOW" if policy.action == "permit" else "DENY" if policy.action in ("deny", "reject", "restrict") else "UNKNOWN"
    return {"device": config.device.id, "ingress": ingress.id, "egress": egress.id, "result": result,
        "reason": f"{policy.name} / Rule {policy.sequence}", "policy": policy.id,
        "trace": policy.trace.model_dump() if policy.trace else None}


def analyze_reachability(configs: list[CanonicalConfig], source: str, destination: str, protocol: str, port: int | None) -> dict[str, Any]:
    topology = build_topology(configs); segment_map = {segment.id: segment for config in configs for segment in config.segments}
    config_map = {config.device.id: config for config in configs}
    if source not in segment_map or destination not in segment_map:
        raise ValueError("Segment not found")
    if source == destination:
        return {"source": source, "destination": destination, "protocol": protocol, "port": port,
            "result": "SAME_SEGMENT", "path": [_segment_node(source)], "steps": [], "topology": topology}
    graph: dict[str, list[str]] = {node["id"]: [] for node in topology["nodes"]}
    for edge in topology["edges"]:
        graph[edge["source"]].append(edge["target"]); graph[edge["target"]].append(edge["source"])
    start, goal = _segment_node(source), _segment_node(destination); queue = deque([start]); previous = {start: None}
    while queue:
        current = queue.popleft()
        if current == goal: break
        for neighbor in graph.get(current, []):
            if neighbor not in previous: previous[neighbor] = current; queue.append(neighbor)
    if goal not in previous:
        return {"source": source, "destination": destination, "protocol": protocol, "port": port,
            "result": "NO_ROUTE", "path": [], "steps": [], "topology": topology}
    path: list[str] = []; current: str | None = goal
    while current is not None: path.append(current); current = previous[current]
    path.reverse(); steps: list[dict[str, Any]] = []
    for index in range(1, len(path) - 1):
        if not path[index].startswith("device:"): continue
        before, after = path[index - 1], path[index + 1]
        if before.startswith("segment:") and after.startswith("segment:"):
            device_id = path[index].removeprefix("device:")
            steps.append(_evaluate_device(config_map[device_id], segment_map[before.removeprefix("segment:")],
                segment_map[after.removeprefix("segment:")], protocol, port))
    results = {step["result"] for step in steps}
    result = "DENY" if "DENY" in results else "UNKNOWN" if "UNKNOWN" in results or not steps else "ALLOW"
    return {"source": source, "destination": destination, "protocol": protocol, "port": port,
        "result": result, "path": path, "steps": steps, "topology": topology}

