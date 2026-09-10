from __future__ import annotations

import ipaddress
from collections import deque

from .flow import create_flow
from .models import CanonicalConfig
from .nat import nat_effects
from .policy_engine import evaluate_device
from .reachability_models import ReachabilityResult
from .routing import routed_egress
from .topology_graph import build_topology_model, segment_node


def _result(**values) -> dict:
    return ReachabilityResult(**values).model_dump(mode="json")


def analyze_reachability(
    configs: list[CanonicalConfig], source: str, destination: str,
    protocol: str, port: int | None, state: str = "new",
    assume_session: bool = False,
    source_port: int | None = None,
    ip_version: int | None = None,
    source_ip: str | None = None,
    destination_ip: str | None = None,
) -> dict:
    topology = build_topology_model(configs)
    base = {
        "source": source, "destination": destination, "protocol": protocol,
        "port": port, "source_port": source_port, "ip_version": ip_version, "state": state,
        "assume_session": assume_session,
        "topology": topology,
    }
    segment_map = {segment.id: segment for config in configs for segment in config.segments}
    config_map = {config.device.id: config for config in configs}
    if source not in segment_map or destination not in segment_map:
        raise ValueError("Segment not found")
    flow = create_flow(segment_map[source], segment_map[destination], protocol, port,
                       state, source_port, ip_version, source_ip, destination_ip)
    ip_version = flow.current.ip_version
    base.update(flow=flow, ip_version=ip_version)
    route_destination = segment_map[destination].model_copy(
        update={"networks": list(flow.current.destination_addresses)}
    )
    if source == destination:
        return _result(**base, result="SAME_SEGMENT", path=[segment_node(source)])

    families = {ipaddress.ip_network(value).version for value in (
        *flow.current.source_addresses, *flow.current.destination_addresses
    )}
    if ip_version is None and len(families) > 1:
        return _result(**base, result="UNKNOWN", route_reason="複数のIP familyがあります。ip_versionを指定してください")

    graph: dict[str, list[str]] = {node.id: [] for node in topology.nodes}
    for edge in topology.edges:
        if edge.type == "adjacent" and ip_version and not any(
            ipaddress.ip_network(network).version == ip_version
            for network in edge.label.split(", ")
        ):
            continue
        graph[edge.source].append(edge.target)
        graph[edge.target].append(edge.source)
    start, goal = segment_node(source), segment_node(destination)
    queue = deque([start])
    previous: dict[str, str | None] = {start: None}
    route_evidence: dict[str, str | None] = {}
    while queue:
        current = queue.popleft()
        if current == goal:
            break
        neighbors = graph.get(current, [])
        if current.startswith("device:"):
            device_id = current.removeprefix("device:")
            incoming = previous.get(current)
            ingress_segment = (
                segment_map.get(incoming.removeprefix("segment:"))
                if incoming and incoming.startswith("segment:") else None
            )
            allowed, evidence = routed_egress(
                config_map[device_id], route_destination, ingress_segment,
                ip_version,
            )
            route_evidence[device_id] = evidence
            if allowed is not None:
                neighbors = [neighbor for neighbor in neighbors
                             if not neighbor.startswith("segment:")
                             or neighbor.removeprefix("segment:") in allowed]
        for neighbor in neighbors:
            if neighbor not in previous:
                previous[neighbor] = current
                queue.append(neighbor)
    if goal not in previous:
        uncertain_route = next((value for value in route_evidence.values()
                                if value and ("unavailable" in value or "unsupported" in value)), None)
        return _result(
            **base, result="UNKNOWN" if uncertain_route else "NO_ROUTE",
            route_reason=uncertain_route,
        )

    path: list[str] = []
    current: str | None = goal
    while current is not None:
        path.append(current)
        current = previous[current]
    path.reverse()
    steps = []
    for index in range(1, len(path) - 1):
        if not path[index].startswith("device:"):
            continue
        before, after = path[index - 1], path[index + 1]
        if not before.startswith("segment:") or not after.startswith("segment:"):
            continue
        device_id = path[index].removeprefix("device:")
        ingress = segment_map[before.removeprefix("segment:")]
        egress = segment_map[after.removeprefix("segment:")]
        step = evaluate_device(
            config_map[device_id], ingress, egress, protocol, port,
            state, assume_session, source_port, ip_version, packet=flow.current,
        )
        step.flow = flow
        step.route = route_evidence.get(device_id) or "connected/inferred"
        step.nat = nat_effects(
            config_map[device_id], ingress, egress, protocol, port, source_port,
            ip_version, packet=flow.current,
        )
        steps.append(step)
    values = {step.result for step in steps}
    result = (
        "DENY" if "DENY" in values else
        "UNKNOWN" if "UNKNOWN" in values or not steps else
        "PARTIAL" if "PARTIAL" in values else
        "ALLOW"
    )
    return _result(**base, result=result, path=path, steps=steps)
