from __future__ import annotations

import ipaddress
from collections import deque
from typing import Any

from .analyzer import policy_coverage
from .models import CanonicalConfig, Confidence, Policy, Segment


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


def _destination_addresses(segment: Segment) -> list[ipaddress.IPv4Address | ipaddress.IPv6Address]:
    result: list[ipaddress.IPv4Address | ipaddress.IPv6Address] = []
    for raw in segment.networks:
        try:
            network = ipaddress.ip_network(raw, strict=False)
            result.append(network.network_address if network.num_addresses == 1 else network.network_address + 1)
        except ValueError:
            pass
    return result


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
            if candidate.version == network.version and candidate.overlaps(network): return True
        except ValueError:
            pass
    return False


def _nat_effects(config: CanonicalConfig, ingress: Segment, egress: Segment,
                 protocol: str, port: int | None) -> list[dict[str, Any]]:
    effects: list[dict[str, Any]] = []
    objects = {item.name: item.values for item in config.address_objects}
    def matches(value: str, segment: Segment, source: bool) -> bool:
        if value.startswith("interface:"):
            name = value.split(":", 1)[1]
            return any(item.segment_id == segment.id and item.name == name for item in config.interfaces)
        candidates = objects.get(value, [])
        if not candidates:
            candidates = [address for policy in config.policies if policy.name == value
                          for address in (policy.src if source else policy.dst)]
        return any(_value_overlaps_segment(candidate, segment) for candidate in (candidates or [value]))
    for rule in config.nat:
        if rule.protocol.lower() not in {"any", "ip", "*", protocol.lower()}:
            continue
        if rule.original_port is not None and port != rule.original_port:
            continue
        if not matches(rule.original_src, ingress, True):
            continue
        if not matches(rule.original_dst, egress, False):
            continue
        effects.append({"name": rule.name, "type": rule.type,
                        "translated_src": rule.translated_src, "translated_dst": rule.translated_dst,
                        "translated_port": rule.translated_port,
                        "trace": rule.trace.model_dump() if rule.trace else None})
    return effects


def _routed_egress(config: CanonicalConfig, destination: Segment,
                   ingress: Segment | None = None) -> tuple[set[str] | None, str | None]:
    """Resolve egress segments using connected and longest-prefix routes.

    None means the uploaded config has no usable routing evidence, so callers
    retain inferred topology behavior instead of claiming NO_ROUTE from an
    incomplete dynamic-routing snapshot.
    """
    attached = {segment.id: segment for segment in config.segments}
    source_vrf = ingress.vrf if ingress else None
    ingress_interfaces = [item for item in config.interfaces if ingress and item.segment_id == ingress.id]
    if any(item.policy_route_map for item in ingress_interfaces):
        return set(), "PBR configured (unsupported match)"
    if destination.device == config.device.id and destination.vrf == source_vrf:
        return {destination.id}, "connected"
    addresses = _destination_addresses(destination)
    parsed_routes: list[tuple[int, Any]] = []
    for route in config.routes:
        if route.vrf != source_vrf:
            continue
        try:
            network = ipaddress.ip_network(route.destination, strict=False)
        except ValueError:
            continue
        if any(address.version == network.version and address in network for address in addresses):
            parsed_routes.append((network.prefixlen, route))
    if not config.routes or not addresses:
        return None, None
    if not parsed_routes:
        if config.device.features.get("dynamic_routing", False):
            return None, "dynamic routing configured (RIB unavailable)"
        return set(), None
    best_prefix = max(prefix for prefix, _ in parsed_routes)
    best = [route for prefix, route in parsed_routes if prefix == best_prefix]
    best_metric = min(route.metric if route.metric is not None else 0 for route in best)
    best = [route for route in best if (route.metric if route.metric is not None else 0) == best_metric]
    selected: set[str] = set()
    for route in best:
        if route.interface:
            for interface in config.interfaces:
                if route.interface in {interface.name, interface.zone} and interface.segment_id:
                    selected.add(interface.segment_id)
        if route.next_hop:
            try:
                next_hop = ipaddress.ip_address(route.next_hop.split("%", 1)[0])
            except ValueError:
                continue
            for segment in attached.values():
                if segment.vrf != source_vrf: continue
                for raw in segment.networks:
                    try:
                        network = ipaddress.ip_network(raw, strict=False)
                        if next_hop.version == network.version and next_hop in network:
                            selected.add(segment.id)
                    except ValueError:
                        pass
    return selected, ", ".join(route.destination for route in best)


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
        if value.startswith("lt ") and value[3:].isdigit() and port < int(value[3:]): return True
        if value.startswith("gt ") and value[3:].isdigit() and port > int(value[3:]): return True
        if value.startswith("neq ") and value[5:].isdigit() and port != int(value[5:]): return True
        if value.startswith("range "): value = value.removeprefix("range ")
        if "-" in value:
            parts = value.split("-")
            if len(parts) == 2 and all(x.isdigit() for x in parts) and int(parts[0]) <= port <= int(parts[1]): return True
    return False


def _packet_matches(policy: Policy, protocol: str, port: int | None) -> bool:
    protocols = {value.lower() for value in policy.protocol}
    protocol_ok = protocol.lower() in protocols or bool(protocols & {"ip", "any", "*"})
    return protocol_ok and _port_matches(policy.dst_ports, port)


def _resolved_policy(config: CanonicalConfig, policy: Policy) -> Policy:
    objects = {item.name: item.values for item in config.address_objects}
    def resolve(values: list[str], seen: set[str] | None = None) -> list[str]:
        seen = set() if seen is None else seen; result: list[str] = []
        for value in values:
            if value in objects and value not in seen:
                result.extend(resolve(objects[value], seen | {value}))
            else:
                result.append(value)
        return list(dict.fromkeys(result))
    return policy.model_copy(update={"src": resolve(policy.src), "dst": resolve(policy.dst)})


def _chain_key(policy: Policy) -> tuple[str, ...]:
    if policy.chain_id:
        return policy.device, policy.chain_id
    if policy.direction == "zone":
        return policy.device, "zone", policy.from_zone or "", policy.to_zone or ""
    if policy.direction in {"forward", "global"}:
        return policy.device, policy.direction
    return policy.device, policy.direction, policy.interface or "", policy.name


def _policy_order(policy: Policy) -> int:
    return policy.order if policy.order is not None else policy.sequence


def _applicable(policy: Policy, config: CanonicalConfig, ingress: Segment, egress: Segment,
                ingress_ifaces: set[str], egress_ifaces: set[str]) -> bool:
    if not policy.enabled:
        return False
    # Definition-only ACLs are not forwarding policy.  Keep globally-scoped
    # firewall rules explicit with direction=forward/global.
    if policy.direction == "unknown" and config.device.network_os in {
        "ios", "ios-xe", "nx-os", "aos-cx", "eos", "alliedware-plus",
        "rtx", "exos", "voss",
    }:
        return False
    if policy.direction == "in" and policy.interface and policy.interface not in ingress_ifaces and ingress.id not in policy.src_segments:
        return False
    if policy.direction == "out" and policy.interface and policy.interface not in egress_ifaces and egress.id not in policy.dst_segments:
        return False
    if policy.direction == "zone":
        if policy.src_segments and ingress.id not in policy.src_segments:
            return False
        if policy.dst_segments and egress.id not in policy.dst_segments:
            return False
        if policy.from_zone and not policy.src_segments and policy.from_zone not in ingress_ifaces:
            return False
        if policy.to_zone and not policy.dst_segments and policy.to_zone not in egress_ifaces:
            return False
    if policy.in_interfaces and not ingress_ifaces.intersection(policy.in_interfaces):
        return False
    if policy.out_interfaces and not egress_ifaces.intersection(policy.out_interfaces):
        return False
    return True


def _chain_default(config: CanonicalConfig, rules: list[Policy]) -> str:
    explicit = next((rule.default_action for rule in rules if rule.default_action), None)
    if explicit:
        return "ALLOW" if explicit == "permit" else "DENY" if explicit in {"deny", "reject"} else "UNKNOWN"
    direction = rules[0].direction
    # Applied ACLs and zone policies have an implicit deny. RouterOS/VyOS
    # forwarding base chains default to accept unless configured otherwise.
    if direction in {"in", "out", "zone", "global"}:
        return "DENY"
    if direction == "forward" and config.device.network_os in {"routeros", "vyos"}:
        return "ALLOW"
    return "UNKNOWN"


def _evaluate_chain(config: CanonicalConfig, rules: list[Policy], ingress: Segment, egress: Segment,
                    protocol: str, port: int | None, state: str, all_chains: dict[tuple[str, ...], list[Policy]],
                    visited: set[tuple[str, ...]] | None = None) -> dict[str, Any]:
    rules = sorted(rules, key=_policy_order)
    key = _chain_key(rules[0]); visited = set() if visited is None else visited
    if key in visited:
        return {"result": "UNKNOWN", "reason": "Policy chain loop", "policy": None, "trace": None}
    visited.add(key)
    for policy in rules:
        if policy.states and not ({state.lower(), "any"} & {value.lower() for value in policy.states}):
            continue
        resolved = _resolved_policy(config, policy)
        coverage = policy_coverage(resolved, ingress, egress)
        if coverage == "NONE" or not _packet_matches(resolved, protocol, port):
            continue
        suffix = "（Segmentの一部に一致）" if coverage == "PARTIAL" else ""
        if coverage == "PARTIAL" or policy.confidence != Confidence.EXACT:
            result = "PARTIAL"
        elif policy.action == "permit":
            result = "ALLOW"
        elif policy.action in {"deny", "reject", "restrict"}:
            result = "DENY"
        elif policy.action == "return":
            return {"result": "RETURN", "reason": f"{policy.name} / Rule {policy.sequence}",
                    "policy": policy.id, "trace": policy.trace.model_dump() if policy.trace else None,
                    "chain": key[-1]}
        elif policy.action == "continue" or not policy.terminal:
            continue
        elif policy.action == "jump" and policy.jump_target:
            target = next((candidate for candidate in all_chains
                           if candidate[-1] == policy.jump_target or candidate[-1].endswith(f":{policy.jump_target}")), None)
            if target:
                jumped = _evaluate_chain(config, all_chains[target], ingress, egress, protocol, port, state,
                                         all_chains, visited.copy())
                if jumped["result"] == "RETURN": continue
                return jumped
            result = "UNKNOWN"
        else:
            result = "UNKNOWN"
        return {"result": result, "reason": f"{policy.name} / Rule {policy.sequence}{suffix}",
                "policy": policy.id, "trace": policy.trace.model_dump() if policy.trace else None,
                "chain": key[-1]}
    if config.device.network_os == "routeros" and not any(rule.entrypoint for rule in rules):
        return {"result": "RETURN", "reason": "custom chain end", "policy": None,
                "trace": None, "chain": key[-1]}
    default = _chain_default(config, rules)
    return {"result": default, "reason": "適用Policyの暗黙deny" if default == "DENY" else
            "Policy chainの既定permit" if default == "ALLOW" else "一致するPolicyを確認できません",
            "policy": None, "trace": None, "chain": key[-1]}


def _evaluate_device(config: CanonicalConfig, ingress: Segment, egress: Segment, protocol: str,
                     port: int | None, state: str = "new") -> dict[str, Any]:
    if state in {"established", "related"} and config.device.network_os in {"srx", "fortios", "panos", "asa", "ftd"}:
        return {"device": config.device.id, "ingress": ingress.id, "egress": egress.id,
                "result": "ALLOW", "reason": "stateful session", "policy": None, "trace": None,
                "chains": []}
    ingress_ifaces = {value for iface in config.interfaces if iface.segment_id == ingress.id for value in (iface.name, iface.zone) if value}
    egress_ifaces = {value for iface in config.interfaces if iface.segment_id == egress.id for value in (iface.name, iface.zone) if value}
    chains: dict[tuple[str, ...], list[Policy]] = {}
    for policy in config.policies:
        if _applicable(policy, config, ingress, egress, ingress_ifaces, egress_ifaces):
            chains.setdefault(_chain_key(policy), []).append(policy)
    entry_chains = {key: rules for key, rules in chains.items() if any(rule.entrypoint for rule in rules)}
    if not entry_chains:
        # ASA permits higher-security to lower-security traffic without an ACL,
        # while lower-to-higher and same-security traffic are denied by default.
        if config.device.network_os in {"asa", "ftd"}:
            source = next((i for i in config.interfaces if i.segment_id == ingress.id), None)
            target = next((i for i in config.interfaces if i.segment_id == egress.id), None)
            if source and target and source.security_level is not None and target.security_level is not None:
                same = source.security_level == target.security_level
                allowed = source.security_level > target.security_level or (
                    same and config.device.features.get("same_security_inter_interface", False))
                return {"device": config.device.id, "ingress": ingress.id, "egress": egress.id,
                        "result": "ALLOW" if allowed else "DENY", "reason": "ASA security-level既定動作",
                        "policy": None, "trace": None, "chains": []}
        firewall_default_deny = config.device.network_os in {"srx", "fortios", "panos"}
        return {"device": config.device.id, "ingress": ingress.id, "egress": egress.id,
                "result": "DENY" if firewall_default_deny else "UNKNOWN",
                "reason": "適用Policyの暗黙deny" if firewall_default_deny else "一致する適用Policyを確認できません",
                "policy": None, "trace": None, "chains": []}
    verdicts = [_evaluate_chain(config, rules, ingress, egress, protocol, port, state, chains)
                for rules in entry_chains.values()]
    values = {item["result"] for item in verdicts}
    result = "DENY" if "DENY" in values else "PARTIAL" if "PARTIAL" in values else \
        "UNKNOWN" if "UNKNOWN" in values else "ALLOW"
    decisive = next((item for item in verdicts if item["result"] == result), verdicts[0])
    return {"device": config.device.id, "ingress": ingress.id, "egress": egress.id,
            "result": result, "reason": decisive["reason"], "policy": decisive["policy"],
            "trace": decisive["trace"], "chains": verdicts}


def analyze_reachability(configs: list[CanonicalConfig], source: str, destination: str, protocol: str,
                         port: int | None, state: str = "new") -> dict[str, Any]:
    topology = build_topology(configs); segment_map = {segment.id: segment for config in configs for segment in config.segments}
    config_map = {config.device.id: config for config in configs}
    if source not in segment_map or destination not in segment_map:
        raise ValueError("Segment not found")
    if source == destination:
        return {"source": source, "destination": destination, "protocol": protocol, "port": port,
            "state": state, "result": "SAME_SEGMENT", "path": [_segment_node(source)], "steps": [], "topology": topology}
    graph: dict[str, list[str]] = {node["id"]: [] for node in topology["nodes"]}
    for edge in topology["edges"]:
        graph[edge["source"]].append(edge["target"]); graph[edge["target"]].append(edge["source"])
    start, goal = _segment_node(source), _segment_node(destination); queue = deque([start]); previous = {start: None}
    route_evidence: dict[str, str | None] = {}
    while queue:
        current = queue.popleft()
        if current == goal: break
        neighbors = graph.get(current, [])
        if current.startswith("device:"):
            device_id = current.removeprefix("device:")
            incoming = previous.get(current)
            ingress_segment = segment_map.get(incoming.removeprefix("segment:")) if incoming and incoming.startswith("segment:") else None
            allowed, evidence = _routed_egress(config_map[device_id], segment_map[destination], ingress_segment)
            route_evidence[device_id] = evidence
            if allowed is not None:
                neighbors = [neighbor for neighbor in neighbors
                             if not neighbor.startswith("segment:") or neighbor.removeprefix("segment:") in allowed]
        for neighbor in neighbors:
            if neighbor not in previous: previous[neighbor] = current; queue.append(neighbor)
    if goal not in previous:
        uncertain_route = next((value for value in route_evidence.values()
                                if value and ("unavailable" in value or "unsupported" in value)), None)
        return {"source": source, "destination": destination, "protocol": protocol, "port": port,
            "state": state, "result": "UNKNOWN" if uncertain_route else "NO_ROUTE", "path": [], "steps": [],
            "route_reason": uncertain_route, "topology": topology}
    path: list[str] = []; current: str | None = goal
    while current is not None: path.append(current); current = previous[current]
    path.reverse(); steps: list[dict[str, Any]] = []
    for index in range(1, len(path) - 1):
        if not path[index].startswith("device:"): continue
        before, after = path[index - 1], path[index + 1]
        if before.startswith("segment:") and after.startswith("segment:"):
            device_id = path[index].removeprefix("device:")
            step = _evaluate_device(config_map[device_id], segment_map[before.removeprefix("segment:")],
                segment_map[after.removeprefix("segment:")], protocol, port, state)
            step["route"] = route_evidence.get(device_id) or "connected/inferred"
            step["nat"] = _nat_effects(config_map[device_id], segment_map[before.removeprefix("segment:")],
                                       segment_map[after.removeprefix("segment:")], protocol, port)
            steps.append(step)
    results = {step["result"] for step in steps}
    result = "DENY" if "DENY" in results else "UNKNOWN" if "UNKNOWN" in results or not steps else "PARTIAL" if "PARTIAL" in results else "ALLOW"
    return {"source": source, "destination": destination, "protocol": protocol, "port": port, "state": state,
        "result": result, "path": path, "steps": steps, "topology": topology}
