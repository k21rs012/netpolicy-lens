"""Path traversal with a separate packet state for each candidate route."""
from __future__ import annotations

import ipaddress
from collections import deque

from .models import CanonicalConfig, Segment
from .nat_pipeline import apply_nat_stage
from .policy_engine import evaluate_device
from .reachability_models import FlowState, HopResult, TopologyData
from .routing import routed_egress
from .topology_graph import segment_node


def _contains(segment: Segment, addresses: tuple[str, ...]) -> bool:
    networks = [ipaddress.ip_network(v, strict=False) for v in segment.networks]
    return bool(addresses) and all(any(ipaddress.ip_network(v).version == n.version
                                      and ipaddress.ip_network(v).subnet_of(n) for n in networks) for v in addresses)


def trace_nat_path(configs: list[CanonicalConfig], source: str, destination: str,
                   flow: FlowState, topology: TopologyData, assume_session: bool) -> dict:
    """Still selects one route; uncertainty is never replaced by a later ALLOW."""
    segments = {s.id: s for c in configs for s in c.segments}
    devices = {c.device.id: c for c in configs}
    adjacent = {s: [] for s in segments}
    for edge in topology.edges:
        if edge.type != "adjacent":
            continue
        left, right = edge.source.removeprefix("segment:"), edge.target.removeprefix("segment:")
        if segments[left].vrf != segments[right].vrf:
            continue
        if flow.current.ip_version and not any(ipaddress.ip_network(n).version == flow.current.ip_version
                                              for n in edge.label.split(", ")):
            continue
        adjacent[left].append(right)
        adjacent[right].append(left)
    queue = deque([(source, flow.current, [segment_node(source)], [], frozenset())])
    failures = []
    explored = set()

    def finish(verdict, packet, path, steps, reason=None):
        return dict(result=verdict, flow=FlowState(original=flow.original, current=packet),
                    path=path, steps=steps, route_reason=reason)

    while queue:
        sid, packet, path, steps, used = queue.popleft()
        identity = (sid, packet.model_dump_json(), used)
        if identity in explored:
            continue
        explored.add(identity)
        if len(explored) > 2048:
            return finish("PARTIAL", packet, path, steps, "NAT経路探索の上限に達しました")
        ingress = segments[sid]
        # A translated destination terminates on its actual subnet, not on the
        # originally selected public/VIP segment. Only after a forwarding hop.
        translated = packet.destination_addresses != flow.original.destination_addresses
        if steps and ((not translated and sid == destination) or (translated and _contains(ingress, packet.destination_addresses))):
            values = {s.result for s in steps}
            verdict = "UNKNOWN" if "UNKNOWN" in values else "PARTIAL" if "PARTIAL" in values else "ALLOW"
            return finish(verdict, packet, path, steps)
        for neighbor in adjacent[sid]:
            if segment_node(neighbor) not in path:
                queue.append((neighbor, packet, [*path, segment_node(neighbor)], steps, used))
        if ingress.device in used:
            continue
        config = devices[ingress.device]
        device_path = [*path, f"device:{config.device.id}"]
        dnat = apply_nat_stage(config, packet, ingress, None, "destination")
        if dnat.blocked:
            reason = dnat.effects[-1].note or "NAT unresolved"
            step = HopResult(device=config.device.id, ingress=sid, egress=sid, result="PARTIAL", reason=reason,
                             nat=dnat.effects, packet_in=packet, packet_out=packet,
                             flow=FlowState(original=flow.original, current=packet))
            failures.append(finish("PARTIAL", packet, device_path, [*steps, step], reason))
            continue
        routed_packet = dnat.packet
        target = segments[destination].model_copy(update={"id": "nat-target", "device": "", "networks": list(routed_packet.destination_addresses)})
        # Keep the existing routing resolver, supplying the translated target.
        # Resolve connected networks by address rather than stale Segment id.
        connected = [s for s in config.segments if s.vrf == ingress.vrf and _contains(s, routed_packet.destination_addresses)]
        # A range split across routing entries needs branch evaluation.
        if any(ipaddress.ip_network(a).version == ipaddress.ip_network(r.destination).version
               and ipaddress.ip_network(r.destination).subnet_of(ipaddress.ip_network(a))
               and ipaddress.ip_network(r.destination) != ipaddress.ip_network(a)
               for a in routed_packet.destination_addresses for r in config.routes if r.vrf == ingress.vrf):
            return finish("PARTIAL", routed_packet, device_path, steps, "宛先範囲に複数の経路条件があります。Destination IPを指定してください")
        allowed, evidence = routed_egress(config, target, ingress, packet.ip_version)
        if connected and not (evidence and "unsupported" in evidence):
            # Explicit more-specific routes (including blackholes) win.
            best_connected = max(ipaddress.ip_network(n).prefixlen for s in connected for n in s.networks
                                 if any(ipaddress.ip_network(a).version == ipaddress.ip_network(n).version
                                        and ipaddress.ip_network(a).subnet_of(ipaddress.ip_network(n)) for a in routed_packet.destination_addresses))
            more_specific = any(r.vrf == ingress.vrf and ipaddress.ip_network(r.destination).prefixlen > best_connected
                                and any(ipaddress.ip_network(a).version == ipaddress.ip_network(r.destination).version
                                        and ipaddress.ip_network(a).subnet_of(ipaddress.ip_network(r.destination)) for a in routed_packet.destination_addresses)
                                for r in config.routes)
            if not more_specific:
                allowed, evidence = {s.id for s in connected}, "connected (current destination)"
        choices = [s for s in config.segments if s.vrf == ingress.vrf and (allowed is None or s.id in allowed)
                   and (s.id != sid or routed_packet.destination_addresses != packet.destination_addresses)]
        if not choices:
            reason = evidence or "変換後の宛先への経路がありません"
            step = HopResult(device=config.device.id, ingress=sid, egress=sid, result="UNKNOWN", reason=reason,
                             route=evidence, nat=dnat.effects, packet_in=packet, packet_out=routed_packet,
                             flow=FlowState(original=flow.original, current=routed_packet))
            failures.append(finish("UNKNOWN" if evidence and ("unsupported" in evidence or "unavailable" in evidence) else "NO_ROUTE",
                                   routed_packet, device_path, [*steps, step], reason))
            continue
        if len(choices) > 1 and allowed is not None:
            return finish("PARTIAL", routed_packet, device_path, steps, "NATを含む複数経路の結果集約は未対応です")
        for egress in choices:
            step = evaluate_device(config, ingress, egress, routed_packet.protocol, routed_packet.destination_port,
                                   routed_packet.state, assume_session, routed_packet.source_port, routed_packet.ip_version,
                                   packet=routed_packet)
            step.flow = FlowState(original=flow.original, current=routed_packet)
            step.packet_in, step.packet_out = packet, routed_packet
            step.route, step.nat = evidence or "connected/inferred", list(dnat.effects)
            next_packet = routed_packet
            next_path = [*device_path, segment_node(egress.id)]
            if step.result == "DENY":
                verdict = "PARTIAL" if any(s.result in {"PARTIAL", "UNKNOWN"} for s in steps) else "DENY"
                failures.append(finish(verdict, routed_packet, next_path, [*steps, step]))
                continue
            snat = apply_nat_stage(config, routed_packet, ingress, egress, "source", step.policy)
            step.nat.extend(snat.effects)
            if snat.blocked:
                step.result, step.reason = "PARTIAL", snat.effects[-1].note or "NAT unresolved"
                failures.append(finish("PARTIAL", routed_packet, next_path, [*steps, step], step.reason))
                continue
            next_packet = snat.packet
            step.packet_out = next_packet
            if any(e.confidence == "PARTIAL" for e in step.nat) and step.result == "ALLOW":
                step.result, step.reason = "PARTIAL", "NATの動的port割り当ては未確定です"
            if allowed is None:
                step.result, step.reason = "UNKNOWN", evidence or "routing evidence unavailable"
            queue.append((egress.id, next_packet, next_path, [*steps, step], used | {config.device.id}))
    if failures:
        # An uncertain branch prevents a definitive denial/no-route claim.
        return min(failures, key=lambda f: {"PARTIAL": 0, "UNKNOWN": 1, "DENY": 2, "NO_ROUTE": 3}[f["result"]])
    return finish("NO_ROUTE", flow.current, [], [], "宛先への経路を確認できません")
