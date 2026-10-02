"""Bounded, branch-local traversal shared by NAT and ordinary static paths."""
from __future__ import annotations

import ipaddress
from collections import deque

from .models import CanonicalConfig, Segment
from .nat_pipeline import apply_nat_stage, NatStage
from .policy_engine import evaluate_device
from .reachability_models import FlowState, HopResult, TopologyData
from .routing import RouteCandidate, active_routes, route_candidates
from .topology_graph import segment_node

MAX_PATHS = 128
MAX_STATES = 2048
MAX_HOPS = 32


def _contains(segment: Segment, addresses: tuple[str, ...]) -> bool:
    networks = [ipaddress.ip_network(v, strict=False) for v in segment.networks]
    return bool(addresses) and all(any(ipaddress.ip_network(v).version == n.version
                                      and ipaddress.ip_network(v).subnet_of(n) for n in networks) for v in addresses)


def trace_nat_path(configs: list[CanonicalConfig], source: str, destination: str,
                   flow: FlowState, topology: TopologyData, assume_session: bool) -> dict:
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
    # Do not deduplicate converging branches: they can carry different policy
    # history or NAT state even when they share the same segment and packet.
    queue = deque([(source, flow.current, [segment_node(source)], [], frozenset(), False)])
    paths = []
    complete = True
    states = 0

    def finish(verdict, packet, path, steps, reason=None):
        paths.append(dict(result=verdict, flow=FlowState(original=flow.original, current=packet),
                          path=path, steps=steps, route_reason=reason))

    def verdict(steps, uncertain):
        values = {s.result for s in steps}
        return "UNKNOWN" if uncertain or "UNKNOWN" in values else "PARTIAL" if "PARTIAL" in values else "ALLOW"

    def inferred_reaches(start, used):
        # Prune unrelated connected subnets only for topology-inferred routes.
        pending, seen = [start], set()
        while pending:
            sid = pending.pop()
            if sid == destination:
                return True
            if sid in seen:
                continue
            seen.add(sid)
            pending.extend(adjacent[sid])
            segment = segments[sid]
            if segment.device not in used:
                pending.extend(s.id for s in devices[segment.device].segments
                               if s.vrf == segment.vrf and s.type != "local")
        return False

    def peers(egress, gateway):
        neighbors = adjacent[egress.id]
        if not gateway:
            return neighbors, False
        address = ipaddress.ip_address(gateway.partition("%")[0])
        exact, unknown = [], []
        for sid in neighbors:
            ips = [raw for i in devices[segments[sid].device].interfaces if i.segment_id == sid for raw in i.addresses]
            if any(ipaddress.ip_interface(raw).ip == address for raw in ips):
                exact.append(sid)
            elif not ips:
                unknown.append(sid)
        # Missing interface addresses never make a guessed gateway certain.
        return (exact, False) if exact else (unknown, True)

    while queue:
        if len(paths) >= MAX_PATHS or states >= MAX_STATES:
            complete = False
            break
        sid, packet, path, steps, used, uncertain = queue.popleft()
        states += 1
        ingress = segments[sid]
        if steps and sid == destination and packet.destination_addresses == flow.original.destination_addresses:
            finish(verdict(steps, uncertain), packet, path, steps)
            continue
        if ingress.device in used:
            finish("UNKNOWN", packet, path, steps, "経路がループしています")
            continue
        if len(steps) >= MAX_HOPS:
            complete = False
            finish("PARTIAL", packet, path, steps, "経路のhop数上限に達しました")
            continue
        config = devices[ingress.device]
        device_path = [*path, f"device:{config.device.id}"]
        dnat = NatStage(packet) if ingress.type == "local" else apply_nat_stage(config, packet, ingress, None, "destination")
        routed_packet = dnat.packet
        target = segments[destination].model_copy(update={"id": "current-target", "device": "", "networks": list(routed_packet.destination_addresses)})
        if dnat.blocked:
            reason = dnat.effects[-1].note or "NAT unresolved"
            step = HopResult(device=config.device.id, ingress=sid, egress=sid, result="PARTIAL", reason=reason,
                             nat=dnat.effects, packet_in=packet, packet_out=packet,
                             flow=FlowState(original=flow.original, current=packet))
            finish("PARTIAL", packet, device_path, [*steps, step], reason)
            continue
        # ECMP enumerates equal-cost next hops. Address-range partitioning is a
        # separate problem: don't certify an entire subnet using one host.
        if any(ipaddress.ip_network(a).version == ipaddress.ip_network(r.destination).version
               and ipaddress.ip_network(r.destination).subnet_of(ipaddress.ip_network(a))
               and ipaddress.ip_network(r.destination) != ipaddress.ip_network(a)
               for a in routed_packet.destination_addresses for r in active_routes(config, ingress.vrf)):
            finish("PARTIAL", routed_packet, device_path, steps, "宛先範囲に複数の経路条件があります。Destination IPを指定してください")
            continue
        candidates = route_candidates(config, target, ingress, packet.ip_version)
        inferred = candidates is None
        if inferred:
            candidates = [RouteCandidate(s.id, "routing evidence unavailable") for s in config.segments
                          if s.vrf == ingress.vrf and s.id != sid and s.type != "local"
                          and inferred_reaches(s.id, used | {config.device.id})]
        if not candidates:
            finish("NO_ROUTE", routed_packet, device_path, steps, "NO_ROUTE: 宛先への経路を確認できません")
            continue
        for candidate in candidates:
            if len(paths) >= MAX_PATHS:
                complete = False
                break
            if candidate.result:
                if candidate.result == "PARTIAL" and "上限" in candidate.evidence:
                    complete = False
                step = HopResult(device=config.device.id, ingress=sid, egress=sid, result="UNKNOWN", reason=candidate.evidence,
                                 route=candidate.evidence, next_hop=candidate.next_hop, nat=dnat.effects, packet_in=packet,
                                 packet_out=routed_packet, flow=FlowState(original=flow.original, current=routed_packet))
                finish(candidate.result, routed_packet, device_path, [*steps, step], candidate.evidence)
                continue
            egress = segments[candidate.egress]
            step = evaluate_device(config, ingress, egress, routed_packet.protocol, routed_packet.destination_port,
                                   routed_packet.state, assume_session, routed_packet.source_port, routed_packet.ip_version,
                                   packet=routed_packet)
            step.flow = FlowState(original=flow.original, current=routed_packet)
            step.packet_in, step.packet_out = packet, routed_packet
            step.route, step.next_hop, step.nat = candidate.evidence, candidate.next_hop, list(dnat.effects)
            next_path = [*device_path, segment_node(egress.id)]
            next_steps = [*steps, step]
            branch_uncertain = uncertain or inferred
            if step.result == "DENY":
                result = "PARTIAL" if uncertain or any(s.result in {"PARTIAL", "UNKNOWN"} for s in steps) else "DENY"
                finish(result, routed_packet, next_path, next_steps)
                continue
            if egress.type == "local":
                finish(verdict(next_steps, branch_uncertain), routed_packet, next_path, next_steps)
                continue
            snat = apply_nat_stage(config, routed_packet, ingress, egress, "source", step.policy)
            step.nat.extend(snat.effects)
            if snat.blocked:
                step.result, step.reason = "PARTIAL", snat.effects[-1].note or "NAT unresolved"
                finish("PARTIAL", routed_packet, next_path, next_steps, step.reason)
                continue
            next_packet = snat.packet
            step.packet_out = next_packet
            if any(e.confidence == "PARTIAL" for e in step.nat) and step.result == "ALLOW":
                step.result, step.reason = "PARTIAL", "NATの動的port割り当ては未確定です"
            translated = next_packet.destination_addresses != flow.original.destination_addresses
            if (not translated and egress.id == destination) or (translated and not candidate.next_hop and _contains(egress, next_packet.destination_addresses)):
                finish(verdict(next_steps, branch_uncertain), next_packet, next_path, next_steps)
                continue
            # A directly connected destination LAN is already the endpoint;
            # other routers sharing that LAN are not ECMP forwarding options.
            if not candidate.next_hop and destination in adjacent[egress.id] and _contains(egress, next_packet.destination_addresses):
                finish(verdict(next_steps, branch_uncertain), next_packet,
                       [*next_path, segment_node(destination)], next_steps)
                continue
            gateway = candidate.next_hop
            if not gateway and candidate.evidence == "connected" and len(next_packet.destination_addresses) == 1:
                target_network = ipaddress.ip_network(next_packet.destination_addresses[0])
                if target_network.num_addresses == 1 and segments[destination].type == "local":
                    gateway = str(target_network.network_address)
            neighbors, unknown_gateway = peers(egress, gateway)
            if not neighbors:
                finish("UNKNOWN" if gateway else "NO_ROUTE", next_packet, next_path, next_steps,
                       "next-hopに対応する機器を確認できません" if gateway else "NO_ROUTE: 出口から宛先への接続を確認できません")
            for neighbor in neighbors:
                if len(queue) + states >= MAX_STATES:
                    complete = False
                    break
                queue.append((neighbor, next_packet, [*next_path, segment_node(neighbor)], next_steps,
                              used | {config.device.id}, branch_uncertain or unknown_gateway))
    if not paths:
        finish("UNKNOWN" if not complete else "NO_ROUTE", flow.current, [], [], "宛先への経路を確認できません")
    values = {p["result"] for p in paths}
    result = paths[0]["result"] if len(values) == 1 and complete else "PARTIAL"
    # The top-level fields remain a representative path for older consumers.
    # New consumers must use paths for branch evidence and NAT output packets.
    representative = paths[0]
    reason = ("経路探索の上限に達したため、未評価の候補があります" if not complete else
              f"{len(paths)}経路を評価: " + ", ".join(f"{v} {sum(p['result'] == v for p in paths)}" for v in sorted(values))
              if len(paths) > 1 else representative["route_reason"])
    return {**representative, "result": result, "route_reason": reason, "paths": paths, "paths_complete": complete}
