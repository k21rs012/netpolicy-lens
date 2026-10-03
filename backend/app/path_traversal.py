"""Bounded, branch-local traversal shared by NAT and ordinary static paths."""
from __future__ import annotations

import ipaddress
from collections import deque
from typing import NamedTuple

from .models import CanonicalConfig
from .nat_pipeline import apply_nat_stage, NatStage
from .policy_engine import evaluate_device
from .reachability_models import FlowState, HopResult, Packet, PathResult, PublicVerdict, TopologyData
from .path_topology import PathTopology, contains
from .path_results import aggregate_paths, path_verdict
from .routing import RouteCandidate, destination_spans_routes, route_candidates
from .topology_graph import segment_node

MAX_PATHS = 128
MAX_STATES = 2048
MAX_HOPS = 32


class TraversalState(NamedTuple):
    segment_id: str
    packet: Packet
    path: list[str]
    steps: list[HopResult]
    used_devices: frozenset[str]
    routing_uncertain: bool


def trace_paths(configs: list[CanonicalConfig], source: str, destination: str,
                flow: FlowState, topology: TopologyData, assume_session: bool) -> dict:
    graph = PathTopology(configs, topology, flow.current.ip_version)
    segments, devices, adjacent = graph.segments, graph.devices, graph.adjacent
    # Do not deduplicate converging branches: they can carry different policy
    # history or NAT state even when they share the same segment and packet.
    queue = deque([TraversalState(source, flow.current, [segment_node(source)], [], frozenset(), False)])
    paths: list[PathResult] = []
    complete = True
    states = 0

    def finish(verdict: PublicVerdict, packet: Packet, path: list[str], steps: list[HopResult], reason: str | None = None):
        paths.append(PathResult(result=verdict, flow=FlowState(original=flow.original, current=packet),
                          path=path, steps=steps, route_reason=reason))

    while queue:
        if len(paths) >= MAX_PATHS or states >= MAX_STATES:
            complete = False
            break
        sid, packet, path, steps, used, uncertain = queue.popleft()
        states += 1
        ingress = segments[sid]
        if steps and not steps[-1].next_hop and sid == destination and packet.destination_addresses == flow.original.destination_addresses:
            finish(path_verdict(steps, uncertain), packet, path, steps)
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
        if destination_spans_routes(config, ingress.vrf, routed_packet.destination_addresses):
            finish("PARTIAL", routed_packet, device_path, steps, "宛先範囲に複数の経路条件があります。Destination IPを指定してください")
            continue
        candidates = route_candidates(config, target, ingress, packet.ip_version)
        inferred = candidates is None
        if inferred:
            candidates = [RouteCandidate(s.id, "routing evidence unavailable") for s in config.segments
                          if s.vrf == ingress.vrf and s.id != sid and s.type != "local"
                          and graph.inferred_reaches(s.id, destination, used | {config.device.id})]
        if not candidates:
            finish("NO_ROUTE", routed_packet, device_path, steps, "NO_ROUTE: 宛先への経路を確認できません")
            continue
        for candidate in candidates:
            if len(paths) >= MAX_PATHS:
                complete = False
                break
            if candidate.result:
                if candidate.truncated:
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
                finish(path_verdict(next_steps, branch_uncertain), routed_packet, next_path, next_steps)
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
            if not candidate.next_hop and ((not translated and egress.id == destination) or (translated and contains(egress, next_packet.destination_addresses))):
                finish(path_verdict(next_steps, branch_uncertain), next_packet, next_path, next_steps)
                continue
            # A directly connected destination LAN is already the endpoint;
            # other routers sharing that LAN are not ECMP forwarding options.
            if not candidate.next_hop and destination in adjacent[egress.id] and contains(egress, next_packet.destination_addresses):
                finish(path_verdict(next_steps, branch_uncertain), next_packet,
                       [*next_path, segment_node(destination)], next_steps)
                continue
            gateway = candidate.next_hop
            if not gateway and candidate.evidence == "connected" and len(next_packet.destination_addresses) == 1:
                target_network = ipaddress.ip_network(next_packet.destination_addresses[0])
                if target_network.num_addresses == 1 and segments[destination].type == "local":
                    gateway = str(target_network.network_address)
            neighbors, unknown_gateway = graph.peers(egress, gateway)
            if not neighbors:
                finish("UNKNOWN" if gateway else "NO_ROUTE", next_packet, next_path, next_steps,
                       "next-hopに対応する機器を確認できません" if gateway else "NO_ROUTE: 出口から宛先への接続を確認できません")
            for neighbor in neighbors:
                if len(queue) + states >= MAX_STATES:
                    complete = False
                    break
                queue.append(TraversalState(neighbor, next_packet, [*next_path, segment_node(neighbor)], next_steps,
                              used | {config.device.id}, branch_uncertain or unknown_gateway))
    if not paths:
        finish("UNKNOWN" if not complete else "NO_ROUTE", flow.current, [], [], "宛先への経路を確認できません")
    return aggregate_paths(paths, complete)
