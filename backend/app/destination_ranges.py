"""Bounded CIDR refinement, replaying each partition from the original source.

Replaying is essential: an earlier policy must evaluate the narrowed range too.
Only equal-sized deterministic prefix translations can project a split back
through DNAT. Many-to-one DNAT produces a host and needs no further split.
"""
import ipaddress
from collections import deque

from .models import CanonicalConfig
from .reachability_models import FlowState, PathResult, TopologyData
from .path_results import aggregate_paths
from .routing import active_routes

MAX_REFINEMENTS = 128
MAX_RANGE_PATHS = 128


class DestinationSplit(Exception):
    def __init__(self, ranges: tuple[str, ...]):
        self.ranges = ranges


def refine_destination(config: CanonicalConfig, vrf: str | None,
                       original: tuple[str, ...], current: tuple[str, ...]) -> None:
    if len(original) != 1 or len(current) != 1:
        return
    before, after = (ipaddress.ip_network(values[0]) for values in (original, current))
    if before.version != after.version or before.num_addresses != after.num_addresses:
        return
    boundaries = [r.destination for r in active_routes(config, vrf)]
    # Local interface hosts are opt-in endpoints, not subnet forwarding targets.
    boundaries += [n for s in config.segments if s.vrf == vrf and s.type != "local" for n in s.networks]
    for value in boundaries:
        boundary = ipaddress.ip_network(value, strict=False)
        if boundary.version != after.version or boundary == after or not boundary.subnet_of(after):
            continue
        address_type = ipaddress.IPv4Address if before.version == 4 else ipaddress.IPv6Address
        start = int(before.network_address) + int(boundary.network_address) - int(after.network_address)
        projected = ipaddress.ip_network((address_type(start), boundary.prefixlen))
        pieces = sorted([projected, *before.address_exclude(projected)], key=lambda n: int(n.network_address))
        raise DestinationSplit(tuple(map(str, pieces)))


def trace_destination_ranges(configs: list[CanonicalConfig], source: str, destination: str,
                             flow: FlowState, topology: TopologyData, assume_session: bool, *, context=None) -> dict:
    from .path_traversal import trace_paths

    # Remove overlaps but preserve adjacent host endpoints (especially LOCAL
    # addresses). Merging them could change input/forward route selection.
    networks = sorted({ipaddress.ip_network(v) for v in flow.original.destination_addresses},
                      key=lambda n: (n.prefixlen, int(n.network_address)))
    disjoint = []
    for network in networks:
        if not any(network.subnet_of(existing) for existing in disjoint):
            disjoint.append(network)
    pending = deque(str(n) for n in sorted(disjoint, key=lambda n: int(n.network_address)))
    if not pending:
        return trace_paths(configs, source, destination, flow, topology, assume_session, context=context)
    paths = []
    complete = True
    attempts = 0
    while pending and attempts < MAX_REFINEMENTS and len(paths) < MAX_RANGE_PATHS:
        scope = pending.popleft()
        packet = flow.original.model_copy(update={"destination_addresses": (scope,)})
        narrowed = FlowState(original=packet, current=packet)
        attempts += 1
        try:
            result = trace_paths(configs, source, destination, narrowed, topology, assume_session, context=context)
        except DestinationSplit as split:
            pending.extendleft(reversed(split.ranges))
            continue
        branch_paths = result["paths"]
        available = MAX_RANGE_PATHS - len(paths)
        for path in branch_paths[:available]:
            path.destination_ranges = [scope]
            paths.append(path)
        if not result["paths_complete"]:
            paths.append(PathResult(result="PARTIAL", destination_ranges=[scope],
                                    route_reason="この宛先範囲には未評価の経路候補があります"))
        complete &= result["paths_complete"] and len(branch_paths) <= available
        if len(branch_paths) > available:
            pending.appendleft(scope)
            break
    if pending:
        complete = False
        paths.append(PathResult(result="PARTIAL", destination_ranges=list(pending),
                                route_reason="宛先範囲・経路の探索上限に達したため、この範囲には未評価の候補があります"))
    result = aggregate_paths(paths, complete)
    # The query-level original remains the requested range; each path has its
    # own narrowed original/current pair, including NAT provenance.
    representative = paths[0].flow
    result["flow"] = FlowState(original=flow.original, current=representative.current if representative else flow.current)
    return result
