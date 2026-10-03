"""Snapshot topology and adjacency queries, independent of packet evaluation."""
from __future__ import annotations

import ipaddress

from .models import CanonicalConfig, Segment
from .reachability_models import TopologyData


def contains(segment: Segment, addresses: tuple[str, ...]) -> bool:
    networks = [ipaddress.ip_network(value, strict=False) for value in segment.networks]
    ranges = [ipaddress.ip_network(value) for value in addresses]
    return bool(ranges) and all(
        any(address.version == network.version and address.subnet_of(network) for network in networks)
        for address in ranges
    )


class PathTopology:
    def __init__(self, configs: list[CanonicalConfig], topology: TopologyData, ip_version: int | None):
        segments = {s.id: s for c in configs for s in c.segments}
        devices = {c.device.id: c for c in configs}
        adjacent = {s: [] for s in segments}
        for edge in topology.edges:
            if edge.type != "adjacent":
                continue
            left, right = edge.source.removeprefix("segment:"), edge.target.removeprefix("segment:")
            if segments[left].vrf != segments[right].vrf:
                continue
            if ip_version and not any(
                ipaddress.ip_network(n).version == ip_version for n in edge.label.split(", ")
            ):
                continue
            adjacent[left].append(right)
            adjacent[right].append(left)
        self.segments, self.devices, self.adjacent = segments, devices, adjacent

    def inferred_reaches(self, start: str, destination: str, used: frozenset[str]) -> bool:
        # Prune unrelated connected subnets only for topology-inferred routes.
        pending, seen = [start], set()
        while pending:
            sid = pending.pop()
            if sid == destination:
                return True
            if sid in seen:
                continue
            seen.add(sid)
            pending.extend(self.adjacent[sid])
            segment = self.segments[sid]
            if segment.device not in used:
                pending.extend(s.id for s in self.devices[segment.device].segments
                               if s.vrf == segment.vrf and s.type != "local")
        return False

    def peers(self, egress: Segment, gateway: str | None) -> tuple[list[str], bool]:
        neighbors = self.adjacent[egress.id]
        if not gateway:
            return neighbors, False
        address = ipaddress.ip_address(gateway.partition("%")[0])
        exact, unknown = [], []
        for sid in neighbors:
            ips = [raw for i in self.devices[self.segments[sid].device].interfaces if i.segment_id == sid for raw in i.addresses]
            if any(ipaddress.ip_interface(raw).ip == address for raw in ips):
                exact.append(sid)
            elif not ips:
                unknown.append(sid)
        # Missing interface addresses never make a guessed gateway certain.
        return (exact, False) if exact else (unknown, True)

