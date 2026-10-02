from __future__ import annotations

import ipaddress
from dataclasses import dataclass

from .models import CanonicalConfig, Route, Segment


def _destination_addresses(segment: Segment) -> list[ipaddress.IPv4Address | ipaddress.IPv6Address]:
    result: list[ipaddress.IPv4Address | ipaddress.IPv6Address] = []
    for raw in segment.networks:
        try:
            network = ipaddress.ip_network(raw, strict=False)
        except ValueError:
            continue
        result.append(network.network_address if network.num_addresses == 1 else network.network_address + 1)
    return result


def routed_egress(config: CanonicalConfig, destination: Segment, ingress: Segment | None = None,
                  ip_version: int | None = None) -> tuple[set[str] | None, str | None]:
    """Compatibility view; path evaluation uses the lossless candidate list."""
    candidates = route_candidates(config, destination, ingress, ip_version)
    if candidates is None:
        return None, None
    return ({c.egress for c in candidates if c.egress},
            ", ".join(dict.fromkeys(c.evidence for c in candidates)))


@dataclass(frozen=True)
class RouteCandidate:
    egress: str | None
    evidence: str
    next_hop: str | None = None
    result: str | None = None


def active_routes(config: CanonicalConfig, vrf: str | None) -> list[Route]:
    """Expand independent static choices without losing their preferences."""
    entries: list[Route] = []
    for route in config.routes:
        if route.vrf != vrf:
            continue
        if route.options:
            for option in route.options:
                distance = option.metric if option.metric is not None else route.metric if route.metric is not None else 1
                if not option.disabled and distance < 255:
                    entries.append(route.model_copy(update={
                        "next_hop": option.next_hop, "next_hops": [], "interface": option.interface,
                        "metric": distance, "route_type": option.route_type,
                    }))
        else:
            hops = list(dict.fromkeys([*route.next_hops, *([route.next_hop] if route.next_hop else [])]))
            entries.extend(route.model_copy(update={"next_hop": hop, "next_hops": []}) for hop in hops or [None])

    return entries


def route_candidates(config: CanonicalConfig, destination: Segment,
                     ingress: Segment | None, ip_version: int | None) -> list[RouteCandidate] | None:
    vrf = ingress.vrf if ingress else None
    if ingress and any(i.segment_id == ingress.id and i.policy_route_map for i in config.interfaces):
        return [RouteCandidate(None, "PBR configured (unsupported match)", result="UNKNOWN")]
    addresses = _destination_addresses(destination)
    addresses = [a for a in addresses if not ip_version or a.version == ip_version]
    if not addresses:
        return [RouteCandidate(None, "宛先アドレスを確認できません", result="UNKNOWN")]
    entries = active_routes(config, vrf)

    lookups = 0

    def resolve(address, visited=frozenset(), inherited_hop=None):
        nonlocal lookups
        lookups += 1
        if lookups > 2048 or len(visited) >= 64:
            return [RouteCandidate(None, "next-hop探索の上限に達しました", inherited_hop, "PARTIAL")]
        if address in visited:
            return [RouteCandidate(None, "recursive next-hop loop", inherited_hop, "UNKNOWN")]
        visited = visited | {address}
        connected = []
        for segment in config.segments:
            if segment.vrf != vrf:
                continue
            for raw in segment.networks:
                network = ipaddress.ip_network(raw, strict=False)
                if network.version == address.version and address in network and (visited != frozenset({address}) or all(
                    ipaddress.ip_network(raw, strict=False).version != network.version
                    or address not in ipaddress.ip_network(raw, strict=False)
                    or ipaddress.ip_network(raw, strict=False).subnet_of(network)
                    for raw in destination.networks
                )):
                    connected.append((network.prefixlen, segment))
        matching = [(ipaddress.ip_network(r.destination, strict=False).prefixlen, r) for r in entries
                    if ipaddress.ip_network(r.destination, strict=False).version == address.version
                    and address in ipaddress.ip_network(r.destination, strict=False)]
        prefix = max([p for p, _ in connected + matching], default=-1)
        direct = [s for p, s in connected if p == prefix]
        if direct:
            local = [s for s in direct if s.type == "local"]
            if local and inherited_hop:
                return [RouteCandidate(None, "next-hopが機器自身を指しています", inherited_hop, "UNKNOWN")]
            return [RouteCandidate(s.id, "connected", inherited_hop) for s in local or direct]
        best = [r for p, r in matching if p == prefix]
        if not best:
            return [RouteCandidate(None, "next-hopへの経路がありません", inherited_hop, "NO_ROUTE")]
        default_distance = 10 if config.device.network_os == "fortios" else 1
        metric = min(r.metric if r.metric is not None else default_distance for r in best)
        result = []
        for route in best:
            if len(result) >= 128 or lookups > 2048:
                result.append(RouteCandidate(None, "next-hop探索の上限に達しました", result="PARTIAL"))
                break
            if (route.metric if route.metric is not None else default_distance) != metric:
                continue
            if route.route_type != "unicast":
                result.append(RouteCandidate(None, f"{route.destination} ({route.route_type})", inherited_hop, "NO_ROUTE"))
                continue
            hop = route.next_hop
            scope = hop.partition("%")[2] if hop else None
            interface = scope or route.interface
            if interface:
                matches = [i.segment_id for i in config.interfaces if interface in {i.name, i.zone}
                           and i.segment_id and any(s.id == i.segment_id and s.vrf == vrf for s in config.segments)]
                result.extend(RouteCandidate(sid, route.destination, hop or inherited_hop) for sid in dict.fromkeys(matches))
                if not matches:
                    result.append(RouteCandidate(None, f"{route.destination}: 出口Interface不明", hop, "UNKNOWN"))
            elif hop:
                try:
                    resolved = resolve(ipaddress.ip_address(hop.partition("%")[0]), visited, hop)
                    result.extend(RouteCandidate(c.egress, route.destination + (f" / {c.evidence}" if c.result else ""),
                                                 c.next_hop, c.result) for c in resolved)
                except ValueError:
                    result.append(RouteCandidate(None, f"{route.destination}: next-hop不明", hop, "UNKNOWN"))
            else:
                result.append(RouteCandidate(None, f"{route.destination}: 出口不明", result="UNKNOWN"))
        return result

    # Lack of routing configuration can support a topology-only inferred path,
    # but cannot certify forwarding. A configured table with no match cannot.
    resolved = [c for a in addresses for c in resolve(a)]
    if all(c.result == "NO_ROUTE" and c.evidence == "next-hopへの経路がありません" for c in resolved):
        if config.device.features.get("dynamic_routing", False):
            return [RouteCandidate(None, "dynamic routing configured (RIB unavailable)", result="UNKNOWN")]
        if not config.routes:
            return None
    return list(dict.fromkeys(resolved))
