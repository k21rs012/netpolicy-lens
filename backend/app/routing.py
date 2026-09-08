from __future__ import annotations

import ipaddress

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


def routed_egress(
    config: CanonicalConfig,
    destination: Segment,
    ingress: Segment | None = None,
    ip_version: int | None = None,
) -> tuple[set[str] | None, str | None]:
    """Resolve egress segments using connected and longest-prefix routes.

    ``None`` means the config has insufficient routing evidence. Callers may
    retain inferred topology behavior but must not turn that uncertainty into
    a definitive NO_ROUTE.
    """
    attached = {segment.id: segment for segment in config.segments}
    source_vrf = ingress.vrf if ingress else None
    ingress_interfaces = [item for item in config.interfaces if ingress and item.segment_id == ingress.id]
    if any(item.policy_route_map for item in ingress_interfaces):
        return set(), "PBR configured (unsupported match)"
    addresses = _destination_addresses(destination)
    if ip_version:
        addresses = [address for address in addresses if address.version == ip_version]
        if not addresses:
            return set(), f"destinationにIPv{ip_version} networkがありません"
    if destination.device == config.device.id and destination.vrf == source_vrf:
        return {destination.id}, "connected"

    def best_routes(address: ipaddress.IPv4Address | ipaddress.IPv6Address) -> list[Route]:
        candidates: list[tuple[int, Route]] = []
        for route in config.routes:
            if route.vrf != source_vrf:
                continue
            try:
                network = ipaddress.ip_network(route.destination, strict=False)
            except ValueError:
                continue
            if address.version == network.version and address in network:
                candidates.append((network.prefixlen, route))
        if not candidates:
            return []
        prefix = max(item[0] for item in candidates)
        routes = [route for length, route in candidates if length == prefix]
        metric = min(route.metric if route.metric is not None else 0 for route in routes)
        return [route for route in routes if (route.metric if route.metric is not None else 0) == metric]

    parsed_routes = [route for address in addresses for route in best_routes(address)]
    if not config.routes or not addresses:
        return None, None
    if not parsed_routes:
        if config.device.features.get("dynamic_routing", False):
            return None, "dynamic routing configured (RIB unavailable)"
        return set(), None

    selected: set[str] = set()
    terminal_routes: list[str] = []

    def resolve(route: Route, visited: set[tuple[str, str | None]]) -> None:
        identity = route.destination, route.vrf
        if identity in visited:
            return
        visited.add(identity)
        if route.route_type != "unicast":
            terminal_routes.append(f"{route.destination} ({route.route_type})")
            return
        if route.interface:
            for interface in config.interfaces:
                if route.interface in {interface.name, interface.zone} and interface.segment_id:
                    selected.add(interface.segment_id)
        hops = list(dict.fromkeys([*route.next_hops, *([route.next_hop] if route.next_hop else [])]))
        for raw_hop in hops:
            address_text, _, scope = raw_hop.partition("%")
            if scope:
                for interface in config.interfaces:
                    if interface.name == scope and interface.segment_id:
                        selected.add(interface.segment_id)
            try:
                next_hop = ipaddress.ip_address(address_text)
            except ValueError:
                continue
            directly_attached = False
            for segment in attached.values():
                if segment.vrf != source_vrf:
                    continue
                for raw in segment.networks:
                    try:
                        network = ipaddress.ip_network(raw, strict=False)
                    except ValueError:
                        continue
                    if next_hop.version == network.version and next_hop in network:
                        selected.add(segment.id)
                        directly_attached = True
            if not directly_attached:
                for recursive in best_routes(next_hop):
                    resolve(recursive, visited.copy())

    for route in parsed_routes:
        resolve(route, set())
    evidence = ", ".join(dict.fromkeys(
        [route.destination for route in parsed_routes] + terminal_routes
    ))
    return selected, evidence
