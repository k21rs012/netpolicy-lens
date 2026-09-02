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
    if destination.device == config.device.id and destination.vrf == source_vrf:
        return {destination.id}, "connected"

    addresses = _destination_addresses(destination)
    parsed_routes: list[tuple[int, Route]] = []
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
        if not route.next_hop:
            continue
        try:
            next_hop = ipaddress.ip_address(route.next_hop.split("%", 1)[0])
        except ValueError:
            continue
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
    return selected, ", ".join(route.destination for route in best)
