from __future__ import annotations

import ipaddress

from .models import Segment
from .reachability_models import FlowState, Packet


IPNetwork = ipaddress.IPv4Network | ipaddress.IPv6Network
IPAddress = ipaddress.IPv4Address | ipaddress.IPv6Address


class FlowInputError(ValueError):
    """An invalid host selection, distinct from a missing segment."""


def create_flow(
    source: Segment, destination: Segment, protocol: str, port: int | None,
    state: str, source_port: int | None, ip_version: int | None,
    source_ip: str | None = None, destination_ip: str | None = None,
) -> FlowState:
    def networks(segment: Segment) -> list[IPNetwork]:
        values = []
        for raw in segment.networks:
            try:
                values.append(ipaddress.ip_network(raw, strict=False))
            except ValueError:
                continue
        return values

    source_networks, destination_networks = networks(source), networks(destination)
    family = ip_version
    addresses: list[IPAddress | None] = []
    for value, candidates, label in (
        (source_ip, source_networks, "source_ip"),
        (destination_ip, destination_networks, "destination_ip"),
    ):
        if value is None:
            addresses.append(None)
            continue
        try:
            address = ipaddress.ip_address(value)
        except ValueError as exc:
            raise FlowInputError(f"{label} must be an IP address") from exc
        if family is not None and family != address.version:
            raise FlowInputError("IP addresses and ip_version must use the same family")
        family = address.version
        if not any(address.version == network.version and address in network for network in candidates):
            raise FlowInputError(f"{label} must belong to the selected segment")
        addresses.append(address)
    if family is None:
        common = {network.version for network in source_networks} & {
            network.version for network in destination_networks
        }
        if len(common) == 1:
            family = common.pop()

    def scope(candidates: list[IPNetwork], address: IPAddress | None) -> tuple[str, ...]:
        if address is not None:
            return (f"{address}/{address.max_prefixlen}",)
        return tuple(str(network) for network in candidates
                     if family is None or network.version == family)

    packet = Packet(
        source_addresses=scope(source_networks, addresses[0]),
        destination_addresses=scope(destination_networks, addresses[1]),
        protocol=protocol, source_port=source_port, destination_port=port,
        ip_version=family, state=state,
    )
    return FlowState(original=packet, current=packet)
