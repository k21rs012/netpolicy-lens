from __future__ import annotations

import ipaddress

from .models import CanonicalConfig, Segment
from .reachability_models import TopologyData, TopologyEdge, TopologyNode, TopologySummary


def segment_node(segment_id: str) -> str:
    return f"segment:{segment_id}"


def device_node(device_id: str) -> str:
    return f"device:{device_id}"


def _overlap(left: Segment, right: Segment) -> list[str]:
    overlaps: list[str] = []
    for first in left.networks:
        for second in right.networks:
            try:
                left_network = ipaddress.ip_network(first, strict=False)
                right_network = ipaddress.ip_network(second, strict=False)
            except ValueError:
                continue
            if left_network.version == right_network.version and left_network.overlaps(right_network):
                most_specific = left_network if left_network.prefixlen >= right_network.prefixlen else right_network
                overlaps.append(str(most_specific))
    return list(dict.fromkeys(overlaps))


def build_topology_model(configs: list[CanonicalConfig]) -> TopologyData:
    nodes: list[TopologyNode] = []
    edges: list[TopologyEdge] = []
    segments = [segment for config in configs for segment in config.segments]
    for config in configs:
        nodes.append(TopologyNode(
            id=device_node(config.device.id), entity_id=config.device.id,
            type="device", label=config.device.hostname,
            subtitle=f"{config.device.vendor} · {config.device.network_os}",
            vendor=config.device.vendor, network_os=config.device.network_os,
        ))
        for segment in config.segments:
            nodes.append(TopologyNode(
                id=segment_node(segment.id), entity_id=segment.id,
                type="segment", label=segment.name,
                subtitle=", ".join(segment.networks) or segment.type,
                device=segment.device, segment_type=segment.type,
            ))
            interfaces = [iface.name for iface in config.interfaces if iface.segment_id == segment.id]
            edges.append(TopologyEdge(
                id=f"owns:{config.device.id}:{segment.id}",
                source=device_node(config.device.id), target=segment_node(segment.id),
                type="owns", label=", ".join(interfaces) or "logical", confidence="EXACT",
            ))
    for index, left in enumerate(segments):
        for right in segments[index + 1:]:
            if left.device == right.device:
                continue
            networks = _overlap(left, right)
            if networks:
                edges.append(TopologyEdge(
                    id=f"adjacent:{left.id}:{right.id}",
                    source=segment_node(left.id), target=segment_node(right.id),
                    type="adjacent", label=", ".join(networks), confidence="INFERRED",
                ))
    return TopologyData(
        nodes=nodes,
        edges=edges,
        summary=TopologySummary(
            devices=sum(node.type == "device" for node in nodes),
            segments=sum(node.type == "segment" for node in nodes),
            adjacencies=sum(edge.type == "adjacent" for edge in edges),
        ),
    )


def build_topology(configs: list[CanonicalConfig]) -> dict:
    return build_topology_model(configs).model_dump()
