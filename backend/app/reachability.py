from __future__ import annotations

import ipaddress

from .flow import create_flow
from .analysis_context import AnalysisContext
from .models import CanonicalConfig
from .destination_ranges import trace_destination_ranges
from .reachability_models import ReachabilityResult, TopologyData
from .topology_graph import build_topology_model, segment_node


def _result(**values) -> dict:
    return ReachabilityResult(**values).model_dump(mode="json")


def analyze_reachability(
    configs: list[CanonicalConfig], source: str, destination: str,
    protocol: str, port: int | None, state: str = "new",
    assume_session: bool = False,
    source_port: int | None = None,
    ip_version: int | None = None,
    source_ip: str | None = None,
    destination_ip: str | None = None,
    icmp_type: int | None = None,
    *, topology: TopologyData | None = None, include_topology: bool = True,
    context: AnalysisContext | None = None,
) -> dict:
    topology = context.topology if context else topology if topology is not None else build_topology_model(configs)
    base = {
        "source": source, "destination": destination, "protocol": protocol,
        "port": port, "source_port": source_port, "ip_version": ip_version, "state": state,
        "assume_session": assume_session,
        "topology": topology if include_topology else TopologyData(),
    }
    segment_map = context.segments if context else {segment.id: segment for config in configs for segment in config.segments}
    config_map = context.devices if context else {config.device.id: config for config in configs}
    if source not in segment_map or destination not in segment_map:
        raise ValueError("Segment not found")
    flow = create_flow(segment_map[source], segment_map[destination], protocol, port,
                       state, source_port, ip_version, source_ip, destination_ip, icmp_type)
    ip_version = flow.current.ip_version
    base.update(flow=flow, ip_version=ip_version, icmp_type=icmp_type)
    if any(segment_map[sid].type == "local" and not addresses for sid, addresses in (
        (source, flow.current.source_addresses), (destination, flow.current.destination_addresses)
    )):
        return _result(**base, result="UNKNOWN", route_reason="機器自身のIPアドレスをconfigから確認できません")
    # An explicit interface IP is host traffic even when its subnet was selected.
    if destination_ip:
        selected = segment_map[destination]
        local = next((s for s in config_map[selected.device].segments
                      if s.type == "local" and s.vrf == selected.vrf
                      and str(ipaddress.ip_network(destination_ip)) in s.networks), None)
        if local:
            destination = local.id
    has_nat = any(not r.disabled for c in configs for r in c.nat)
    if source == destination and segment_map[source].type == "local":
        return _result(**base, result="UNKNOWN", route_reason="機器内のループバック通信は評価対象外です")
    if source == destination and not has_nat:
        return _result(**base, result="SAME_SEGMENT", path=[segment_node(source)])

    families = {ipaddress.ip_network(value).version for value in (
        *flow.current.source_addresses, *flow.current.destination_addresses
    )}
    if ip_version is None and len(families) > 1:
        return _result(**base, result="UNKNOWN", route_reason="複数のIP familyがあります。ip_versionを指定してください")

    traced = trace_destination_ranges(configs, source, destination, flow, topology, assume_session, context=context)
    return _result(**{**base, **traced})
