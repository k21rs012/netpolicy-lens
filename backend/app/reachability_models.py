from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field

from .models import Trace


PublicVerdict = Literal["ALLOW", "DENY", "PARTIAL", "UNKNOWN", "NO_ROUTE", "SAME_SEGMENT"]
ChainVerdictValue = Literal["ALLOW", "DENY", "PARTIAL", "UNKNOWN", "RETURN"]


class TopologyNode(BaseModel):
    id: str
    entity_id: str
    type: Literal["device", "segment"]
    label: str
    subtitle: str
    vendor: str | None = None
    network_os: str | None = None
    device: str | None = None
    segment_type: str | None = None


class TopologyEdge(BaseModel):
    id: str
    source: str
    target: str
    type: Literal["owns", "adjacent"]
    label: str
    confidence: Literal["EXACT", "INFERRED"]


class TopologySummary(BaseModel):
    devices: int = 0
    segments: int = 0
    adjacencies: int = 0


class TopologyData(BaseModel):
    nodes: list[TopologyNode] = Field(default_factory=list)
    edges: list[TopologyEdge] = Field(default_factory=list)
    summary: TopologySummary = Field(default_factory=TopologySummary)


class NatEffect(BaseModel):
    name: str
    type: str
    translated_src: str | None = None
    translated_dst: str | None = None
    translated_port: int | None = None
    evaluation_order: str | None = None
    confidence: Literal["EXACT", "PARTIAL"] = "EXACT"
    note: str | None = None
    trace: Trace | None = None


class ChainVerdict(BaseModel):
    result: ChainVerdictValue
    reason: str
    policy: str | None = None
    trace: Trace | None = None
    chain: str | None = None


class HopResult(BaseModel):
    device: str
    ingress: str
    egress: str
    result: Literal["ALLOW", "DENY", "PARTIAL", "UNKNOWN"]
    reason: str
    policy: str | None = None
    trace: Trace | None = None
    chains: list[ChainVerdict] = Field(default_factory=list)
    route: str | None = None
    nat: list[NatEffect] = Field(default_factory=list)


class ReachabilityResult(BaseModel):
    source: str
    destination: str
    protocol: str
    port: int | None = None
    source_port: int | None = None
    ip_version: Literal[4, 6] | None = None
    state: str = "new"
    assume_session: bool = False
    result: PublicVerdict
    path: list[str] = Field(default_factory=list)
    steps: list[HopResult] = Field(default_factory=list)
    route_reason: str | None = None
    topology: TopologyData
