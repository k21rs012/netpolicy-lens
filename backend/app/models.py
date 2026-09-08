from __future__ import annotations

from enum import Enum
from typing import Any, Literal

from pydantic import BaseModel, Field


class Confidence(str, Enum):
    EXACT = "EXACT"
    INFERRED = "INFERRED"
    PARTIAL = "PARTIAL"
    UNKNOWN = "UNKNOWN"


class Trace(BaseModel):
    source_file: str = "uploaded.conf"
    line_start: int = 0
    line_end: int = 0
    raw_config: str = ""


class Device(BaseModel):
    id: str
    hostname: str
    vendor: str
    network_os: str
    platform: str | None = None
    source_file: str
    site: str | None = None
    confidence: float = 0.0
    features: dict[str, bool] = Field(default_factory=dict)


class Interface(BaseModel):
    device: str
    name: str
    description: str | None = None
    addresses: list[str] = Field(default_factory=list)
    vlan_id: int | None = None
    trunk_vlans: list[int] = Field(default_factory=list)
    zone: str | None = None
    segment_id: str | None = None
    acl_in: list[str] = Field(default_factory=list)
    acl_out: list[str] = Field(default_factory=list)
    security_level: int | None = None
    vrf: str | None = None
    policy_route_map: str | None = None
    trace: Trace | None = None


class VLAN(BaseModel):
    device: str
    id: int
    name: str
    subnets: list[str] = Field(default_factory=list)
    gateway: str | None = None
    trace: Trace | None = None


class Segment(BaseModel):
    id: str
    name: str
    type: Literal["zone", "vlan", "interface", "subnet", "logical"]
    device: str
    vlan_id: int | None = None
    networks: list[str] = Field(default_factory=list)
    vrf: str | None = None


class Zone(BaseModel):
    device: str
    name: str
    interfaces: list[str] = Field(default_factory=list)
    segment_id: str
    trace: Trace | None = None


class Route(BaseModel):
    device: str
    destination: str
    next_hop: str | None = None
    next_hops: list[str] = Field(default_factory=list)
    interface: str | None = None
    metric: int | None = None
    vrf: str | None = None
    policy: str | None = None
    route_type: Literal["unicast", "blackhole", "reject", "unreachable"] = "unicast"
    trace: Trace | None = None


class Policy(BaseModel):
    id: str
    device: str
    name: str
    sequence: int
    src: list[str] = Field(default_factory=lambda: ["any"])
    dst: list[str] = Field(default_factory=lambda: ["any"])
    src_segments: list[str] = Field(default_factory=list)
    dst_segments: list[str] = Field(default_factory=list)
    protocol: list[str] = Field(default_factory=lambda: ["ip"])
    src_ports: list[str] = Field(default_factory=lambda: ["any"])
    dst_ports: list[str] = Field(default_factory=lambda: ["any"])
    src_negate: bool = False
    dst_negate: bool = False
    action: Literal["permit", "deny", "reject", "restrict", "continue", "jump", "return", "unknown"]
    direction: Literal["in", "out", "zone", "forward", "global", "unknown"] = "unknown"
    interface: str | None = None
    in_interfaces: list[str] = Field(default_factory=list)
    out_interfaces: list[str] = Field(default_factory=list)
    from_zone: str | None = None
    to_zone: str | None = None
    confidence: Confidence = Confidence.EXACT
    chain_id: str | None = None
    order: int | None = None
    default_action: Literal["permit", "deny", "reject", "jump", "return", "unknown"] | None = None
    enabled: bool = True
    terminal: bool = True
    jump_target: str | None = None
    default_jump_target: str | None = None
    states: list[str] = Field(default_factory=list)
    ip_version: Literal[4, 6] | None = None
    unsupported_matches: list[str] = Field(default_factory=list)
    entrypoint: bool = True
    trace: Trace | None = None


class NATRule(BaseModel):
    device: str
    name: str
    type: str
    original_src: str = "any"
    original_dst: str = "any"
    translated_src: str | None = None
    translated_dst: str | None = None
    protocol: str = "any"
    original_port: int | None = None
    translated_port: int | None = None
    sequence: int | None = None
    source_ports: list[str] = Field(default_factory=list)
    destination_ports: list[str] = Field(default_factory=list)
    in_interfaces: list[str] = Field(default_factory=list)
    out_interfaces: list[str] = Field(default_factory=list)
    disabled: bool = False
    ip_version: Literal[4, 6] | None = None
    trace: Trace | None = None


class AddressObject(BaseModel):
    device: str
    name: str
    values: list[str]


class ServiceObject(BaseModel):
    device: str
    name: str
    protocol: str
    ports: list[str]


class ParserWarning(BaseModel):
    device: str
    line: int
    config: str
    reason: str
    parser: str


class ParserCapabilities(BaseModel):
    parser_id: str
    label: str
    interfaces: bool = False
    vlans: bool = False
    zones: bool = False
    routes: bool = False
    acl: bool = False
    firewall_policy: bool = False
    nat: bool = False
    address_objects: bool = False
    service_objects: bool = False
    ipv4: bool = True
    ipv6: bool = False
    status: Literal["available", "planned"] = "available"


class CanonicalConfig(BaseModel):
    device: Device
    interfaces: list[Interface] = Field(default_factory=list)
    vlans: list[VLAN] = Field(default_factory=list)
    segments: list[Segment] = Field(default_factory=list)
    zones: list[Zone] = Field(default_factory=list)
    routes: list[Route] = Field(default_factory=list)
    policies: list[Policy] = Field(default_factory=list)
    nat: list[NATRule] = Field(default_factory=list)
    address_objects: list[AddressObject] = Field(default_factory=list)
    service_objects: list[ServiceObject] = Field(default_factory=list)
    warnings: list[ParserWarning] = Field(default_factory=list)
    unsupported: list[ParserWarning] = Field(default_factory=list)

    def counts(self) -> dict[str, int]:
        return {key: len(value) for key, value in self.model_dump().items() if isinstance(value, list)}


class MatrixCell(BaseModel):
    source: str
    destination: str
    result: Literal["ALLOW", "DENY", "PARTIAL", "UNKNOWN", "SAME_SEGMENT"]
    allowed: list[str] = Field(default_factory=list)
    denied: list[str] = Field(default_factory=list)
    policy_ids: list[str] = Field(default_factory=list)
    traces: list[dict[str, Any]] = Field(default_factory=list)
