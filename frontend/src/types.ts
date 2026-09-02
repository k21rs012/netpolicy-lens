export type Result =
  | "ALLOW"
  | "DENY"
  | "PARTIAL"
  | "UNKNOWN"
  | "SAME_SEGMENT"
  | "NO_ROUTE";
export interface Segment {
  id: string;
  name: string;
  type: string;
  device: string;
  networks: string[];
  vlan_id?: number;
}
export interface Trace {
  device: string;
  interface?: string;
  policy: string;
  sequence: number;
  action: string;
  service: string;
  trace?: { source_file: string; line_start: number; raw_config: string };
}
export interface Cell {
  source: string;
  destination: string;
  result: Result;
  allowed: string[];
  denied: string[];
  policy_ids: string[];
  traces: Trace[];
}
export interface MatrixData {
  snapshot_id: string | null;
  segments: Segment[];
  cells: Cell[];
}
export interface Device {
  id: string;
  hostname: string;
  vendor: string;
  network_os: string;
  platform?: string;
  source_file: string;
  site?: string;
  confidence: number;
  counts: Record<string, number>;
}
export interface ParserWarning {
  device: string;
  line: number;
  config: string;
  reason: string;
  parser: string;
  kind?: "warning" | "unsupported";
}
export interface DeviceDetail {
  device: Device;
  interfaces: any[];
  vlans: any[];
  segments: Segment[];
  zones: any[];
  routes: any[];
  policies: Policy[];
  nat: any[];
  address_objects: any[];
  service_objects: any[];
  warnings: ParserWarning[];
  unsupported: ParserWarning[];
}
export interface Policy {
  id: string;
  device: string;
  name: string;
  sequence: number;
  src: string[];
  dst: string[];
  protocol: string[];
  dst_ports: string[];
  action: string;
  interface?: string;
  from_zone?: string;
  to_zone?: string;
  trace?: { source_file: string; line_start: number; raw_config: string };
}
export interface Capability {
  parser_id: string;
  label: string;
  interfaces: boolean;
  vlans: boolean;
  zones: boolean;
  routes: boolean;
  acl: boolean;
  firewall_policy: boolean;
  nat: boolean;
  ipv6: boolean;
  status: string;
}
export interface Snapshot {
  id: string;
  name: string;
  created_at: string;
  parser_version: string;
  device_count: number;
}
export interface CommunicationDiff {
  source: string;
  destination: string;
  source_label: string;
  destination_label: string;
  source_device: string;
  destination_device: string;
  before_result: Result | null;
  after_result: Result | null;
  new_allow: string[];
  new_deny: string[];
  removed_allow: string[];
  removed_deny: string[];
  after_traces: Trace[];
}
export interface ObjectDiff {
  change: "ADDED" | "REMOVED" | "CHANGED";
  kind: string;
  key: string;
  before: any;
  after: any;
  fields: { field: string; before: any; after: any }[];
}
export interface DiffData {
  before: Snapshot;
  after: Snapshot;
  summary: {
    new_allow: number;
    new_deny: number;
    removed_allow: number;
    added_rules: number;
    removed_rules: number;
    changed_rules: number;
    network_changes: number;
  };
  communications: CommunicationDiff[];
  policies: ObjectDiff[];
  network: ObjectDiff[];
}
export interface TopologyNode {
  id: string;
  entity_id: string;
  type: "device" | "segment";
  label: string;
  subtitle: string;
  vendor?: string;
  network_os?: string;
  device?: string;
  segment_type?: string;
}
export interface TopologyEdge {
  id: string;
  source: string;
  target: string;
  type: "owns" | "adjacent";
  label: string;
  confidence: "EXACT" | "INFERRED";
}
export interface TopologyData {
  snapshot_id: string | null;
  nodes: TopologyNode[];
  edges: TopologyEdge[];
  summary: { devices: number; segments: number; adjacencies: number };
}
export interface ReachabilityStep {
  device: string;
  ingress: string;
  egress: string;
  result: Result;
  reason: string;
  policy: string | null;
  route?: string;
  nat?: { name: string; type: string; translated_src?: string; translated_dst?: string; translated_port?: number }[];
  chains?: { result: Result; reason: string; policy: string | null; chain?: string }[];
  trace?: {
    source_file: string;
    line_start: number;
    line_end: number;
    raw_config: string;
  } | null;
}
export interface ReachabilityData {
  snapshot_id: string | null;
  source: string;
  destination: string;
  protocol: string;
  port: number | null;
  state: string;
  result: Result;
  path: string[];
  steps: ReachabilityStep[];
  topology: TopologyData;
}
