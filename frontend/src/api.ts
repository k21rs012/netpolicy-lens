import type {
  Capability,
  Device,
  DeviceDetail,
  DiffData,
  MatrixData,
  ParserWarning,
  Policy,
  ReachabilityData,
  Snapshot,
  TopologyData,
} from "./types";


const json = async <T>(url: string, init?: RequestInit): Promise<T> => {
  const r = await fetch(url, init);
  if (!r.ok) throw new Error((await r.text()) || r.statusText);
  return r.json();
};
const snapshotUrl = (url: string, id = "") => id ? `${url}${url.includes("?") ? "&" : "?"}snapshot_id=${encodeURIComponent(id)}` : url;
export const api = {
  matrix: (protocol = "", port = "", signal?: AbortSignal, snapshotId = "", ipVersion = "") =>
    json<MatrixData>(
      snapshotUrl(`/api/matrix?limit=25&protocol=${encodeURIComponent(protocol)}${port ? `&port=${encodeURIComponent(port)}` : ""}`, snapshotId) + (ipVersion ? `&ip_version=${ipVersion}` : ""), { signal },
    ),
  matrixWindow: (data: MatrixData, sources: string[], destinations: string[], signal: AbortSignal) => {
    const query = new URLSearchParams({ limit: "25", protocol: data.protocol || "" });
    if (data.snapshot_id) query.set("snapshot_id", data.snapshot_id);
    if (data.ip_version) query.set("ip_version", String(data.ip_version));
    if (data.port != null) query.set("port", String(data.port));
    sources.forEach(id => query.append("source_ids", id));
    destinations.forEach(id => query.append("destination_ids", id));
    return json<MatrixData>(`/api/matrix?${query}`, { signal });
  },
  devices: (snapshotId = "") => json<{ items: Device[] }>(snapshotUrl("/api/devices", snapshotId)),
  device: (id: string, snapshotId = "") => json<DeviceDetail>(snapshotUrl(`/api/devices/${encodeURIComponent(id)}`, snapshotId)),
  policies: (snapshotId = "") => json<{ items: Policy[] }>(snapshotUrl("/api/policies", snapshotId)),
  capabilities: () => json<Capability[]>("/api/parser/capabilities"),
  warnings: (device = "") =>
    json<{ items: ParserWarning[] }>(`/api/parser/warnings?device=${encodeURIComponent(device)}`),
  snapshots: () => json<Snapshot[]>("/api/snapshots"),
  backupSnapshot: async (id: string) => {
    const response = await fetch(`/api/snapshots/${encodeURIComponent(id)}/backup`);
    if (!response.ok) throw new Error(await response.text());
    return response.blob();
  },
  previewRestore: (file: File) => {
    const body = new FormData(); body.append("file", file);
    return json<{ snapshot: Snapshot; suggested_name: string }>("/api/snapshots/restore/preview", { method: "POST", body });
  },
  restoreSnapshot: (file: File, name: string) => {
    const body = new FormData(); body.append("file", file); body.append("name", name);
    return json<Snapshot>("/api/snapshots/restore", { method: "POST", body });
  },
  renameSnapshot: (id: string, name: string) => json<Snapshot>(`/api/snapshots/${encodeURIComponent(id)}`, {
    method: "PATCH", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ name }),
  }),
  deleteSnapshot: async (id: string) => {
    const response = await fetch(`/api/snapshots/${encodeURIComponent(id)}`, { method: "DELETE" });
    if (!response.ok) throw new Error(await response.text());
  },
  debug: (signal?: AbortSignal, snapshotId = "") => json<any>(snapshotUrl("/api/parser/debug", snapshotId), { signal }),
  sample: () => json<any>("/api/sample/load", { method: "POST" }),
  diff: (before: string, after: string, protocol = "", port = "", signal?: AbortSignal, ipVersion = "") =>
    json<DiffData>(
      `/api/diff?before=${encodeURIComponent(before)}&after=${encodeURIComponent(after)}${protocol ? `&protocol=${encodeURIComponent(protocol)}` : ""}${port !== "" ? `&port=${encodeURIComponent(port)}` : ""}${ipVersion ? `&ip_version=${ipVersion}` : ""}`,
      { signal },
    ),
  topology: (snapshotId = "") => json<TopologyData>(snapshotUrl("/api/topology", snapshotId)),
  reachability: (
    src: string,
    dst: string,
    protocol: string,
    port: string,
    sourcePort: string,
    ipVersion: string,
    state = "new",
    assumeSession = false,
    sourceIp = "",
    destinationIp = "",
    icmpType = "",
    snapshotId = "",
  ) =>
    json<ReachabilityData>(
      snapshotUrl(`/api/reachability?src=${encodeURIComponent(src)}&dst=${encodeURIComponent(dst)}&protocol=${encodeURIComponent(protocol)}${port ? `&port=${encodeURIComponent(port)}` : ""}${sourcePort ? `&source_port=${encodeURIComponent(sourcePort)}` : ""}${ipVersion ? `&ip_version=${encodeURIComponent(ipVersion)}` : ""}${sourceIp ? `&source_ip=${encodeURIComponent(sourceIp)}` : ""}${destinationIp ? `&destination_ip=${encodeURIComponent(destinationIp)}` : ""}${icmpType !== "" ? `&icmp_type=${encodeURIComponent(icmpType)}` : ""}&state=${encodeURIComponent(state)}&assume_session=${assumeSession}`, snapshotId),
    ),
  previewConfigs: (files: File[]) => {
    const form = new FormData();
    files.forEach((f) => form.append("files", f));
    return json<any>("/api/configs/preview", { method: "POST", body: form });
  },
  importConfigs: (
    files: File[],
    name: string,
    parserIds: Record<string, string> = {},
    sites: Record<string, string> = {},
  ) => {
    const form = new FormData();
    files.forEach((f) => form.append("files", f));
    form.append("snapshot_name", name);
    form.append("parser_ids", JSON.stringify(parserIds));
    form.append("sites", JSON.stringify(sites));
    return json<any>("/api/configs/import", { method: "POST", body: form });
  },
};
