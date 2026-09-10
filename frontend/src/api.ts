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
export const api = {
  matrix: (protocol = "", port = "") =>
    json<MatrixData>(
      `/api/matrix?protocol=${encodeURIComponent(protocol)}${port ? `&port=${encodeURIComponent(port)}` : ""}`,
    ),
  devices: () => json<{ items: Device[] }>("/api/devices"),
  device: (id: string) => json<DeviceDetail>(`/api/devices/${encodeURIComponent(id)}`),
  policies: () => json<{ items: Policy[] }>("/api/policies"),
  capabilities: () => json<Capability[]>("/api/parser/capabilities"),
  warnings: (device = "") =>
    json<{ items: ParserWarning[] }>(`/api/parser/warnings?device=${encodeURIComponent(device)}`),
  snapshots: () => json<Snapshot[]>("/api/snapshots"),
  debug: () => json<any>("/api/parser/debug"),
  sample: () => json<any>("/api/sample/load", { method: "POST" }),
  diff: (before: string, after: string) =>
    json<DiffData>(
      `/api/diff?before=${encodeURIComponent(before)}&after=${encodeURIComponent(after)}`,
    ),
  topology: () => json<TopologyData>("/api/topology"),
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
  ) =>
    json<ReachabilityData>(
      `/api/reachability?src=${encodeURIComponent(src)}&dst=${encodeURIComponent(dst)}&protocol=${encodeURIComponent(protocol)}${port ? `&port=${encodeURIComponent(port)}` : ""}${sourcePort ? `&source_port=${encodeURIComponent(sourcePort)}` : ""}${ipVersion ? `&ip_version=${encodeURIComponent(ipVersion)}` : ""}${sourceIp ? `&source_ip=${encodeURIComponent(sourceIp)}` : ""}${destinationIp ? `&destination_ip=${encodeURIComponent(destinationIp)}` : ""}&state=${encodeURIComponent(state)}&assume_session=${assumeSession}`,
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
