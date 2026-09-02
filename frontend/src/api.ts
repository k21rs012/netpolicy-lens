const json = async <T>(url: string, init?: RequestInit): Promise<T> => {
  const r = await fetch(url, init);
  if (!r.ok) throw new Error((await r.text()) || r.statusText);
  return r.json();
};
export const api = {
  matrix: (protocol = "", port = "") =>
    json<any>(
      `/api/matrix?protocol=${encodeURIComponent(protocol)}&port=${encodeURIComponent(port)}`,
    ),
  devices: () => json<any>("/api/devices"),
  device: (id: string) => json<any>(`/api/devices/${encodeURIComponent(id)}`),
  policies: () => json<any>("/api/policies"),
  capabilities: () => json<any>("/api/parser/capabilities"),
  warnings: (device = "") =>
    json<any>(`/api/parser/warnings?device=${encodeURIComponent(device)}`),
  snapshots: () => json<any>("/api/snapshots"),
  debug: () => json<any>("/api/parser/debug"),
  sample: () => json<any>("/api/sample/load", { method: "POST" }),
  diff: (before: string, after: string) =>
    json<any>(
      `/api/diff?before=${encodeURIComponent(before)}&after=${encodeURIComponent(after)}`,
    ),
  topology: () => json<any>("/api/topology"),
  reachability: (src: string, dst: string, protocol: string, port: string, state = "new") =>
    json<any>(
      `/api/reachability?src=${encodeURIComponent(src)}&dst=${encodeURIComponent(dst)}&protocol=${encodeURIComponent(protocol)}&port=${encodeURIComponent(port)}&state=${encodeURIComponent(state)}`,
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
