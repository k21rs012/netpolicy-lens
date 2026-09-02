import { useEffect, useState } from "react";
import { Search } from "lucide-react";

import { api } from "../api";
import { Status } from "../components/Status";
import type { Device, Policy } from "../types";


export function Policies({ items }: { items: Policy[] }) {
  const [query, setQuery] = useState("");
  const [device, setDevice] = useState("");
  const [vendor, setVendor] = useState("");
  const [networkOs, setNetworkOs] = useState("");
  const [source, setSource] = useState("");
  const [destination, setDestination] = useState("");
  const [action, setAction] = useState("");
  const [protocol, setProtocol] = useState("");
  const [port, setPort] = useState("");
  const [deviceItems, setDeviceItems] = useState<Device[]>([]);
  useEffect(() => {
    api
      .devices()
      .then((value) => setDeviceItems(value.items))
      .catch(() => {});
  }, []);
  const deviceMap = Object.fromEntries(deviceItems.map((x) => [x.id, x]));
  const devices = [...new Set(items.map((p) => p.device))].sort();
  const vendors = [...new Set(deviceItems.map((x) => x.vendor))].sort();
  const operatingSystems = [
    ...new Set(deviceItems.map((x) => x.network_os)),
  ].sort();
  const protocols = [...new Set(items.flatMap((p) => p.protocol))].sort();
  const rows = items.filter((p) => {
    const owner = deviceMap[p.device];
    const src = (p.from_zone || p.src.join(", ")).toLowerCase();
    const dst = (p.to_zone || p.dst.join(", ")).toLowerCase();
    return (
      (!device || p.device === device) &&
      (!vendor || owner?.vendor === vendor) &&
      (!networkOs || owner?.network_os === networkOs) &&
      (!source || src.includes(source.toLowerCase())) &&
      (!destination || dst.includes(destination.toLowerCase())) &&
      (!action || p.action === action) &&
      (!protocol || p.protocol.includes(protocol)) &&
      (!port || p.dst_ports.some((x) => x.includes(port))) &&
      JSON.stringify(p).toLowerCase().includes(query.toLowerCase())
    );
  });
  return (
    <div className="panel">
      <div className="toolbar policy-toolbar">
        <div className="search">
          <Search />
          <input
            aria-label="ポリシーを検索"
            placeholder="ポリシー名を検索"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
          />
        </div>
        <label>
          Device
          <select
            aria-label="ポリシーのデバイス"
            value={device}
            onChange={(e) => setDevice(e.target.value)}
          >
            <option value="">ALL</option>
            {devices.map((x) => (
              <option key={x}>{x}</option>
            ))}
          </select>
        </label>
        <label>
          Vendor
          <select
            aria-label="ポリシーのベンダー"
            value={vendor}
            onChange={(e) => setVendor(e.target.value)}
          >
            <option value="">ALL</option>
            {vendors.map((x) => (
              <option key={x}>{x}</option>
            ))}
          </select>
        </label>
        <label>
          OS
          <select
            aria-label="ポリシーのOS"
            value={networkOs}
            onChange={(e) => setNetworkOs(e.target.value)}
          >
            <option value="">ALL</option>
            {operatingSystems.map((x) => (
              <option key={x}>{x}</option>
            ))}
          </select>
        </label>
        <label>
          Source
          <input
            aria-label="ポリシーの送信元"
            value={source}
            onChange={(e) => setSource(e.target.value)}
            placeholder="any"
          />
        </label>
        <label>
          Destination
          <input
            aria-label="ポリシーの宛先"
            value={destination}
            onChange={(e) => setDestination(e.target.value)}
            placeholder="any"
          />
        </label>
        <label>
          Action
          <select
            aria-label="ポリシーのアクション"
            value={action}
            onChange={(e) => setAction(e.target.value)}
          >
            <option value="">ALL</option>
            <option value="permit">ALLOW</option>
            <option value="deny">DENY</option>
            <option value="reject">REJECT</option>
            <option value="restrict">RESTRICT</option>
          </select>
        </label>
        <label>
          Protocol
          <select
            aria-label="ポリシーのプロトコル"
            value={protocol}
            onChange={(e) => setProtocol(e.target.value)}
          >
            <option value="">ALL</option>
            {protocols.map((x) => (
              <option key={x} value={x}>
                {x.toUpperCase()}
              </option>
            ))}
          </select>
        </label>
        <label>
          Port
          <input
            aria-label="ポリシーのポート"
            value={port}
            onChange={(e) => setPort(e.target.value)}
            placeholder="any"
          />
        </label>
        <span className="result-count">
          {rows.length} / {items.length} 件
        </span>
      </div>
      <div className="table-scroll">
        <table className="data-table">
          <thead>
            <tr>
              <th>デバイス / ポリシー</th>
              <th>送信元</th>
              <th>宛先</th>
              <th>プロトコル</th>
              <th>ポート</th>
              <th>アクション</th>
              <th>根拠</th>
            </tr>
          </thead>
          <tbody>
            {rows.map((p) => (
              <tr key={p.id}>
                <td>
                  <b>{p.device}</b>
                  <small>
                    {p.name} · #{p.sequence}
                  </small>
                </td>
                <td>{p.from_zone || p.src.join(", ")}</td>
                <td>{p.to_zone || p.dst.join(", ")}</td>
                <td>{p.protocol.join(", ").toUpperCase()}</td>
                <td>
                  <code>{p.dst_ports.join(", ")}</code>
                </td>
                <td>
                  <Status value={p.action === "permit" ? "ALLOW" : "DENY"} />
                </td>
                <td>
                  <small>
                    {p.trace?.source_file}:{p.trace?.line_start}
                  </small>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
