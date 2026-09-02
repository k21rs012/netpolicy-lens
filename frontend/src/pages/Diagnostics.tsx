import { useState } from "react";
import { Activity, Check, ChevronRight, Download, FileCode2, ShieldCheck } from "lucide-react";

import type { Capability } from "../types";



export function Capabilities({ items }: { items: Capability[] }) {
  const keys = [
    ["interfaces", "IF"],
    ["vlans", "VLAN"],
    ["routes", "Route"],
    ["acl", "ACL"],
    ["zones", "Zone"],
    ["firewall_policy", "Policy"],
    ["nat", "NAT"],
    ["ipv6", "IPv6"],
  ] as const;
  return (
    <div className="panel">
      <div className="callout">
        <Activity />
        <div>
          <b>Parser Plugin Architecture</b>
          <p>
            新しいNetwork
            OSはParserを登録するだけで、AnalyzerとUIへ自動的に反映されます。
          </p>
        </div>
      </div>
      <table className="data-table capability">
        <thead>
          <tr>
            <th>Network OS</th>
            {keys.map((k) => (
              <th key={k[0]}>{k[1]}</th>
            ))}
            <th>Status</th>
          </tr>
        </thead>
        <tbody>
          {items.map((c) => (
            <tr key={c.parser_id}>
              <td>
                <b>{c.label}</b>
                <small>{c.parser_id}</small>
              </td>
              {keys.map(([k]) => (
                <td key={k}>
                  {c[k] ? (
                    <Check className="yes" />
                  ) : (
                    <span className="dash">—</span>
                  )}
                </td>
              ))}
              <td>
                <span className={`stage ${c.status}`}>
                  {c.status === "available" ? "利用可能" : "予定"}
                </span>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

export function Debug({ data }: { data: any[] }) {
  const [selected, setSelected] = useState(0);
  const download = () => {
    const item = data[selected];
    if (!item) return;
    const blob = new Blob([JSON.stringify(item, null, 2)], {
      type: "application/json",
    });
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    link.download = `${item.device.hostname}-canonical.json`;
    link.click();
    URL.revokeObjectURL(url);
  };
  return (
    <div className="debug">
      <div className="debug-list">
        {data.map((x, i) => (
          <button
            className={i === selected ? "active" : ""}
            onClick={() => setSelected(i)}
            key={x.device.id}
          >
            <FileCode2 />
            <span>
              {x.device.hostname}
              <small>{x.device.network_os}</small>
            </span>
            <ChevronRight />
          </button>
        ))}
      </div>
      <div className="debug-output">
        <div>
          <span>
            <ShieldCheck />
            Secretマスク済みCanonical JSON
          </span>
          <button onClick={download} disabled={!data.length}>
            <Download />
            JSON Export
          </button>
        </div>
        <pre>
          {data.length
            ? JSON.stringify(data[selected], null, 2)
            : "No parser output"}
        </pre>
      </div>
    </div>
  );
}
