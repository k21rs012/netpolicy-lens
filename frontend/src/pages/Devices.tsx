import { useEffect, useState } from "react";
import {
  AlertTriangle, Check, ChevronRight, FileCode2, RefreshCw,
  Server, ShieldCheck, X,
} from "lucide-react";

import { api } from "../api";
import type { Device, DeviceDetail, ParserWarning } from "../types";



export function Devices({
  items,
  onSelect,
}: {
  items: Device[];
  onSelect: (device: Device) => void;
}) {
  return (
    <div className="cards">
      {items.map((d) => (
        <article
          className="device-card"
          key={d.id}
          role="button"
          tabIndex={0}
          onClick={() => onSelect(d)}
          onKeyDown={(e) => e.key === "Enter" && onSelect(d)}
        >
          <div className={`vendor ${d.vendor}`}>
            <Server />
          </div>
          <div className="device-title">
            <div>
              <h3>{d.hostname}</h3>
              <p>
                {d.site && <>{d.site.toUpperCase()} · </>}
                {d.vendor.toUpperCase()} · {d.network_os.toUpperCase()}
              </p>
            </div>
            <span className="confidence">
              {Math.round(d.confidence * 100)}% 検出
            </span>
          </div>
          <div className="device-stats">
            <span>
              <b>{d.counts.interfaces || 0}</b>Interfaces
            </span>
            <span>
              <b>{d.counts.segments || 0}</b>Segments
            </span>
            <span>
              <b>{d.counts.policies || 0}</b>Policies
            </span>
            <span>
              <b>{d.counts.nat || 0}</b>NAT
            </span>
          </div>
          <footer>
            <FileCode2 />
            {d.source_file}
            <span
              className={
                d.counts.warnings || d.counts.unsupported
                  ? "warning-dot"
                  : "clean-dot"
              }
            />
            {(d.counts.warnings || 0) + (d.counts.unsupported || 0)} issues
            <ChevronRight />
          </footer>
        </article>
      ))}
    </div>
  );
}

function WarningRows({
  items,
  kind,
}: {
  items: ParserWarning[];
  kind: string;
}) {
  return items.length ? (
    <div className="issue-list">
      {items.map((item, index) => (
        <article key={`${kind}:${item.line}:${index}`}>
          <AlertTriangle />
          <div>
            <b>{item.reason}</b>
            <code>{item.config}</code>
            <small>
              {item.parser} · line {item.line}
            </small>
          </div>
        </article>
      ))}
    </div>
  ) : (
    <div className="detail-empty">
      <Check />
      該当項目はありません
    </div>
  );
}
export function DeviceDetailDrawer({
  device,
  close,
}: {
  device: Device;
  close: () => void;
}) {
  const [data, setData] = useState<DeviceDetail | null>(null);
  const [tab, setTab] = useState("interfaces");
  useEffect(() => {
    api.device(device.id).then(setData);
  }, [device.id]);
  const sections = data
    ? {
        interfaces: data.interfaces,
        vlans: data.vlans,
        zones: data.zones,
        segments: data.segments,
        routes: data.routes,
        policies: data.policies,
        nat: data.nat,
        address_objects: data.address_objects,
        service_objects: data.service_objects,
        warnings: data.warnings,
        unsupported: data.unsupported,
      }
    : ({} as Record<string, any[]>);
  const labels: Record<string, string> = {
    interfaces: "Interfaces",
    vlans: "VLANs",
    zones: "Zones",
    segments: "Segments",
    routes: "Routes",
    policies: "Policies",
    nat: "NAT",
    address_objects: "Addresses",
    service_objects: "Services",
    warnings: "Warnings",
    unsupported: "Unsupported",
  };
  return (
    <aside
      className="drawer device-drawer"
      role="dialog"
      aria-modal="true"
      aria-label={`${device.hostname}の詳細`}
    >
      <div className="drawer-head">
        <div>
          <small>DEVICE DETAIL</small>
          <h2>
            <Server />
            {device.hostname}
          </h2>
          <p>
            {device.site && `${device.site.toUpperCase()} · `}
            {device.vendor.toUpperCase()} · {device.network_os.toUpperCase()} ·{" "}
            {device.source_file}
          </p>
        </div>
        <button
          className="icon"
          aria-label="デバイス詳細を閉じる"
          title="閉じる"
          onClick={close}
        >
          <X />
        </button>
      </div>
      {!data ? (
        <div className="loading drawer-loading">
          <RefreshCw className="spin" />
          詳細を読み込み中
        </div>
      ) : (
        <>
          <div className="device-detail-stats">
            <span>
              <b>{data.interfaces.length}</b>IF
            </span>
            <span>
              <b>{data.segments.length}</b>Segments
            </span>
            <span>
              <b>{data.routes.length}</b>Routes
            </span>
            <span>
              <b>{data.policies.length}</b>Policies
            </span>
            <span>
              <b>{data.nat.length}</b>NAT
            </span>
            <span
              className={
                data.warnings.length + data.unsupported.length
                  ? "has-issues"
                  : ""
              }
            >
              <b>{data.warnings.length + data.unsupported.length}</b>Issues
            </span>
          </div>
          <div className="detail-tabs">
            {Object.keys(sections).map((key) => (
              <button
                className={tab === key ? "active" : ""}
                onClick={() => setTab(key)}
                key={key}
              >
                {labels[key]}
                <span>{sections[key].length}</span>
              </button>
            ))}
          </div>
          <div className="detail-content">
            {tab === "warnings" ? (
              <WarningRows items={data.warnings} kind="warning" />
            ) : tab === "unsupported" ? (
              <WarningRows items={data.unsupported} kind="unsupported" />
            ) : sections[tab]?.length ? (
              <div className="object-list">
                {sections[tab].map((item, index) => (
                  <article key={item.id || item.name || index}>
                    <div>
                      <b>
                        {item.name ||
                          item.destination ||
                          item.id ||
                          `${labels[tab]} ${index + 1}`}
                      </b>
                      <small>
                        {item.description ||
                          item.action ||
                          item.type ||
                          item.interface ||
                          ""}
                      </small>
                    </div>
                    <pre>{JSON.stringify(item, null, 2)}</pre>
                  </article>
                ))}
              </div>
            ) : (
              <div className="detail-empty">
                <Check />
                {labels[tab]}はありません
              </div>
            )}
          </div>
          <p className="masked-note">
            <ShieldCheck />
            保存・表示されるPassword、Secret、SNMP
            Communityは自動的にマスクされます。
          </p>
        </>
      )}
    </aside>
  );
}
