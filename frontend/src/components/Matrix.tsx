import { useEffect, useMemo, useState } from "react";
import { ChevronRight, CircleHelp, FileCode2, Network, Search, X, Zap } from "lucide-react";

import { api } from "../api";
import { Status } from "./Status";
import type { Cell, Device, MatrixData, Result, Segment } from "../types";


export function Empty({ load }: { load: () => void }) {
  return (
    <div className="empty">
      <div className="empty-visual">
        <Network />
        <i />
        <i />
        <i />
      </div>
      <h2>まだネットワークがありません</h2>
      <p>
        サンプル構成を読み込むか、実機の設定ファイルをアップロードしてください。
      </p>
      <button className="primary" onClick={load}>
        <Zap />
        サンプルで始める
      </button>
    </div>
  );
}

export function Matrix({
  data,
  onCell,
}: {
  data: MatrixData;
  onCell: (c: Cell) => void;
}) {
  const [devices, setDevices] = useState<Device[]>([]);
  const [query, setQuery] = useState("");
  const [device, setDevice] = useState("");
  const [site, setSite] = useState("");
  const [vendor, setVendor] = useState("");
  const [networkOs, setNetworkOs] = useState("");
  const [type, setType] = useState("");
  const [vlan, setVlan] = useState("");
  const [result, setResult] = useState("");
  useEffect(() => {
    api
      .devices()
      .then((value) => setDevices(value.items))
      .catch(() => {});
  }, []);
  const deviceById = useMemo(
    () => Object.fromEntries(devices.map((d) => [d.id, d])),
    [devices],
  );
  const segments = useMemo(
    () =>
      data.segments.filter((s) => {
        const owner = deviceById[s.device];
        const text = [s.name, s.id, s.device, ...s.networks]
          .join(" ")
          .toLowerCase();
        return (
          (!query || text.includes(query.toLowerCase())) &&
          (!device || s.device === device) &&
          (!site || owner?.site === site) &&
          (!vendor || owner?.vendor === vendor) &&
          (!networkOs || owner?.network_os === networkOs) &&
          (!type || s.type === type) &&
          (!vlan || String(s.vlan_id ?? "") === vlan)
        );
      }),
    [
      data.segments,
      deviceById,
      query,
      device,
      site,
      vendor,
      networkOs,
      type,
      vlan,
    ],
  );
  const ids = new Set(segments.map((s) => s.id));
  const cells = data.cells.filter(
    (c) =>
      ids.has(c.source) &&
      ids.has(c.destination) &&
      (!result || c.result === result),
  );
  const filtered = { ...data, segments, cells };
  const clear = () => {
    setQuery("");
    setDevice("");
    setSite("");
    setVendor("");
    setNetworkOs("");
    setType("");
    setVlan("");
    setResult("");
  };
  const active = !!(
    query ||
    device ||
    site ||
    vendor ||
    networkOs ||
    type ||
    vlan ||
    result
  );
  const sites = [
    ...new Set(devices.flatMap((d) => (d.site ? [d.site] : []))),
  ].sort();
  const vendors = [...new Set(devices.map((d) => d.vendor))].sort();
  const operatingSystems = [
    ...new Set(devices.map((d) => d.network_os)),
  ].sort();
  const types = [...new Set(data.segments.map((s) => s.type))].sort();
  const vlans = [
    ...new Set(
      data.segments.flatMap((s) => (s.vlan_id == null ? [] : [s.vlan_id])),
    ),
  ].sort((a, b) => a - b);
  return (
    <>
      <div className="matrix-advanced">
        <div className="search">
          <Search />
          <input
            aria-label="Segmentを検索"
            placeholder="Segment / subnetを検索"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
          />
        </div>
        <label>
          Device
          <select
            aria-label="デバイスで絞り込み"
            value={device}
            onChange={(e) => setDevice(e.target.value)}
          >
            <option value="">ALL</option>
            {devices.map((d) => (
              <option value={d.id} key={d.id}>
                {d.hostname}
              </option>
            ))}
          </select>
        </label>
        <label>
          Site
          <select
            aria-label="Siteで絞り込み"
            value={site}
            onChange={(e) => setSite(e.target.value)}
          >
            <option value="">ALL</option>
            {sites.map((x) => (
              <option key={x}>{x}</option>
            ))}
          </select>
        </label>
        <label>
          Vendor
          <select
            aria-label="ベンダーで絞り込み"
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
            aria-label="OSで絞り込み"
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
          Type
          <select
            aria-label="Segment種別で絞り込み"
            value={type}
            onChange={(e) => setType(e.target.value)}
          >
            <option value="">ALL</option>
            {types.map((x) => (
              <option key={x}>{x}</option>
            ))}
          </select>
        </label>
        <label>
          VLAN
          <select
            aria-label="VLANで絞り込み"
            value={vlan}
            onChange={(e) => setVlan(e.target.value)}
          >
            <option value="">ALL</option>
            {vlans.map((x) => (
              <option key={x} value={x}>
                {x}
              </option>
            ))}
          </select>
        </label>
        <label>
          Result
          <select
            aria-label="判定結果で絞り込み"
            value={result}
            onChange={(e) => setResult(e.target.value)}
          >
            <option value="">ALL</option>
            {(
              [
                "ALLOW",
                "DENY",
                "PARTIAL",
                "UNKNOWN",
                "SAME_SEGMENT",
              ] as Result[]
            ).map((x) => (
              <option key={x}>{x}</option>
            ))}
          </select>
        </label>
        <button disabled={!active} onClick={clear}>
          <X />
          クリア
        </button>
        <span>
          {segments.length} / {data.segments.length} segments
        </span>
      </div>
      {segments.length ? (
        <div className="matrix-wrap">
          <table className="matrix">
            <thead>
              <tr>
                <th className="corner">
                  送信元 <ChevronRight /> 宛先
                </th>
                {filtered.segments.map((s) => (
                  <th key={s.id}>
                    <span>{s.name}</span>
                    <small>
                      {deviceById[s.device]?.site
                        ? `${deviceById[s.device].site} · `
                        : ""}
                      {s.device} · {s.type.toUpperCase()}
                    </small>
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {filtered.segments.map((src) => (
                <tr key={src.id}>
                  <th>
                    <span>{src.name}</span>
                    <small>
                      {src.device} · {src.networks[0] || "no subnet"}
                    </small>
                  </th>
                  {filtered.segments.map((dst) => {
                    const c = filtered.cells.find(
                      (x) => x.source === src.id && x.destination === dst.id,
                    );
                    return (
                      <td key={dst.id}>
                        {c ? (
                          <button
                            className={`cell ${c.result.toLowerCase()}`}
                            onClick={() => onCell(c)}
                            title={`${src.name} (${src.device}) → ${dst.name} (${dst.device})`}
                          >
                            <Status value={c.result} compact />
                            <small>{c.allowed[0] || c.denied[0] || ""}</small>
                          </button>
                        ) : (
                          <span className="filtered-cell">—</span>
                        )}
                      </td>
                    );
                  })}
                </tr>
              ))}
            </tbody>
          </table>
          <div className="legend">
            {(
              [
                "ALLOW",
                "DENY",
                "PARTIAL",
                "UNKNOWN",
                "SAME_SEGMENT",
              ] as Result[]
            ).map((x) => (
              <Status key={x} value={x} />
            ))}
          </div>
        </div>
      ) : (
        <div className="matrix-no-results">
          <Search />
          条件に一致するSegmentがありません
          <button onClick={clear}>条件をクリア</button>
        </div>
      )}
    </>
  );
}

export function Detail({
  cell,
  segments,
  close,
}: {
  cell: Cell;
  segments: Segment[];
  close: () => void;
}) {
  const name = (id: string) => segments.find((s) => s.id === id)?.name || id;
  return (
    <aside
      className="drawer"
      role="dialog"
      aria-modal="true"
      aria-label="通信判定の詳細"
    >
      <div className="drawer-head">
        <div>
          <small>通信判定の詳細</small>
          <h2>
            {name(cell.source)} <ChevronRight /> {name(cell.destination)}
          </h2>
        </div>
        <button
          className="icon"
          aria-label="詳細を閉じる"
          title="閉じる"
          onClick={close}
        >
          <X />
        </button>
      </div>
      <div className="verdict">
        <Status value={cell.result} />
        <p>
          {cell.result === "UNKNOWN"
            ? "明示的なポリシー根拠を確認できません。安全のため許可とは判定しません。"
            : "一致した設定ルールに基づく静的解析結果です。"}
        </p>
      </div>
      {(cell.allowed.length > 0 || cell.denied.length > 0) && (
        <div className="split">
          <section>
            <label>許可</label>
            {cell.allowed.map((x) => (
              <span className="service allow" key={x}>
                {x}
              </span>
            ))}
          </section>
          <section>
            <label>拒否</label>
            {cell.denied.map((x) => (
              <span className="service deny" key={x}>
                {x}
              </span>
            ))}
          </section>
        </div>
      )}
      <h3>Rule trace</h3>
      {cell.traces.length ? (
        cell.traces.map((t, i) => (
          <div className="trace" key={i}>
            <div className="trace-line">
              <span>{i + 1}</span>
              <b>{t.device}</b>
              <small>{t.interface || "zone policy"}</small>
            </div>
            <div className="trace-rule">
              <FileCode2 />
              <div>
                <b>
                  {t.policy} / Rule {t.sequence}
                </b>
                <code>{t.trace?.raw_config || t.service}</code>
                <small>
                  {t.trace && `${t.trace.source_file}:${t.trace.line_start}`}
                </small>
              </div>
            </div>
            <Status value={t.action === "permit" ? "ALLOW" : "DENY"} />
          </div>
        ))
      ) : (
        <div className="no-trace">
          <CircleHelp />
          <p>一致するルールがありません</p>
        </div>
      )}
    </aside>
  );
}
