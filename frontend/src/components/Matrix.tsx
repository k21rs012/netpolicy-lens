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
  onVisibleCells,
}: {
  data: MatrixData;
  onCell: (c: Cell) => void;
  onVisibleCells?: (cells: Cell[]) => void;
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
      .devices(data.snapshot_id || "")
      .then((value) => setDevices(value.items))
      .catch(() => {});
  }, [data.snapshot_id]);
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
  const pageSize = 25;
  const [sourcePage, setSourcePage] = useState(0);
  const [destinationPage, setDestinationPage] = useState(0);
  const [pageData, setPageData] = useState<{ base: MatrixData; key: string; data: MatrixData } | null>(null);
  const [pageError, setPageError] = useState<{ key: string; message: string } | null>(null);
  const [retry, setRetry] = useState(0);
  useEffect(() => { setSourcePage(0); setDestinationPage(0); }, [query, device, site, vendor, networkOs, type, vlan]);
  const lastPage = Math.max(0, Math.ceil(segments.length / pageSize) - 1);
  const srcPage = Math.min(sourcePage, lastPage), dstPage = Math.min(destinationPage, lastPage);
  const sources = segments.slice(srcPage * pageSize, (srcPage + 1) * pageSize);
  const destinations = segments.slice(dstPage * pageSize, (dstPage + 1) * pageSize);
  const requestKey = JSON.stringify([sources.map(s => s.id), destinations.map(s => s.id)]);
  const initialMatches = !data.window || requestKey === JSON.stringify([data.window.source_ids, data.window.destination_ids]);
  const current = initialMatches ? data : pageData?.base === data && pageData.key === requestKey ? pageData.data : null;
  useEffect(() => {
    if (initialMatches || !sources.length || !destinations.length) return;
    const controller = new AbortController();
    setPageError(null);
    const [srcIds, dstIds] = JSON.parse(requestKey) as [string[], string[]];
    api.matrixWindow(data, srcIds, dstIds, controller.signal).then(value => {
      if (!controller.signal.aborted) setPageData({ base: data, key: requestKey, data: value });
    }).catch(cause => {
      if (!controller.signal.aborted) setPageError({ key: requestKey, message: String(cause.message || cause) });
    });
    return () => controller.abort();
  }, [data, requestKey, initialMatches, retry]);
  const cellByPair = useMemo(() => new Map((current?.cells || []).map(cell =>
    [JSON.stringify([cell.source, cell.destination]), cell])), [current]);
  const visibleCells = useMemo(() => {
    const [srcIds, dstIds] = JSON.parse(requestKey) as [string[], string[]];
    const srcSet = new Set(srcIds), dstSet = new Set(dstIds);
    return (current?.cells || []).filter(cell => srcSet.has(cell.source) && dstSet.has(cell.destination));
  }, [current, requestKey]);
  useEffect(() => onVisibleCells?.(visibleCells), [visibleCells, onVisibleCells]);
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
      <div className="matrix-scope" role="note">
        <CircleHelp aria-hidden="true" />
        <div>
          <strong>{data.evaluation === "path" ? `通信条件を評価中${data.ip_version ? ` / IPv${data.ip_version}` : ""}` : "設定ルールの概要"}</strong>
          <p>{data.evaluation === "path"
            ? "Path traceと同じ経路・Policy・NAT解析です。Segment全体・新規通信として評価します。Protocol未指定の場合はTCP・UDP・SCTPの結果を集約します。"
            : "表示サービスは経路全体の通信保証ではありません。Protocol・Port・IP familyのいずれかを指定すると、Path traceと同じ条件評価に切り替わります。"}</p>
        </div>
      </div>
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
                "NO_ROUTE",
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
      {segments.length > pageSize && (
        <nav className="matrix-pagination" aria-label="Matrixの表示範囲">
          <div><span>送信元 {srcPage * pageSize + 1}–{srcPage * pageSize + sources.length} / {segments.length}</span>
            <button disabled={!srcPage} onClick={() => setSourcePage(srcPage - 1)} aria-label="送信元の前のページ">前へ</button>
            <button disabled={srcPage >= lastPage} onClick={() => setSourcePage(srcPage + 1)} aria-label="送信元の次のページ">次へ</button></div>
          <div><span>宛先 {dstPage * pageSize + 1}–{dstPage * pageSize + destinations.length} / {segments.length}</span>
            <button disabled={!dstPage} onClick={() => setDestinationPage(dstPage - 1)} aria-label="宛先の前のページ">前へ</button>
            <button disabled={dstPage >= lastPage} onClick={() => setDestinationPage(dstPage + 1)} aria-label="宛先の次のページ">次へ</button></div>
          <small>25 × 25件ずつ解析します。判定結果の絞り込み・集計は表示範囲が対象です。</small>
        </nav>
      )}
      {segments.length && !current ? (
        pageError?.key === requestKey ? <div role="alert" className="matrix-page-message">{pageError.message}<button onClick={() => setRetry(value => value + 1)}>再試行</button></div>
          : <div role="status" className="matrix-page-message">表示範囲を解析中</div>
      ) : segments.length ? (
        <div className="matrix-wrap">
          <table className="matrix">
            <thead>
              <tr>
                <th className="corner">
                  送信元 <ChevronRight /> 宛先
                </th>
                {destinations.map((s) => (
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
              {sources.map((src) => (
                <tr key={src.id}>
                  <th>
                    <span>{src.name}</span>
                    <small>
                      {src.device} · {src.networks[0] || "no subnet"}
                    </small>
                  </th>
                  {destinations.map((dst) => {
                    const found = cellByPair.get(JSON.stringify([src.id, dst.id]));
                    const c = found && (!result || found.result === result) ? found : undefined;
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
                "NO_ROUTE",
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
          {cell.reason || (cell.result === "UNKNOWN"
            ? "明示的なポリシー根拠を確認できません。安全のため許可とは判定しません。"
            : "一致した設定ルールに基づく静的解析結果です。")}
          {cell.evaluation === "path" && <small>条件: {cell.query} · Segment全体 / 新規通信。特定IP・送信元port・IP familyはPath traceで指定できます。</small>}
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
      {!!cell.destination_ranges?.length && (
        <section className="destination-ranges" aria-label="宛先範囲別の判定">
          <h3>宛先範囲別の判定</h3>
          {cell.destination_ranges.map((range, index) => (
            <div key={index}>
              <code>{range.addresses.join(", ")}</code>
              <Status value={range.result} />
              <small>{range.protocol.toUpperCase()} · 経路 {range.path_index}{range.reason ? ` · ${range.reason}` : ""}</small>
            </div>
          ))}
        </section>
      )}
      <h3>Rule trace</h3>
      {cell.traces.length ? (
        cell.traces.map((t, i) => (
          <div className="trace" key={i}>
            <div className="trace-line">
              <span>{i + 1}</span>
              <b>{t.device}</b>
              <small>{t.interface || "zone policy"}</small>
              {t.path_index && <small>経路 {t.path_index} · {t.path_result}</small>}
            </div>
            <div className="trace-rule">
              <FileCode2 />
              <div>
                <b>
                  {t.policy}{t.sequence != null ? ` / Rule ${t.sequence}` : ""}
                </b>
                <code>{t.trace?.raw_config || t.service}</code>
                {t.reason && <small>{t.service}: {t.reason}</small>}
                {t.route && <small>経路: {t.route}{t.next_hop ? ` · next-hop: ${t.next_hop}` : ""}</small>}
                <small>
                  {t.trace && `${t.trace.source_file}:${t.trace.line_start}`}
                </small>
              </div>
            </div>
            <Status value={t.result || (t.action === "permit" ? "ALLOW" : ["deny", "reject", "restrict"].includes(t.action) ? "DENY" : "UNKNOWN")} />
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
