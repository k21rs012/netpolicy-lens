import { useEffect, useState } from "react";
import {
  AlertTriangle, ArrowRight, Check, CircleHelp, GitCompareArrows,
  Minus, Network, Plus, RefreshCw, ShieldCheck,
} from "lucide-react";

import { api } from "../api";
import { Status } from "../components/Status";
import type { DiffData, ObjectDiff, Snapshot } from "../types";



const changeLabel: Record<ObjectDiff["change"], string> = {
  ADDED: "追加",
  REMOVED: "削除",
  CHANGED: "変更",
};
const valueText = (value: any) =>
  Array.isArray(value) ? value.join(", ") : value == null ? "—" : String(value);
export function SnapshotDiff({ snapshots }: { snapshots: Snapshot[] }) {
  const [protocol, setProtocol] = useState("");
  const [port, setPort] = useState("");
  const [query, setQuery] = useState({ protocol: "", port: "" });
  const [before, setBefore] = useState("");
  const [after, setAfter] = useState("");
  const [data, setData] = useState<DiffData | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  useEffect(() => {
    if (snapshots.length >= 2) {
      setAfter((x) => x || snapshots[0].id);
      setBefore((x) => x || snapshots[1].id);
    }
  }, [snapshots]);
  useEffect(() => {
    let active = true;
    const controller = new AbortController();
    setData(null);
    setError("");
    if (!before || !after || before === after) {
      setBusy(false);
      return;
    }
    setBusy(true);
    api.diff(before, after, query.protocol, query.port, controller.signal)
      .then(value => { if (active) setData(value); })
      .catch(cause => { if (active) setError(String(cause)); })
      .finally(() => { if (active) setBusy(false); });
    return () => { active = false; controller.abort(); };
  }, [before, after, query]);
  if (snapshots.length < 2)
    return (
      <div className="empty diff-empty">
        <GitCompareArrows />
        <h2>比較するSnapshotが足りません</h2>
        <p>Config Importを2回以上実行すると、変更前後を比較できます。</p>
      </div>
    );
  const risky = data?.communications.filter((x) => x.new_allow.length) || [];
  const other = data?.communications.filter((x) => !x.new_allow.length) || [];
  return (
    <div className="diff-page">
      <div className="diff-controls">
        <div>
          <small>BASELINE</small>
          <label>
            <select
              aria-label="比較元Snapshot"
              value={before}
              onChange={(e) => setBefore(e.target.value)}
            >
              {snapshots.map((s) => (
                <option value={s.id} key={s.id}>
                  {s.name} · {new Date(s.created_at).toLocaleString("ja-JP")}
                </option>
              ))}
            </select>
          </label>
        </div>
        <ArrowRight />
        <div>
          <small>AFTER CHANGE</small>
          <label>
            <select
              aria-label="比較先Snapshot"
              value={after}
              onChange={(e) => setAfter(e.target.value)}
            >
              {snapshots.map((s) => (
                <option value={s.id} key={s.id}>
                  {s.name} · {new Date(s.created_at).toLocaleString("ja-JP")}
                </option>
              ))}
            </select>
          </label>
        </div>
        {busy && <RefreshCw className="spin" />}
      </div>
      <form className="diff-query" onSubmit={event => { event.preventDefault(); setData(null); setQuery({ protocol, port }); }}>
        <label>Protocol<select aria-label="比較Protocol" value={protocol} onChange={event => setProtocol(event.target.value)}>
          <option value="">未指定</option>
          {["tcp", "udp", "sctp", "icmp", "icmpv6", "gre", "esp", "ah", "ospf", "igmp"].map(value => <option key={value} value={value}>{value.toUpperCase()}</option>)}
        </select></label>
        <label>Port<input aria-label="比較Port" type="number" min="0" max="65535" step="1" value={port} onChange={event => setPort(event.target.value)} placeholder="未指定" /></label>
        <button type="submit">条件を適用</button>
        <p>ProtocolまたはPortを指定すると、Pathと同じ処理で新規通信を評価します。送信元portは未指定、Segment全体が対象です。両方未指定では設定ルールの概要を比較します。Policy・Network変更は条件で絞り込みません。</p>
      </form>
      {busy && <p role="status">比較中…</p>}
      {before === after && (
        <div className="diff-note">
          <CircleHelp />
          異なるSnapshotを選択してください。
        </div>
      )}
      {error && (
        <div className="diff-note error" role="alert">
          <AlertTriangle />
          {error}
        </div>
      )}
      {data && (
        <>
          <p className="diff-query-scope">{data.evaluation === "path" ? `経路評価: ${(data.protocol || "TCP + UDP + SCTP").toUpperCase()} / ${data.port ?? "ANY"}` : "設定ルールの概要（経路全体の通信保証ではありません）"}</p>
          <div className="diff-summary">
            <article className="risk">
              <span>新しく許可</span>
              <b>{data.summary.new_allow}</b>
              <AlertTriangle />
              <small>要レビュー</small>
            </article>
            <article>
              <span>新しく拒否</span>
              <b>{data.summary.new_deny}</b>
              <ShieldCheck />
              <small>通信影響</small>
            </article>
            <article>
              <span>変更ルール</span>
              <b>{data.summary.changed_rules}</b>
              <GitCompareArrows />
              <small>
                追加 {data.summary.added_rules} · 削除{" "}
                {data.summary.removed_rules}
              </small>
            </article>
            <article>
              <span>Network変更</span>
              <b>{data.summary.network_changes}</b>
              <Network />
              <small>IF / VLAN / Zone</small>
            </article>
          </div>
          <section className="diff-section">
            <div className="section-head">
              <div>
                <small>REACHABILITY CHANGES</small>
                <h2>通信可否の変更</h2>
              </div>
              <span>{data.communications.length} changes</span>
            </div>
            {risky.length > 0 && (
              <div className="risk-banner">
                <AlertTriangle />
                <div>
                  <b>新しく許可された通信があります</b>
                  <p>
                    意図した変更か、Rule Traceと変更元configを確認してください。
                  </p>
                </div>
              </div>
            )}
            <div className="diff-list">
              {[...risky, ...other].map((row, i) => (
                <article
                  className={
                    row.new_allow.length
                      ? "comm-change new-allow"
                      : "comm-change"
                  }
                  key={`${row.source}:${row.destination}:${i}`}
                >
                  <div className="comm-path">
                    <span>
                      <b>{row.source_label}</b>
                      <small>{row.source_device}</small>
                    </span>
                    <ArrowRight />
                    <span>
                      <b>{row.destination_label}</b>
                      <small>{row.destination_device}</small>
                    </span>
                  </div>
                  <div className="result-shift">
                    {row.before_result ? (
                      <Status value={row.before_result} />
                    ) : (
                      <span>—</span>
                    )}
                    <ArrowRight />
                    {row.after_result ? (
                      <Status value={row.after_result} />
                    ) : (
                      <span>—</span>
                    )}
                  </div>
                  <div className="service-deltas">
                    {row.new_allow.map((x) => (
                      <span className="delta allow" key={`a${x}`}>
                        <Plus />
                        ALLOW {x}
                      </span>
                    ))}
                    {row.new_deny.map((x) => (
                      <span className="delta deny" key={`d${x}`}>
                        <Plus />
                        DENY {x}
                      </span>
                    ))}
                    {row.removed_allow.map((x) => (
                      <span className="delta removed" key={`ra${x}`}>
                        <Minus />
                        ALLOW {x}
                      </span>
                    ))}
                    {row.removed_deny.map((x) => (
                      <span className="delta removed" key={`rd${x}`}>
                        <Minus />
                        DENY {x}
                      </span>
                    ))}
                  </div>
                  {data.evaluation === "path" && <details><summary>変更前後の判定根拠</summary><p>変更前: {row.before_reason || "対象なし"}</p><p>変更後: {row.after_reason || "対象なし"}</p></details>}
                  {data.evaluation === "path" && <details className="diff-ranges"><summary>宛先範囲ごとの変更前後</summary>
                    {([ ["変更前", row.before_ranges], ["変更後", row.after_ranges] ] as const).map(([label, ranges]) => <div key={label}><b>{label}</b>
                      {ranges?.length ? ranges.map((range, index) => <p key={index}><code>{range.addresses.join(", ")}</code> · {range.protocol.toUpperCase()} · <Status value={range.result} /></p>) : <p>対象なし</p>}
                    </div>)}
                  </details>}
                  {row.after_traces[0]?.trace && (
                    <code>
                      {row.after_traces[0].trace.source_file}:
                      {row.after_traces[0].trace.line_start}
                    </code>
                  )}
                </article>
              ))}
              {!data.communications.length && (
                <div className="diff-none">
                  <Check />
                  通信可否の変更はありません
                </div>
              )}
            </div>
          </section>
          <section className="diff-section">
            <div className="section-head">
              <div>
                <small>CANONICAL POLICY DIFF</small>
                <h2>Policy変更</h2>
              </div>
              <span>{data.policies.length} changes</span>
            </div>
            <ObjectDiffTable items={data.policies} />
          </section>
          <section className="diff-section">
            <div className="section-head">
              <div>
                <small>NETWORK STRUCTURE DIFF</small>
                <h2>Interface / VLAN / Zone変更</h2>
              </div>
              <span>{data.network.length} changes</span>
            </div>
            <ObjectDiffTable items={data.network} />
          </section>
        </>
      )}
    </div>
  );
}

function ObjectDiffTable({ items }: { items: ObjectDiff[] }) {
  return items.length ? (
    <div className="table-scroll">
      <table className="data-table diff-table">
        <thead>
          <tr>
            <th>変更</th>
            <th>対象</th>
            <th>変更フィールド</th>
            <th>Before</th>
            <th>After</th>
          </tr>
        </thead>
        <tbody>
          {items.map((item) => (
            <tr key={`${item.kind}:${item.key}:${item.change}`}>
              <td>
                <span className={`change ${item.change.toLowerCase()}`}>
                  {changeLabel[item.change]}
                </span>
              </td>
              <td>
                <b>{item.key}</b>
                <small>{item.kind.toUpperCase()}</small>
              </td>
              <td>
                {item.fields.length
                  ? item.fields.map((x) => <code key={x.field}>{x.field}</code>)
                  : "—"}
              </td>
              <td>
                {item.fields.length ? (
                  item.fields.map((x) => (
                    <small key={x.field}>
                      {x.field}: {valueText(x.before)}
                    </small>
                  ))
                ) : (
                  <small>{item.before?.name || item.before?.id || "—"}</small>
                )}
              </td>
              <td>
                {item.fields.length ? (
                  item.fields.map((x) => (
                    <small key={x.field}>
                      {x.field}: {valueText(x.after)}
                    </small>
                  ))
                ) : (
                  <small>{item.after?.name || item.after?.id || "—"}</small>
                )}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  ) : (
    <div className="diff-none">
      <Check />
      変更はありません
    </div>
  );
}
