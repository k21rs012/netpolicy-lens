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
    if (!before || !after || before === after) {
      setData(null);
      return;
    }
    setBusy(true);
    setError("");
    api
      .diff(before, after)
      .then(setData)
      .catch((e) => setError(String(e)))
      .finally(() => setBusy(false));
  }, [before, after]);
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
      {before === after && (
        <div className="diff-note">
          <CircleHelp />
          異なるSnapshotを選択してください。
        </div>
      )}
      {error && (
        <div className="diff-note error">
          <AlertTriangle />
          {error}
        </div>
      )}
      {data && (
        <>
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
