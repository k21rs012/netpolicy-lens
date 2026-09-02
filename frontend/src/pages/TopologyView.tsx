import { useEffect, useState } from "react";
import {
  AlertTriangle, ArrowRight, CircleHelp, LayoutGrid, Network,
  RefreshCw, Route, Server, Wifi, WifiOff,
} from "lucide-react";

import { api } from "../api";
import { Status } from "../components/Status";
import type { ReachabilityData, TopologyData, TopologyNode } from "../types";


export function TopologyView() {
  const [data, setData] = useState<TopologyData | null>(null);
  const [result, setResult] = useState<ReachabilityData | null>(null);
  const [src, setSrc] = useState("");
  const [dst, setDst] = useState("");
  const [protocol, setProtocol] = useState("tcp");
  const [port, setPort] = useState("443");
  const [state, setState] = useState("new");
  const [assumeSession, setAssumeSession] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  useEffect(() => {
    api
      .topology()
      .then((value: TopologyData) => {
        setData(value);
        const segments = value.nodes.filter((n) => n.type === "segment");
        setSrc(segments[0]?.entity_id || "");
        setDst(segments[1]?.entity_id || segments[0]?.entity_id || "");
      })
      .catch((e) => setError(String(e)));
  }, []);
  const analyze = async () => {
    if (!src || !dst) return;
    setBusy(true);
    setError("");
    try {
      setResult(
        await api.reachability(src, dst, protocol, port, state, assumeSession),
      );
    } catch (e) {
      setError(String(e));
    } finally {
      setBusy(false);
    }
  };
  if (!data)
    return error ? (
      <div className="empty error-state" role="alert">
        <AlertTriangle />
        <h2>Topologyを読み込めませんでした</h2>
        <p>{error}</p>
      </div>
    ) : (
      <div className="loading">
        <RefreshCw className="spin" />
        Topologyを生成中
      </div>
    );
  const segments = data.nodes.filter((n) => n.type === "segment");
  const devices = data.nodes.filter((n) => n.type === "device");
  const segmentPositions = Object.fromEntries(
    segments.map((n, i) => [n.id, { x: 90 + i * 150, y: 285 }]),
  );
  const positions: Record<string, { x: number; y: number }> = {
    ...segmentPositions,
  };
  devices.forEach((n, i) => {
    const owned = data.edges
      .filter((e) => e.type === "owns" && e.source === n.id)
      .map((e) => segmentPositions[e.target]?.x)
      .filter(Boolean);
    positions[n.id] = {
      x: owned.length
        ? owned.reduce((a, b) => a + b, 0) / owned.length
        : 90 + i * 170,
      y: 75,
    };
  });
  const width = Math.max(1040, segments.length * 150 + 30);
  const nodeById = Object.fromEntries(data.nodes.map((n) => [n.id, n]));
  const pathSet = new Set(result?.path || []);
  const optionLabel = (n: TopologyNode) =>
    `${n.label} (${n.device || n.subtitle})`;
  return (
    <div className="topology-page">
      <div className="topology-summary">
        <article>
          <Network />
          <span>
            Devices<b>{data.summary.devices}</b>
          </span>
        </article>
        <article>
          <LayoutGrid />
          <span>
            Segments<b>{data.summary.segments}</b>
          </span>
        </article>
        <article>
          <Wifi />
          <span>
            推定リンク<b>{data.summary.adjacencies}</b>
          </span>
        </article>
        <div>
          <b>Topology confidence</b>
          <p>同一サブネットの機器間リンクは設定情報からの推定です。</p>
        </div>
      </div>
      <section className="topology-panel">
        <div className="section-head">
          <div>
            <small>CANONICAL TOPOLOGY</small>
            <h2>Network graph</h2>
          </div>
          <div className="topology-legend">
            <span>
              <i className="exact" />
              所有関係
            </span>
            <span>
              <i className="inferred" />
              推定接続
            </span>
          </div>
        </div>
        <div className="topology-canvas">
          <svg viewBox={`0 0 ${width} 390`} style={{ width, height: 390 }}>
            {data.edges.map((e) => {
              const a = positions[e.source],
                b = positions[e.target];
              if (!a || !b) return null;
              const active = pathSet.has(e.source) && pathSet.has(e.target);
              return (
                <g key={e.id}>
                  <line
                    className={`${e.type} ${active ? "path-active" : ""}`}
                    x1={a.x}
                    y1={a.y}
                    x2={b.x}
                    y2={b.y}
                  />
                  {e.type === "adjacent" && (
                    <text x={(a.x + b.x) / 2} y={(a.y + b.y) / 2 - 8}>
                      {e.label}
                    </text>
                  )}
                </g>
              );
            })}
            {data.nodes.map((n) => {
              const p = positions[n.id];
              const active = pathSet.has(n.id);
              return (
                <g
                  key={n.id}
                  className={`topology-node ${n.type} ${active ? "path-active" : ""}`}
                  transform={`translate(${p.x},${p.y})`}
                >
                  <rect x={-62} y={-27} width={124} height={54} rx={8} />
                  {n.type === "device" ? (
                    <Server x={-53} y={-9} />
                  ) : (
                    <Network x={-53} y={-9} />
                  )}
                  <text className="node-label" x={-29} y={-4}>
                    {n.label.slice(0, 17)}
                  </text>
                  <text className="node-subtitle" x={-29} y={12}>
                    {n.subtitle.slice(0, 21)}
                  </text>
                </g>
              );
            })}
          </svg>
        </div>
      </section>
      <section className="path-panel">
        <div className="section-head">
          <div>
            <small>END-TO-END REACHABILITY</small>
            <h2>Path trace</h2>
          </div>
          <Route />
        </div>
        <div className="path-controls">
          <label>
            Source
            <select value={src} onChange={(e) => setSrc(e.target.value)}>
              {segments.map((n) => (
                <option key={n.id} value={n.entity_id}>
                  {optionLabel(n)}
                </option>
              ))}
            </select>
          </label>
          <ArrowRight />
          <label>
            Destination
            <select value={dst} onChange={(e) => setDst(e.target.value)}>
              {segments.map((n) => (
                <option key={n.id} value={n.entity_id}>
                  {optionLabel(n)}
                </option>
              ))}
            </select>
          </label>
          <label>
            Protocol
            <select
              value={protocol}
              onChange={(e) => setProtocol(e.target.value)}
            >
              <option>tcp</option>
              <option>udp</option>
              <option>icmp</option>
            </select>
          </label>
          <label>
            Port
            <input
              value={port}
              onChange={(e) => setPort(e.target.value)}
              placeholder="any"
            />
          </label>
          <label>
            State
            <select
              value={state}
              onChange={(e) => {
                setState(e.target.value);
                if (e.target.value === "new") setAssumeSession(false);
              }}
            >
              <option value="new">new</option>
              <option value="established">established</option>
              <option value="related">related</option>
            </select>
          </label>
          {state !== "new" && (
            <label className="session-assumption">
              <input
                type="checkbox"
                checked={assumeSession}
                onChange={(e) => setAssumeSession(e.target.checked)}
              />
              既存セッションを仮定
            </label>
          )}
          <button className="primary" onClick={analyze} disabled={busy}>
            {busy ? <RefreshCw className="spin" /> : <Route />}経路を解析
          </button>
        </div>
        {error && (
          <div className="diff-note error">
            <AlertTriangle />
            {error}
          </div>
        )}
        {result && (
          <div className="path-result">
            <div className="path-verdict">
              <Status value={result.result} />
              <span>
                {result.protocol.toUpperCase()}
                {result.port ? ` / ${result.port}` : ""}
                {` / ${result.state}`}
                {result.assume_session ? " / session assumed" : ""}
              </span>
              <small>設定ベースの静的推定結果</small>
            </div>
            {result.path.length > 0 ? (
              <div className="path-chain">
                {result.path.map((id, i) => (
                  <span key={id}>
                    <b>{nodeById[id]?.label || id}</b>
                    <small>
                      {nodeById[id]?.type === "device"
                        ? "policy hop"
                        : "segment"}
                    </small>
                    {i < result.path.length - 1 && <ArrowRight />}
                  </span>
                ))}
              </div>
            ) : (
              <div className="no-route">
                <WifiOff />
                <p>設定から到達可能な経路を構成できません。</p>
              </div>
            )}
            <div className="hop-list">
              {result.steps.map((step, i) => (
                <article key={`${step.device}:${i}`}>
                  <span className="hop-number">{i + 1}</span>
                  <div>
                    <small>HOP {i + 1}</small>
                    <h3>
                      {nodeById[`device:${step.device}`]?.label || step.device}
                    </h3>
                    <p>
                      {nodeById[`segment:${step.ingress}`]?.label} →{" "}
                      {nodeById[`segment:${step.egress}`]?.label}
                    </p>
                  </div>
                  <div className="hop-reason">
                    <b>{step.reason}</b>
                    <small>route: {step.route || "connected/inferred"}</small>
                    {!!step.nat?.length && <small>NAT: {step.nat.map((item) => item.name).join(", ")}</small>}
                    {step.trace && (
                      <>
                        <code>{step.trace.raw_config}</code>
                        <small>
                          {step.trace.source_file}:{step.trace.line_start}
                        </small>
                      </>
                    )}
                  </div>
                  <Status value={step.result} />
                </article>
              ))}
            </div>
          </div>
        )}
        <p className="topology-note">
          <CircleHelp />
          静的ルートと設定上のNAT・通信stateを評価します。動的ルーティング、物理配線、実際の稼働状態は含まれず、根拠不足はUNKNOWNとして扱います。
        </p>
      </section>
    </div>
  );
}
