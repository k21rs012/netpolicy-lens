import { useEffect, useState } from "react";
import {
  AlertTriangle, ArrowRight, ChevronDown, CircleHelp, LayoutGrid, Network,
  RefreshCw, Route, Server, Wifi, WifiOff,
} from "lucide-react";

import { api } from "../api";
import { Status } from "../components/Status";
import type { Packet, ReachabilityData, TopologyData, TopologyNode } from "../types";


function packetSummary(packet: Packet) {
  const endpoint = (addresses: string[], port: number | null) =>
    `${addresses.join(", ") || "不明"}${port != null ? ` (port ${port})` : ""}`;
  return `${endpoint(packet.source_addresses, packet.source_port)} → ${endpoint(packet.destination_addresses, packet.destination_port)}`;
}

export function TopologyView() {
  const [data, setData] = useState<TopologyData | null>(null);
  const [result, setResult] = useState<ReachabilityData | null>(null);
  const [pathIndex, setPathIndex] = useState(0);
  const [src, setSrc] = useState("");
  const [dst, setDst] = useState("");
  const [protocol, setProtocol] = useState("tcp");
  const [icmpType, setIcmpType] = useState("8");
  const [port, setPort] = useState("443");
  const [sourceIp, setSourceIp] = useState("");
  const [destinationIp, setDestinationIp] = useState("");
  const [sourcePort, setSourcePort] = useState("");
  const [ipVersion, setIpVersion] = useState("4");
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
      setPathIndex(0);
      setResult(
        await api.reachability(
          src, dst, protocol, protocol === "icmp" ? "" : port,
          protocol === "icmp" ? "" : sourcePort, ipVersion, state, assumeSession,
          sourceIp, destinationIp, protocol === "icmp" ? icmpType : "",
        ),
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
  const selectedPath = result?.paths?.[pathIndex] ?? result;
  const segments = data.nodes.filter((n) => n.type === "segment");
  const hasLocalEndpoint = segments.some((n) => n.segment_type === "local");
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
  const pathSet = new Set(selectedPath?.path || []);
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
          <label className="path-endpoint">
            Source
            <select aria-describedby={hasLocalEndpoint ? "source-local-hint" : undefined} aria-label="Source" value={src} onChange={(e) => setSrc(e.target.value)}>
              {segments.map((n) => (
                <option key={n.id} value={n.entity_id}>
                  {optionLabel(n)}
                </option>
              ))}
            </select>
            {hasLocalEndpoint && <small className="path-field-hint" id="source-local-hint">機器からの通信は「機器自身」を選択</small>}
          </label>
          <label className="path-endpoint">
            Destination
            <select aria-describedby={hasLocalEndpoint ? "destination-local-hint" : undefined} aria-label="Destination" value={dst} onChange={(e) => setDst(e.target.value)}>
              {segments.map((n) => (
                <option key={n.id} value={n.entity_id}>
                  {optionLabel(n)}
                </option>
              ))}
            </select>
            {hasLocalEndpoint && <small className="path-field-hint" id="destination-local-hint">機器への通信は「機器自身」を選択</small>}
          </label>
          <label className="path-endpoint">
            Source IP
            <input aria-label="Source IP" aria-describedby="source-ip-hint" value={sourceIp} onChange={(e) => setSourceIp(e.target.value)} placeholder="省略時はSegment範囲" />
            <small className="path-field-hint" id="source-ip-hint">省略するとSegment全体を評価</small>
          </label>
          <label className="path-endpoint">
            Destination IP
            <input aria-label="Destination IP" aria-describedby="destination-ip-hint" value={destinationIp} onChange={(e) => setDestinationIp(e.target.value)} placeholder="省略時はSegment範囲" />
            <small className="path-field-hint" id="destination-ip-hint">NATを使う場合は変換前のIPを指定</small>
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
            IP family
            <select value={ipVersion} onChange={(e) => {
              setIpVersion(e.target.value);
              setIcmpType(e.target.value === "6" ? "128" : "8");
            }}>
              <option value="4">IPv4</option>
              <option value="6">IPv6</option>
            </select>
          </label>
          {protocol === "icmp" && (
            <label>
              ICMP type
              <input type="number" min="0" max="255" value={icmpType}
                onChange={(e) => setIcmpType(e.target.value)} placeholder="未指定" />
            </label>
          )}
          <label>
            Source port
            <input
              disabled={protocol === "icmp"}
              value={sourcePort}
              inputMode="numeric"
              onChange={(e) => setSourcePort(e.target.value)}
              placeholder="any"
            />
          </label>
          <label>
            Port
            <input
              disabled={protocol === "icmp"}
              value={port}
              inputMode="numeric"
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
          <div className="path-actions">
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
        </div>
        {error && (
          <div className="diff-note error">
            <AlertTriangle />
            {error}
          </div>
        )}
        {result && selectedPath && (
          <div className="path-result">
            <div className="path-verdict">
              <Status value={result.result} />
              <span>
                {result.protocol.toUpperCase()}
                {result.port ? ` / ${result.port}` : ""}
                {result.source_port ? ` / src:${result.source_port}` : ""}
                {result.ip_version ? ` / IPv${result.ip_version}` : ""}
                {result.icmp_type != null ? ` / type:${result.icmp_type}` : ""}
                {` / ${result.state}`}
                {result.assume_session ? " / session assumed" : ""}
              </span>
              <small>設定ベースの静的推定結果</small>
            </div>
            {result.flow && (
              <p>
                通信範囲: {result.flow.original.source_addresses.join(", ") || "不明"}
                {" → "}{result.flow.original.destination_addresses.join(", ") || "不明"}
              </p>
            )}
            {result.route_reason && <p className="path-summary">{result.route_reason}</p>}
            {result.paths_complete === false && (
              <p className="path-limit" role="status"><AlertTriangle />未評価の候補があるため、全経路の到達性は確定していません。</p>
            )}
            {!!result.paths?.length && result.paths.length > 1 && (
              <div className="path-options" role="group" aria-label="候補経路">
                {result.paths.map((path, index) => (
                  <button type="button" key={index} aria-pressed={pathIndex === index}
                    onClick={() => setPathIndex(index)} aria-label={`経路 ${index + 1}: ${path.result}`}>
                    <span>経路 {index + 1}</span><Status value={path.result} />
                    <small>{path.steps.map(step => nodeById[`device:${step.device}`]?.label || step.device).join(" → ") || "経路不明"}</small>
                  </button>
                ))}
              </div>
            )}
            {!!result.paths?.length && result.paths.length > 1 && (
              <p className="path-selected">経路 {pathIndex + 1} の詳細 · {selectedPath.route_reason || "下記の機器・ルールを順に評価"}</p>
            )}
            {selectedPath.flow && selectedPath.steps.some(step => step.nat?.length) && (
              <p>最終通信: {packetSummary(selectedPath.flow.current)}</p>
            )}
            {selectedPath.path.length > 0 ? (
              <div className="path-chain">
                {selectedPath.path.map((id, i) => (
                  <span key={`${id}:${i}`}>
                    <b>{nodeById[id]?.label || id}</b>
                    <small>
                      {nodeById[id]?.type === "device"
                        ? "policy hop"
                        : "segment"}
                    </small>
                    {i < selectedPath.path.length - 1 && <ArrowRight />}
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
              {selectedPath.steps.map((step, i) => (
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
                    <small>route: {step.route || "connected/inferred"}{step.next_hop ? ` · next-hop: ${step.next_hop}` : ""}</small>
                    {step.flow && (
                      <small>
                        評価アドレス: {step.flow.current.source_addresses.join(", ") || "不明"}
                        {" → "}{step.flow.current.destination_addresses.join(", ") || "不明"}
                      </small>
                    )}
                    {!!step.nat?.length && step.packet_in && step.packet_out && (
                      <small>
                        受信時: {packetSummary(step.packet_in)}
                        <br />処理後: {packetSummary(step.packet_out)}
                      </small>
                    )}
                    {!!step.nat?.length && step.nat.map((item) => (
                      <small key={`${item.type}:${item.name}`}>
                        NAT: {item.name} ({item.type}, {item.confidence})
                        {` · ${item.applied ? "適用済み" : item.type === "exclude" && item.confidence === "EXACT" ? "除外" : "未適用"}`}
                        {item.before && item.after && item.applied && (
                          <><br />変換前: {packetSummary(item.before)}<br />変換後: {packetSummary(item.after)}</>
                        )}
                        {item.evaluation_order ? ` · ${item.evaluation_order}` : ""}
                        {item.note ? ` · ${item.note}` : ""}
                      </small>
                    ))}
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
        <details className="path-help">
          <summary><CircleHelp /><span>NATと解析範囲について</span><ChevronDown className="path-help-chevron" /></summary>
          <div className="path-help-content">
            <p>NATを使う場合は、変換前の宛先Segment・IPを指定してください。対応するNATは変換後のIP・portで経路と後続機器を評価し、実際の到達先を表示します。</p>
            <p>複数経路は候補ごとに評価します。全候補が許可ならALLOW、判定が混在する場合や探索上限に達した場合はPARTIALです。変換先や処理順が不明なNATもPARTIALになります。動的ルーティング、物理配線、実際の稼働状態は評価対象外です。</p>
          </div>
        </details>
      </section>
    </div>
  );
}
