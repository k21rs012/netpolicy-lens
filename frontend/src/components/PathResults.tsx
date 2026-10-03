import { AlertTriangle, ArrowRight, WifiOff } from "lucide-react";
import { Status } from "./Status";
import type { Packet, ReachabilityData, TopologyNode } from "../types";

function packetSummary(packet: Packet) {
  const endpoint = (addresses: string[], port: number | null) =>
    `${addresses.join(", ") || "不明"}${port != null ? ` (port ${port})` : ""}`;
  return `${endpoint(packet.source_addresses, packet.source_port)} → ${endpoint(packet.destination_addresses, packet.destination_port)}`;
}

interface Props {
  result: ReachabilityData;
  pathIndex: number;
  onSelectPath: (index: number) => void;
  nodeById: Record<string, TopologyNode>;
}

export function PathResults({ result, pathIndex, onSelectPath, nodeById }: Props) {
  const selectedPath = result.paths?.[pathIndex] ?? result;
  return (
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
              onClick={() => onSelectPath(index)} aria-label={`経路 ${index + 1}: ${path.result}`}>
              <span>経路 {index + 1}</span><Status value={path.result} />
              {!!path.destination_ranges?.length && <small>宛先: {path.destination_ranges.join(", ")}</small>}
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
  );
}
