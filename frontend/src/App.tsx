import { useEffect, useMemo, useState } from "react";
import {
  Activity,
  AlertTriangle,
  Braces,
  Check,
  CircleHelp,
  Clock3,
  Database,
  Filter,
  GitCompareArrows,
  LayoutGrid,
  Menu,
  Network,
  Plus,
  RefreshCw,
  Route,
  Server,
  ShieldCheck,
  Wifi,
} from "lucide-react";
import { ImportDialog } from "./components/ImportDialog";
import { Detail, Empty, Matrix } from "./components/Matrix";
import { useAppData } from "./hooks/useAppData";
import { Devices, DeviceDetailDrawer } from "./pages/Devices";
import { Capabilities, Debug } from "./pages/Diagnostics";
import { Policies } from "./pages/Policies";
import { SnapshotDiff } from "./pages/SnapshotDiff";
import { TopologyView } from "./pages/TopologyView";
import type { Cell, Device } from "./types";

const nav = [
  ["matrix", "ポリシーマトリクス", LayoutGrid],
  ["topology", "Topology / Path", Route],
  ["diff", "Snapshot Diff", GitCompareArrows],
  ["policies", "ポリシー", ShieldCheck],
  ["devices", "デバイス", Server],
  ["debug", "Parser Debug", Braces],
  ["capabilities", "対応状況", Activity],
] as const;

export default function App() {
  const [page, setPage] = useState("matrix");
  const [sidebarCollapsed, setSidebarCollapsed] = useState(() => {
    const saved = localStorage.getItem("netpolicy-sidebar-collapsed");
    return saved === null
      ? window.matchMedia("(max-width: 900px)").matches
      : saved === "1";
  });
  const {
    matrix, devices, policies, capabilities, debug, snapshots, loading,
    protocol, setProtocol, port, setPort, error, refresh, loadSample,
  } = useAppData();
  const [selected, setSelected] = useState<Cell | null>(null);
  const [selectedDevice, setSelectedDevice] = useState<Device | null>(null);
  const [dialog, setDialog] = useState(false);
  useEffect(() => {
    localStorage.setItem(
      "netpolicy-sidebar-collapsed",
      sidebarCollapsed ? "1" : "0",
    );
  }, [sidebarCollapsed]);
  const title = nav.find((n) => n[0] === page)?.[1];
  const stats = useMemo(
    () => ({
      allow: matrix.cells.filter((c) => c.result === "ALLOW").length,
      deny: matrix.cells.filter((c) => c.result === "DENY").length,
      unknown: matrix.cells.filter((c) => c.result === "UNKNOWN").length,
    }),
    [matrix],
  );
  return (
    <div className={`app ${sidebarCollapsed ? "sidebar-collapsed" : ""}`}>
      <aside className="sidebar">
        <div className="brand">
          <div>
            <Network />
          </div>
          <span>
            <b>NetPolicy</b>
            <small>LENS</small>
          </span>
        </div>
        <nav aria-label="メインナビゲーション">
          {nav.map(([id, label, Icon]) => (
            <button
              aria-current={page === id ? "page" : undefined}
              title={sidebarCollapsed ? label : undefined}
              className={page === id ? "active" : ""}
              onClick={() => setPage(id)}
              key={id}
            >
              <Icon />
              {label}
              {id === "debug" && <span className="beta">JSON</span>}
            </button>
          ))}
        </nav>
        <div className="side-foot">
          <span>
            <Wifi />
            ローカル解析
          </span>
          <small>Configは外部送信されません</small>
          <div className="version">
            v0.1.0 <i /> MVP
          </div>
        </div>
      </aside>
      <main>
        <header>
          <div>
            <button
              className="mobile-menu"
              aria-label={sidebarCollapsed ? "メニューを開く" : "メニューを畳む"}
              title={sidebarCollapsed ? "メニューを開く" : "メニューを畳む"}
              onClick={() => setSidebarCollapsed((value) => !value)}
            >
              <Menu />
            </button>
            <small>NETWORK ANALYSIS</small>
            <h1>{title}</h1>
          </div>
          <div className="header-actions">
            <button
              onClick={() => refresh()}
              className="icon"
              aria-label="データを再読み込み"
              title="再読み込み"
            >
              <RefreshCw />
            </button>
            <button className="primary" onClick={() => setDialog(true)}>
              <Plus />
              <span>Config Import</span>
            </button>
          </div>
        </header>
        {error && (
          <div className="diff-note error" role="alert">
            <AlertTriangle />
            データを読み込めませんでした: {error}
          </div>
        )}
        {page === "matrix" && (
          <>
            <div className="overview">
              <div>
                <span>Segments</span>
                <b>{matrix.segments.length}</b>
                <Network />
              </div>
              <div>
                <span>許可パス</span>
                <b>{stats.allow}</b>
                <Check />
              </div>
              <div>
                <span>拒否パス</span>
                <b>{stats.deny}</b>
                <ShieldCheck />
              </div>
              <div>
                <span>要確認</span>
                <b>{stats.unknown}</b>
                <CircleHelp />
              </div>
            </div>
            <div className="matrix-tools">
              <div>
                <Filter />
                <b>表示条件</b>
              </div>
              <label>
                Protocol
                <select
                  aria-label="プロトコル"
                  value={protocol}
                  onChange={(e) => setProtocol(e.target.value)}
                >
                  <option value="">ALL</option>
                  <option>tcp</option>
                  <option>udp</option>
                  <option>icmp</option>
                </select>
              </label>
              <label>
                Port
                <input
                  aria-label="ポート"
                  inputMode="numeric"
                  value={port}
                  onChange={(e) => setPort(e.target.value)}
                  placeholder="any"
                />
              </label>
              <span className="snapshot">
                <Clock3 />
                {matrix.snapshot_id ? "Latest snapshot" : "No snapshot"}
              </span>
            </div>
            {loading ? (
              <div className="loading">
                <RefreshCw className="spin" />
                解析結果を読み込み中
              </div>
            ) : matrix.segments.length ? (
              <Matrix data={matrix} onCell={setSelected} />
            ) : (
              <Empty load={loadSample} />
            )}
          </>
        )}
        {page === "topology" && <TopologyView />}
        {page === "diff" && <SnapshotDiff snapshots={snapshots} />}{" "}
        {page === "policies" && <Policies items={policies} />}{" "}
        {page === "devices" && (
          <Devices items={devices} onSelect={setSelectedDevice} />
        )}{" "}
        {page === "capabilities" && <Capabilities items={capabilities} />}{" "}
        {page === "debug" && <Debug data={debug} />}
        <footer className="main-footer">
          <span>
            <Database />
            SQLite snapshot
          </span>
          <span>
            <GitCompareArrows />
            Snapshot diff active
          </span>
          <span>
            <Route />
            Multi-hop path analysis
          </span>
        </footer>
      </main>
      {selected && (
        <>
          <div className="shade" onClick={() => setSelected(null)} />
          <Detail
            cell={selected}
            segments={matrix.segments}
            close={() => setSelected(null)}
          />
        </>
      )}
      {selectedDevice && (
        <>
          <div className="shade" onClick={() => setSelectedDevice(null)} />
          <DeviceDetailDrawer
            device={selectedDevice}
            close={() => setSelectedDevice(null)}
          />
        </>
      )}
      {dialog && (
        <ImportDialog
          close={() => setDialog(false)}
          done={() => {
            setDialog(false);
            refresh();
          }}
        />
      )}
    </div>
  );
}
