import { useEffect, useState } from "react";
import {
  AlertTriangle, Check, ClipboardPaste, FileCode2, Network, Plus,
  RefreshCw, Search, Server, Trash2, Upload, X,
} from "lucide-react";

import { api } from "../api";
import type { Capability } from "../types";


type PastedConfig = { id: number; filename: string; content: string };
type ImportPreview = {
  source_file: string;
  detected: { parser_id: string; confidence: number } | null;
  candidates: { parser_id: string; confidence: number }[];
  needs_confirmation: boolean;
};
export function ImportDialog({
  close,
  done,
}: {
  close: () => void;
  done: () => void;
}) {
  const [mode, setMode] = useState<"files" | "paste">("files");
  const [files, setFiles] = useState<File[]>([]);
  const [name, setName] = useState(
    `snapshot-${new Date().toISOString().slice(0, 10)}`,
  );
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [pasted, setPasted] = useState<PastedConfig[]>([
    { id: 1, filename: "device-1.conf", content: "" },
  ]);
  const [preview, setPreview] = useState<ImportPreview[]>([]);
  const [overrides, setOverrides] = useState<Record<string, string>>({});
  const [sites, setSites] = useState<Record<string, string>>({});
  const [capabilities, setCapabilities] = useState<Capability[]>([]);
  const [result, setResult] = useState<any>(null);
  useEffect(() => {
    api
      .capabilities()
      .then((items: Capability[]) =>
        setCapabilities(items.filter((x) => x.status === "available")),
      )
      .catch(() => {});
  }, []);
  const invalidate = () => {
    setPreview([]);
    setOverrides({});
    setSites({});
    setResult(null);
  };
  const update = (id: number, field: "filename" | "content", value: string) => {
    setPasted((rows) =>
      rows.map((row) => (row.id === id ? { ...row, [field]: value } : row)),
    );
    invalidate();
  };
  const add = () => {
    setPasted((rows) => [
      ...rows,
      {
        id: Math.max(0, ...rows.map((x) => x.id)) + 1,
        filename: `device-${rows.length + 1}.conf`,
        content: "",
      },
    ]);
    invalidate();
  };
  const remove = (id: number) => {
    setPasted((rows) => rows.filter((row) => row.id !== id));
    invalidate();
  };
  const validPasted = pasted.filter((x) => x.content.trim());
  const targets = () =>
    mode === "files"
      ? files
      : validPasted.map((row, index) => {
          let filename = row.filename.trim() || `device-${index + 1}.conf`;
          if (!/\.[a-z0-9]+$/i.test(filename)) filename += `.conf`;
          return new File([row.content], filename, { type: "text/plain" });
        });
  const chooseFiles = (selected: File[]) => {
    setFiles(selected);
    invalidate();
  };
  const runPreview = async () => {
    setBusy(true);
    setError("");
    try {
      const response = await api.previewConfigs(targets());
      setPreview(response.items);
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  };
  const submit = async () => {
    if (!preview.length) {
      await runPreview();
      return;
    }
    setBusy(true);
    setError("");
    try {
      const response = await api.importConfigs(
        targets(),
        name,
        overrides,
        sites,
      );
      if (response.errors?.length) setResult(response);
      else done();
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  };
  const hasTargets =
    mode === "files" ? files.length > 0 : validPasted.length > 0;
  const needsChoice = preview.some(
    (item) => item.needs_confirmation && !overrides[item.source_file],
  );
  const disabled =
    busy || !hasTargets || !!result || (preview.length > 0 && needsChoice);
  return (
    <div className="modal-backdrop">
      <div
        className={`modal import-modal ${mode === "paste" ? "paste-mode" : ""}`}
        role="dialog"
        aria-modal="true"
        aria-label="機器設定を解析"
      >
        <div className="drawer-head">
          <div>
            <small>CONFIG IMPORT</small>
            <h2>機器設定を解析</h2>
          </div>
          <button
            className="icon"
            aria-label="Import画面を閉じる"
            title="閉じる"
            onClick={close}
          >
            <X />
          </button>
        </div>
        <label className="field">
          Snapshot名
          <input value={name} onChange={(e) => setName(e.target.value)} />
        </label>
        <div className="import-tabs" role="tablist" aria-label="Import方法">
          <button
            role="tab"
            aria-selected={mode === "files"}
            className={mode === "files" ? "active" : ""}
            onClick={() => {
              setMode("files");
              invalidate();
            }}
          >
            <Upload />
            ファイル / フォルダ
          </button>
          <button
            role="tab"
            aria-selected={mode === "paste"}
            className={mode === "paste" ? "active" : ""}
            onClick={() => {
              setMode("paste");
              invalidate();
            }}
          >
            <ClipboardPaste />
            機器ごとに貼り付け
          </button>
        </div>
        {mode === "files" ? (
          <>
            <label className="dropzone">
              <Upload />
              <b>ファイルを選択、またはドロップ</b>
              <span>複数の .conf / .txt、または ZIP に対応</span>
              <input
                aria-label="設定ファイルを選択"
                type="file"
                multiple
                onChange={(e) => chooseFiles(Array.from(e.target.files || []))}
              />
              {files.length > 0 && <em>{files.length} ファイル選択済み</em>}
            </label>
            <label className="folder-picker">
              <Network />
              フォルダ内のconfigをまとめて選択
              <input
                aria-label="設定フォルダを選択"
                type="file"
                multiple
                {...({ webkitdirectory: "" } as any)}
                onChange={(e) => chooseFiles(Array.from(e.target.files || []))}
              />
            </label>
          </>
        ) : (
          <div className="paste-configs">
            <div className="paste-guide">
              <ClipboardPaste />
              <span>
                <b>機器1台につき1つの欄へconfigを貼り付け</b>
                <small>
                  Network OSとHostnameは設定内容から自動検出します。
                </small>
              </span>
              <button onClick={add}>
                <Plus />
                機器を追加
              </button>
            </div>
            {pasted.map((row, index) => (
              <article className="paste-card" key={row.id}>
                <div className="paste-card-head">
                  <span>
                    <Server />
                    <b>機器 {index + 1}</b>
                  </span>
                  <input
                    aria-label={`機器 ${index + 1} の設定名`}
                    value={row.filename}
                    onChange={(e) => update(row.id, "filename", e.target.value)}
                    placeholder="router01.conf"
                  />
                  {pasted.length > 1 && (
                    <button
                      aria-label={`機器 ${index + 1} を削除`}
                      className="icon danger"
                      onClick={() => remove(row.id)}
                    >
                      <Trash2 />
                    </button>
                  )}
                </div>
                <textarea
                  aria-label={`機器 ${index + 1} のconfig`}
                  value={row.content}
                  onChange={(e) => update(row.id, "content", e.target.value)}
                  placeholder={
                    "hostname router01\ninterface GigabitEthernet0/0\n ..."
                  }
                />
                <small>
                  {row.content.split("\n").length} lines ·{" "}
                  {row.content.length.toLocaleString()} chars
                </small>
              </article>
            ))}
          </div>
        )}
        {preview.length > 0 && (
          <div className="import-preview">
            <div>
              <b>解析プレビュー</b>
              <small>
                Network OSを確認し、必要に応じてSite名を設定してください。
              </small>
            </div>
            {preview.map((item) => (
              <article
                className={item.needs_confirmation ? "needs-confirmation" : ""}
                key={item.source_file}
              >
                <FileCode2 />
                <span>
                  <b>{item.source_file}</b>
                  <small>
                    {item.detected
                      ? `${item.detected.parser_id} · ${Math.round(item.detected.confidence * 100)}%`
                      : "検出候補なし"}
                  </small>
                </span>
                <select
                  aria-label={`${item.source_file} のNetwork OS`}
                  value={overrides[item.source_file] || ""}
                  onChange={(e) =>
                    setOverrides((value) => ({
                      ...value,
                      [item.source_file]: e.target.value,
                    }))
                  }
                >
                  <option value="">自動検出</option>
                  {capabilities.map((cap) => (
                    <option value={cap.parser_id} key={cap.parser_id}>
                      {cap.label}
                    </option>
                  ))}
                </select>
                <input
                  className="site-input"
                  aria-label={`${item.source_file} のSite`}
                  placeholder="Site（任意）"
                  value={sites[item.source_file] || ""}
                  onChange={(e) =>
                    setSites((value) => ({
                      ...value,
                      [item.source_file]: e.target.value,
                    }))
                  }
                />
                {item.needs_confirmation && !overrides[item.source_file] && (
                  <AlertTriangle />
                )}
              </article>
            ))}
          </div>
        )}
        {result && (
          <div className="import-result">
            <Check />
            <div>
              <b>{result.imported.length}台をImportしました</b>
              <p>
                {result.errors.length}
                件は解析できませんでした。成功分はSnapshotに保存済みです。
              </p>
              {result.errors.map((item: any) => (
                <small key={item.source_file}>
                  {item.source_file}: {item.error}
                </small>
              ))}
            </div>
          </div>
        )}
        {error && (
          <div className="import-error" role="alert">
            <AlertTriangle />
            {error}
          </div>
        )}
        <div className="modal-actions">
          <span>
            {preview.length
              ? `${preview.length} configを確認済み`
              : mode === "paste"
                ? `${validPasted.length} 台を検出`
                : `${files.length} ファイルを検出`}
          </span>
          <button onClick={result ? done : close}>
            {result ? "完了" : "キャンセル"}
          </button>
          {!result && (
            <button className="primary" disabled={disabled} onClick={submit}>
              {busy ? (
                <RefreshCw className="spin" />
              ) : preview.length ? (
                <Upload />
              ) : (
                <Search />
              )}
              {busy ? "処理中…" : preview.length ? "Import" : "検出プレビュー"}
            </button>
          )}
        </div>
      </div>
    </div>
  );
}
