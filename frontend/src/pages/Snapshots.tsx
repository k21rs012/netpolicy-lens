import { useEffect, useRef, useState } from "react";
import { api } from "../api";
import type { Snapshot } from "../types";

function DeleteDialog({ snapshot, busy, error, close, remove }: {
  snapshot: Snapshot; busy: boolean; error: string; close: () => void; remove: () => void;
}) {
  const ref = useRef<HTMLDialogElement>(null);
  useEffect(() => { ref.current?.showModal(); }, []);
  return <dialog ref={ref} className="snapshot-delete" aria-labelledby="snapshot-delete-title"
    onCancel={event => { event.preventDefault(); if (!busy) close(); }}>
    <h2 id="snapshot-delete-title">Snapshotを削除しますか？</h2>
    <p><strong>{snapshot.name}</strong>（{snapshot.device_count}台）と保存されたconfigを削除します。元に戻せません。</p>
    <p>選択中のSnapshotを削除すると、残っている最新のSnapshotに切り替わります。</p>
    {error && <p role="alert">{error}</p>}
    <div className="snapshot-actions">
      <button autoFocus disabled={busy} onClick={close}>キャンセル</button>
      <button disabled={busy} className="snapshot-danger" onClick={remove}>削除を実行</button>
    </div>
  </dialog>;
}

export function Snapshots({ items, selected, select, refresh }: {
  items: Snapshot[]; selected: string; select: (id: string) => Promise<void>; refresh: () => Promise<void>;
}) {
  const [file, setFile] = useState<File | null>(null);
  const [preview, setPreview] = useState<{ snapshot: Snapshot; suggested_name: string } | null>(null);
  const [restoreName, setRestoreName] = useState("");
  const [notice, setNotice] = useState("");
  const fileInput = useRef<HTMLInputElement>(null);
  const [query, setQuery] = useState("");
  const [editing, setEditing] = useState<string | null>(null);
  const [name, setName] = useState("");
  const [deleting, setDeleting] = useState<Snapshot | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const change = async (action: () => Promise<unknown>) => {
    setBusy(true); setError("");
    try { await action(); setEditing(null); setDeleting(null); await refresh(); }
    catch (cause) { setError(cause instanceof Error ? cause.message : String(cause)); }
    finally { setBusy(false); }
  };
  const backup = async (item: Snapshot) => {
    setBusy(true); setError(""); setNotice("");
    try {
      const blob = await api.backupSnapshot(item.id);
      const url = URL.createObjectURL(blob);
      const link = document.createElement("a");
      link.href = url; link.download = `snapshot-${item.id}.netpolicy.json`;
      document.body.appendChild(link); link.click(); link.remove();
      setTimeout(() => URL.revokeObjectURL(url), 1000);
      setNotice(`${item.name} のバックアップを書き出しました。`);
    } catch (cause) { setError(cause instanceof Error ? cause.message : String(cause)); }
    finally { setBusy(false); }
  };
  const inspect = async () => {
    if (!file) return;
    setBusy(true); setError(""); setNotice(""); setPreview(null);
    try {
      if (file.size > 50 * 1024 * 1024) throw new Error("バックアップは50 MiB以下にしてください");
      const value = await api.previewRestore(file);
      setPreview(value); setRestoreName(value.suggested_name);
    } catch (cause) { setError(cause instanceof Error ? cause.message : String(cause)); }
    finally { setBusy(false); }
  };
  const restore = async () => {
    if (!file || !preview) return;
    setBusy(true); setError(""); setNotice("");
    try {
      const restored = await api.restoreSnapshot(file, restoreName.trim());
      setPreview(null); setFile(null); setQuery("");
      if (fileInput.current) fileInput.current.value = "";
      await select(restored.id);
      setNotice(`${restored.name} を新しいSnapshotとして復元しました。`);
    } catch (cause) { setError(cause instanceof Error ? cause.message : String(cause)); }
    finally { setBusy(false); }
  };
  const shown = items.filter(item => `${item.name} ${item.id}`.toLowerCase().includes(query.toLowerCase()));
  return <section className="snapshot-manager">
    <p>保存した構成を選ぶと、Matrix・Path・機器一覧・Parser Debugの解析対象が切り替わります。</p>
    <section className="snapshot-restore" aria-label="Snapshotの復元">
      <h3>バックアップから復元</h3>
      <p>保存configと解析モデルを新しいSnapshotとして追加します。既存のSnapshotは上書きしません。</p>
      <label>バックアップファイル（JSON・最大50 MiB）<input ref={fileInput} aria-label="Snapshotバックアップファイル" type="file" accept=".json,application/json" disabled={busy}
        onChange={event => { setFile(event.target.files?.[0] || null); setPreview(null); setError(""); setNotice(""); }} /></label>
      <button disabled={busy || !file} onClick={() => void inspect()}>内容を確認</button>
      {preview && <form onSubmit={event => { event.preventDefault(); void restore(); }}>
        <p><strong>{preview.snapshot.name}</strong> · {preview.snapshot.device_count}台 · {new Date(preview.snapshot.created_at).toLocaleString()}</p>
        <label>復元後の名前<input aria-label="復元後のSnapshot名" value={restoreName} maxLength={128} disabled={busy} onChange={event => setRestoreName(event.target.value)} /></label>
        <button type="submit" disabled={busy || !restoreName.trim()}>復元する</button>
      </form>}
      {busy && <p role="status">処理中…</p>}
    </section>
    {notice && <p role="status">{notice}</p>}
    <label>履歴を検索<input aria-label="Snapshotを検索" value={query} onChange={event => setQuery(event.target.value)} /></label>
    {error && !deleting && <p role="alert">{error}</p>}
    {!shown.length && <p>{items.length ? "一致するSnapshotがありません。" : "まだSnapshotがありません。Config Importから設定を取り込んでください。"}</p>}
    {shown.map(item => <article key={item.id} aria-label={`Snapshot ${item.name}`}>
      <div className="snapshot-info">
        {editing === item.id ? <form onSubmit={event => { event.preventDefault(); void change(() => api.renameSnapshot(item.id, name.trim())); }}>
          <label>新しい名前<input autoFocus aria-label="新しいSnapshot名" maxLength={128} value={name} onChange={event => setName(event.target.value)} /></label>
          <div className="snapshot-actions"><button disabled={busy || !name.trim()} type="submit">保存</button><button disabled={busy} type="button" onClick={() => setEditing(null)}>キャンセル</button></div>
        </form> : <h3>{item.name} {selected === item.id && <small>選択中</small>}</h3>}
        <p>{new Date(item.created_at).toLocaleString()} · {item.device_count}台</p>
        <code>{item.id}</code>
        {item.restored_from && <p>復元元: {item.restored_from.name} · {new Date(item.restored_from.created_at).toLocaleString()}</p>}
      </div>
      <div className="snapshot-actions">
        <button disabled={busy || selected === item.id} onClick={() => void select(item.id)}>解析対象にする</button>
        <button disabled={busy} onClick={() => void backup(item)}>バックアップ</button>
        <button disabled={busy} onClick={() => { setEditing(item.id); setName(item.name); setError(""); }}>名前変更</button>
        <button disabled={busy} onClick={() => { setDeleting(item); setError(""); }}>削除</button>
      </div>
    </article>)}
    {deleting && <DeleteDialog snapshot={deleting} busy={busy} error={error} close={() => setDeleting(null)} remove={() => void change(() => api.deleteSnapshot(deleting.id))} />}
  </section>;
}
