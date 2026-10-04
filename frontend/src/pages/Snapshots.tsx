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
  const shown = items.filter(item => `${item.name} ${item.id}`.toLowerCase().includes(query.toLowerCase()));
  return <section className="snapshot-manager">
    <p>保存した構成を選ぶと、Matrix・Path・機器一覧・Parser Debugの解析対象が切り替わります。</p>
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
      </div>
      <div className="snapshot-actions">
        <button disabled={busy || selected === item.id} onClick={() => void select(item.id)}>解析対象にする</button>
        <button disabled={busy} onClick={() => { setEditing(item.id); setName(item.name); setError(""); }}>名前変更</button>
        <button disabled={busy} onClick={() => { setDeleting(item); setError(""); }}>削除</button>
      </div>
    </article>)}
    {deleting && <DeleteDialog snapshot={deleting} busy={busy} error={error} close={() => setDeleting(null)} remove={() => void change(() => api.deleteSnapshot(deleting.id))} />}
  </section>;
}
