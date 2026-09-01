from __future__ import annotations

import io
import zipfile
from datetime import datetime

from fastapi import FastAPI, File, Form, HTTPException, Query, UploadFile
from fastapi.middleware.cors import CORSMiddleware

from .analyzer import build_matrix
from .diff import compare_snapshots
from .parsers import ParserRegistry
from .sample import SAMPLES
from .storage import SnapshotStore
from .topology import analyze_reachability, build_topology

app = FastAPI(title="NetPolicy Lens API", version="0.1.0")
app.add_middleware(CORSMiddleware, allow_origins=["http://localhost:5173", "http://localhost:8080"], allow_methods=["*"], allow_headers=["*"])
store = SnapshotStore()


def _items_from_uploads(files: list[UploadFile]) -> list[tuple[str, str]]:
    items: list[tuple[str, str]] = []
    for upload in files:
        data = upload.file.read()
        if upload.filename and upload.filename.lower().endswith(".zip"):
            with zipfile.ZipFile(io.BytesIO(data)) as archive:
                for info in archive.infolist():
                    if not info.is_dir() and not info.filename.startswith("__MACOSX/"):
                        items.append((info.filename, archive.read(info).decode("utf-8", errors="replace")))
        else:
            items.append((upload.filename or "uploaded.conf", data.decode("utf-8", errors="replace")))
    return items


@app.get("/api/health")
def health(): return {"status": "ok", "version": app.version}


@app.get("/api/parser/capabilities")
def capabilities():
    planned = [
        {"parser_id": "cisco_nxos", "label": "Cisco NX-OS"},
        {"parser_id": "cisco_asa", "label": "Cisco ASA"},
        {"parser_id": "extreme_exos", "label": "ExtremeXOS"},
        {"parser_id": "mikrotik_routeros", "label": "MikroTik RouterOS"},
    ]
    defaults = {"interfaces": True, "vlans": True, "zones": False, "routes": True,
        "acl": True, "firewall_policy": False, "nat": False, "address_objects": False,
        "service_objects": False, "ipv4": True, "ipv6": True, "status": "planned"}
    return [c.model_dump() for c in ParserRegistry.capabilities()] + [{**defaults, **item} for item in planned]


@app.post("/api/configs/detect")
async def detect(file: UploadFile = File(...)):
    text = (await file.read()).decode("utf-8", errors="replace")
    return [{"parser_id": x.parser_id, "confidence": round(x.confidence, 2)} for x in ParserRegistry.detect(text)]


@app.post("/api/configs/import")
def import_configs(files: list[UploadFile] = File(...), snapshot_name: str | None = Form(None), parser_id: str | None = Form(None)):
    parsed = []
    errors = []
    for filename, raw in _items_from_uploads(files):
        try:
            cfg, ranked = ParserRegistry.parse(raw, filename, parser_id)
            parsed.append((filename, raw, cfg))
        except Exception as exc:
            errors.append({"source_file": filename, "error": str(exc)})
    if not parsed: raise HTTPException(422, detail={"message": "解析できる設定がありません", "errors": errors})
    snapshot_id = store.create(snapshot_name or f"import-{datetime.now().strftime('%Y%m%d-%H%M%S')}", parsed)
    return {"snapshot_id": snapshot_id, "imported": [cfg.device.model_dump() for _, _, cfg in parsed], "errors": errors}


@app.post("/api/sample/load")
def load_sample():
    parsed = [(name, raw, ParserRegistry.parse(raw, name)[0]) for name, raw in SAMPLES.items()]
    snapshot_id = store.create("sample-network", parsed)
    return {"snapshot_id": snapshot_id, "imported": len(parsed)}


def configs(snapshot_id: str | None):
    resolved = snapshot_id or store.latest_id()
    if not resolved: return [], None
    return store.load(resolved), resolved


@app.get("/api/snapshots")
def snapshots(): return store.list()


@app.get("/api/diff")
def snapshot_diff(before: str | None = None, after: str | None = None):
    available = store.list()
    if not before or not after:
        if len(available) < 2:
            raise HTTPException(422, "比較には2つ以上のSnapshotが必要です")
        after = after or available[0]["id"]
        before = before or next((x["id"] for x in available if x["id"] != after), None)
    before_meta, after_meta = store.get(before), store.get(after)
    if not before_meta or not after_meta:
        raise HTTPException(404, "Snapshot not found")
    if before == after:
        raise HTTPException(422, "異なるSnapshotを選択してください")
    result = compare_snapshots(store.load(before), store.load(after))
    return {"before": before_meta, "after": after_meta, **result}


@app.get("/api/devices")
def devices(snapshot_id: str | None = None):
    cfgs, resolved = configs(snapshot_id)
    return {"snapshot_id": resolved, "items": [{**c.device.model_dump(), "counts": c.counts()} for c in cfgs]}


@app.get("/api/devices/{device_id}")
def device_detail(device_id: str, snapshot_id: str | None = None):
    cfgs, _ = configs(snapshot_id)
    if cfg := next((c for c in cfgs if c.device.id == device_id), None): return cfg
    raise HTTPException(404, "Device not found")


@app.get("/api/policies")
def policies(snapshot_id: str | None = None, action: str | None = None, protocol: str | None = None, q: str | None = None):
    cfgs, resolved = configs(snapshot_id); items = [p for c in cfgs for p in c.policies]
    if action: items = [p for p in items if p.action == action]
    if protocol: items = [p for p in items if protocol.lower() in p.protocol]
    if q: items = [p for p in items if q.lower() in p.model_dump_json().lower()]
    return {"snapshot_id": resolved, "items": items}


@app.get("/api/matrix")
def matrix(snapshot_id: str | None = None, protocol: str | None = Query(None), port: str | None = Query(None)):
    cfgs, resolved = configs(snapshot_id); cells = build_matrix(cfgs)
    if protocol or port:
        needle = "/".join(x for x in ((protocol or "").upper(), port or "") if x)
        for cell in cells:
            cell.allowed = [x for x in cell.allowed if needle in x]
            cell.denied = [x for x in cell.denied if needle in x]
            if cell.result != "SAME_SEGMENT": cell.result = "PARTIAL" if cell.allowed and cell.denied else "ALLOW" if cell.allowed else "DENY" if cell.denied else "UNKNOWN"
    return {"snapshot_id": resolved, "segments": [s for c in cfgs for s in c.segments], "cells": cells}


@app.get("/api/matrix/{src}/{dst}")
def matrix_detail(src: str, dst: str, snapshot_id: str | None = None):
    data = matrix(snapshot_id)
    if cell := next((x for x in data["cells"] if x.source == src and x.destination == dst), None): return cell
    raise HTTPException(404, "Matrix cell not found")


@app.get("/api/parser/debug")
def parser_debug(snapshot_id: str | None = None):
    cfgs, resolved = configs(snapshot_id); return {"snapshot_id": resolved, "items": cfgs}


@app.get("/api/topology")
def topology(snapshot_id: str | None = None):
    cfgs, resolved = configs(snapshot_id)
    return {"snapshot_id": resolved, **build_topology(cfgs)}


@app.get("/api/reachability")
def reachability(src: str, dst: str, protocol: str = "tcp", port: int | None = None, snapshot_id: str | None = None):
    cfgs, resolved = configs(snapshot_id)
    try: result = analyze_reachability(cfgs, src, dst, protocol, port)
    except ValueError as exc: raise HTTPException(404, str(exc)) from exc
    return {"snapshot_id": resolved, **result}
