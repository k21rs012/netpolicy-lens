from __future__ import annotations

import io
import json
import zipfile
from datetime import datetime

from fastapi import FastAPI, File, Form, HTTPException, Query, UploadFile
from fastapi.middleware.cors import CORSMiddleware

from .analyzer import build_matrix
from .diff import compare_snapshots
from .parsers import ParserRegistry
from .sample import SAMPLES
from .storage import SnapshotStore
from .flow import FlowInputError
from .topology import analyze_reachability, build_topology

app = FastAPI(title="NetPolicy Lens API", version="0.1.0")
app.add_middleware(CORSMiddleware, allow_origins=["http://localhost:5173", "http://localhost:8080"], allow_methods=["*"], allow_headers=["*"])
store = SnapshotStore()
MAX_UPLOAD_BYTES = 20 * 1024 * 1024
MAX_ARCHIVE_BYTES = 50 * 1024 * 1024
MAX_CONFIG_FILES = 500


def _items_from_uploads(files: list[UploadFile]) -> list[tuple[str, str]]:
    items: list[tuple[str, str]] = []
    for upload in files:
        data = upload.file.read(MAX_UPLOAD_BYTES + 1)
        if len(data) > MAX_UPLOAD_BYTES:
            raise HTTPException(413, f"{upload.filename or 'upload'} exceeds the 20 MiB upload limit")
        if upload.filename and upload.filename.lower().endswith(".zip"):
            try:
                with zipfile.ZipFile(io.BytesIO(data)) as archive:
                    members = [info for info in archive.infolist()
                               if not info.is_dir() and not info.filename.startswith("__MACOSX/")]
                    if len(items) + len(members) > MAX_CONFIG_FILES:
                        raise HTTPException(413, f"archive exceeds the {MAX_CONFIG_FILES} file limit")
                    if sum(info.file_size for info in members) > MAX_ARCHIVE_BYTES:
                        raise HTTPException(413, "archive exceeds the 50 MiB expanded-size limit")
                    for info in members:
                        items.append((info.filename, archive.read(info).decode("utf-8", errors="replace")))
            except zipfile.BadZipFile as exc:
                raise HTTPException(422, f"invalid ZIP file: {upload.filename}") from exc
        else:
            items.append((upload.filename or "uploaded.conf", data.decode("utf-8", errors="replace")))
        if len(items) > MAX_CONFIG_FILES:
            raise HTTPException(413, f"import exceeds the {MAX_CONFIG_FILES} file limit")
    return items


@app.get("/api/health")
def health(): return {"status": "ok", "version": app.version}


@app.get("/api/parser/capabilities")
def capabilities():
    return [capability.model_dump() for capability in ParserRegistry.capabilities()]


@app.post("/api/configs/detect")
async def detect(file: UploadFile = File(...)):
    text = (await file.read()).decode("utf-8", errors="replace")
    return [{"parser_id": x.parser_id, "confidence": round(x.confidence, 2)} for x in ParserRegistry.detect(text)]


@app.post("/api/configs/preview")
def preview_configs(files: list[UploadFile] = File(...)):
    items = []
    for filename, raw in _items_from_uploads(files):
        ranked = ParserRegistry.detect(raw)
        candidates = [{"parser_id": item.parser_id, "confidence": round(item.confidence, 2)}
                      for item in ranked[:3]]
        items.append({"source_file": filename, "detected": candidates[0] if candidates else None,
                      "candidates": candidates, "needs_confirmation": not candidates or candidates[0]["confidence"] < 0.5})
    return {"items": items}


@app.post("/api/configs/import")
def import_configs(files: list[UploadFile] = File(...), snapshot_name: str | None = Form(None),
                   parser_id: str | None = Form(None), parser_ids: str | None = Form(None),
                   sites: str | None = Form(None)):
    try:
        overrides = json.loads(parser_ids) if parser_ids else {}
        site_map = json.loads(sites) if sites else {}
    except json.JSONDecodeError as exc:
        raise HTTPException(422, "parser_ids and sites must be JSON objects") from exc
    if not isinstance(overrides, dict) or not isinstance(site_map, dict):
        raise HTTPException(422, "parser_ids and sites must be JSON objects")
    parsed = []
    errors = []
    results = []
    for filename, raw in _items_from_uploads(files):
        try:
            selected_parser = overrides.get(filename) or parser_id
            cfg, ranked = ParserRegistry.parse(raw, filename, selected_parser)
            cfg.device.site = (str(site_map[filename]).strip() or None) if filename in site_map else None
            parsed.append((filename, raw, cfg))
            results.append({"source_file": filename, "status": "imported", "parser_id": selected_parser or ranked[0].parser_id,
                            "confidence": cfg.device.confidence, "hostname": cfg.device.hostname})
        except Exception as exc:
            errors.append({"source_file": filename, "error": str(exc)})
            results.append({"source_file": filename, "status": "error", "error": str(exc)})
    if not parsed: raise HTTPException(422, detail={"message": "解析できる設定がありません", "errors": errors})
    snapshot_id = store.create(snapshot_name or f"import-{datetime.now().strftime('%Y%m%d-%H%M%S')}", parsed)
    return {"snapshot_id": snapshot_id, "imported": [cfg.device.model_dump() for _, _, cfg in parsed],
            "errors": errors, "results": results}


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


@app.get("/api/parser/warnings")
def parser_warnings(snapshot_id: str | None = None, device: str | None = None):
    cfgs, resolved = configs(snapshot_id)
    items = [
        {**warning.model_dump(), "kind": kind}
        for config in cfgs
        for kind, warnings in (("warning", config.warnings), ("unsupported", config.unsupported))
        for warning in warnings
        if not device or warning.device == device
    ]
    return {"snapshot_id": resolved, "items": items, "count": len(items)}


@app.get("/api/topology")
def topology(snapshot_id: str | None = None):
    cfgs, resolved = configs(snapshot_id)
    return {"snapshot_id": resolved, **build_topology(cfgs)}


@app.get("/api/reachability")
def reachability(src: str, dst: str, protocol: str = "tcp", port: int | None = None,
                 state: str = "new", assume_session: bool = False,
                 source_port: int | None = None,
                 ip_version: int | None = None,
                 source_ip: str | None = None, destination_ip: str | None = None,
                 snapshot_id: str | None = None):
    cfgs, resolved = configs(snapshot_id)
    if state not in {"new", "established", "related", "invalid", "untracked"}:
        raise HTTPException(422, "Unsupported connection state")
    if port is not None and not 0 <= port <= 65535:
        raise HTTPException(422, "port must be between 0 and 65535")
    if source_port is not None and not 0 <= source_port <= 65535:
        raise HTTPException(422, "source_port must be between 0 and 65535")
    if ip_version not in {None, 4, 6}:
        raise HTTPException(422, "ip_version must be 4 or 6")
    try: result = analyze_reachability(
        cfgs, src, dst, protocol, port, state, assume_session, source_port,
        ip_version, source_ip, destination_ip,
    )
    except FlowInputError as exc: raise HTTPException(422, str(exc)) from exc
    except ValueError as exc: raise HTTPException(404, str(exc)) from exc
    return {"snapshot_id": resolved, **result}
