from __future__ import annotations

import io
import json
import zipfile
from datetime import datetime

from fastapi import FastAPI, File, Form, HTTPException, Query, UploadFile, Response
from pydantic import BaseModel, Field, field_validator
from fastapi.middleware.cors import CORSMiddleware
from fastapi.encoders import jsonable_encoder
from .response_cache import ResponseCache

from .analyzer import build_matrix
from .matrix_query import build_query_matrix, normalize_query
from .diff import compare_snapshots
from .parsers import ParserRegistry
from .sample import SAMPLES
from .storage import SnapshotStore
from .flow import FlowInputError
from .topology import analyze_reachability, build_topology

app = FastAPI(title="NetPolicy Lens API", version="0.1.0")
app.add_middleware(CORSMiddleware, allow_origins=["http://localhost:5173", "http://localhost:8080"], allow_methods=["*"], allow_headers=["*"])
store = SnapshotStore()
matrix_cache = ResponseCache()
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
    if store.get(resolved) is None:
        raise HTTPException(404, "Snapshot not found")
    return store.load(resolved), resolved


@app.get("/api/snapshots")
def snapshots(): return store.list()


class SnapshotRename(BaseModel):
    name: str = Field(min_length=1, max_length=128)

    @field_validator("name", mode="before")
    @classmethod
    def trim_name(cls, name: str) -> str:
        if not isinstance(name, str):
            raise ValueError("Snapshot名は文字列で指定してください")
        name = name.strip()
        if not name:
            raise ValueError("Snapshot名を入力してください")
        return name


@app.patch("/api/snapshots/{snapshot_id}")
def rename_snapshot(snapshot_id: str, payload: SnapshotRename):
    if not store.rename(snapshot_id, payload.name):
        raise HTTPException(404, "Snapshot not found")
    return store.get(snapshot_id)


@app.delete("/api/snapshots/{snapshot_id}", status_code=204)
def delete_snapshot(snapshot_id: str):
    if not store.delete(snapshot_id):
        raise HTTPException(404, "Snapshot not found")
    matrix_cache.discard_store(store)
    return Response(status_code=204)


@app.get("/api/diff")
def snapshot_diff(before: str | None = None, after: str | None = None,
                  protocol: str | None = None, port: int | None = Query(None, ge=0, le=65535)):
    try:
        protocol = normalize_query(protocol, port)
    except ValueError as exc:
        raise HTTPException(422, str(exc)) from exc
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
    result = compare_snapshots(store.load(before), store.load(after), protocol, port)
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


def matrix_data(snapshot_id: str | None, protocol: str | None, port: int | None,
                source: str | None = None, destination: str | None = None,
                *, limit: int | None = None, source_ids: list[str] | None = None,
                destination_ids: list[str] | None = None):
    try:
        protocol = normalize_query(protocol, port)
    except ValueError as exc:
        raise HTTPException(422, str(exc)) from exc
    resolved = snapshot_id or store.latest_id()
    windowed = limit is not None or source_ids is not None or destination_ids is not None
    cache_key = (store, resolved, protocol, port, limit, source, destination,
                 tuple(source_ids) if source_ids is not None else None,
                 tuple(destination_ids) if destination_ids is not None else None)
    if resolved is not None and store.get(resolved) is None:
        raise HTTPException(404, "Snapshot not found")
    if windowed and resolved is not None and (cached := matrix_cache.get(cache_key)) is not None:
        return cached
    cfgs, resolved = configs(resolved)
    segments = [s for c in cfgs for s in c.segments]
    ids = [s.id for s in segments]
    if source is not None:
        source_ids = [source]
    if destination is not None:
        destination_ids = [destination]
    if windowed:
        if any(value not in ids for value in (source_ids or []) + (destination_ids or [])):
            raise HTTPException(422, "Unknown segment in matrix window")
        source_ids = list(dict.fromkeys(source_ids)) if source_ids is not None else ids[:limit or 25]
        destination_ids = list(dict.fromkeys(destination_ids)) if destination_ids is not None else ids[:limit or 25]
    conditioned = protocol is not None or port is not None
    cells = (build_query_matrix(cfgs, protocol, port, source_ids=source_ids, destination_ids=destination_ids) if conditioned
             else build_matrix(cfgs, source_ids, destination_ids))
    result = {"snapshot_id": resolved, "evaluation": "path" if conditioned else "policy_summary",
              "protocol": protocol, "port": port, "segments": segments, "cells": cells}
    if windowed:
        result["window"] = {"source_ids": source_ids, "destination_ids": destination_ids,
                            "total_cells": len(ids) ** 2, "complete": len(source_ids) == len(ids) and len(destination_ids) == len(ids)}
    if windowed and resolved is not None:
        matrix_cache.put(cache_key, jsonable_encoder(result))
    return result


@app.get("/api/matrix")
def matrix(snapshot_id: str | None = None, protocol: str | None = None,
           port: int | None = Query(None, ge=0, le=65535),
           limit: int | None = Query(None, ge=1, le=50),
           source_ids: list[str] | None = Query(None, max_length=50),
           destination_ids: list[str] | None = Query(None, max_length=50)):
    return matrix_data(snapshot_id, protocol, port, limit=limit, source_ids=source_ids, destination_ids=destination_ids)


@app.get("/api/matrix/{src}/{dst}")
def matrix_detail(src: str, dst: str, snapshot_id: str | None = None,
                  protocol: str | None = None, port: int | None = Query(None, ge=0, le=65535)):
    data = matrix_data(snapshot_id, protocol, port, src, dst)
    if cell := next((x for x in data["cells"] if x.source == src and x.destination == dst), None):
        return cell
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
                 icmp_type: int | None = None,
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
        ip_version, source_ip, destination_ip, icmp_type,
    )
    except FlowInputError as exc: raise HTTPException(422, str(exc)) from exc
    except ValueError as exc: raise HTTPException(404, str(exc)) from exc
    return {"snapshot_id": resolved, **result}
