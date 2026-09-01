from __future__ import annotations

import json
import os
import sqlite3
import uuid
from datetime import UTC, datetime
from pathlib import Path

from .models import CanonicalConfig


class SnapshotStore:
    def __init__(self, path: str | None = None):
        self.path = Path(path or os.getenv("DATABASE_PATH", "./data/netpolicy.db"))
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.connect() as con:
            con.execute("CREATE TABLE IF NOT EXISTS snapshots (id TEXT PRIMARY KEY, name TEXT NOT NULL, created_at TEXT NOT NULL, parser_version TEXT NOT NULL)")
            con.execute("CREATE TABLE IF NOT EXISTS configs (id TEXT PRIMARY KEY, snapshot_id TEXT NOT NULL, source_file TEXT NOT NULL, raw_config TEXT NOT NULL, canonical_json TEXT NOT NULL, FOREIGN KEY(snapshot_id) REFERENCES snapshots(id))")

    def connect(self):
        con = sqlite3.connect(self.path); con.row_factory = sqlite3.Row; return con

    def create(self, name: str, items: list[tuple[str, str, CanonicalConfig]]) -> str:
        snapshot_id = str(uuid.uuid4())
        with self.connect() as con:
            con.execute("INSERT INTO snapshots VALUES (?, ?, ?, ?)", (snapshot_id, name, datetime.now(UTC).isoformat(), "0.1.0"))
            con.executemany("INSERT INTO configs VALUES (?, ?, ?, ?, ?)", [(str(uuid.uuid4()), snapshot_id, filename, raw, cfg.model_dump_json()) for filename, raw, cfg in items])
        return snapshot_id

    def list(self):
        with self.connect() as con:
            return [dict(r) for r in con.execute("SELECT s.*, COUNT(c.id) device_count FROM snapshots s LEFT JOIN configs c ON c.snapshot_id=s.id GROUP BY s.id ORDER BY s.created_at DESC")]

    def load(self, snapshot_id: str) -> list[CanonicalConfig]:
        with self.connect() as con:
            rows = con.execute("SELECT canonical_json FROM configs WHERE snapshot_id=? ORDER BY source_file", (snapshot_id,)).fetchall()
        return [CanonicalConfig.model_validate(json.loads(r[0])) for r in rows]

    def get(self, snapshot_id: str):
        with self.connect() as con:
            row = con.execute("SELECT s.*, COUNT(c.id) device_count FROM snapshots s LEFT JOIN configs c ON c.snapshot_id=s.id WHERE s.id=? GROUP BY s.id", (snapshot_id,)).fetchone()
        return dict(row) if row else None

    def latest_id(self) -> str | None:
        with self.connect() as con:
            row = con.execute("SELECT id FROM snapshots ORDER BY created_at DESC LIMIT 1").fetchone()
        return row[0] if row else None
