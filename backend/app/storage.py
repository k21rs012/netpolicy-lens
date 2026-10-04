from __future__ import annotations

import os
import json
import sqlite3
import uuid
from datetime import UTC, datetime
from pathlib import Path

from .models import CanonicalConfig
from .security import mask_canonical, mask_config


class SnapshotStore:
    def __init__(self, path: str | None = None):
        self.path = Path(path or os.getenv("DATABASE_PATH", "./data/netpolicy.db"))
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.connect() as con:
            con.execute("CREATE TABLE IF NOT EXISTS snapshots (id TEXT PRIMARY KEY, name TEXT NOT NULL, created_at TEXT NOT NULL, parser_version TEXT NOT NULL)")
            con.execute("CREATE TABLE IF NOT EXISTS configs (id TEXT PRIMARY KEY, snapshot_id TEXT NOT NULL, source_file TEXT NOT NULL, raw_config TEXT NOT NULL, canonical_json TEXT NOT NULL, FOREIGN KEY(snapshot_id) REFERENCES snapshots(id))")
            if "restored_from" not in {row[1] for row in con.execute("PRAGMA table_info(snapshots)")}:
                con.execute("ALTER TABLE snapshots ADD COLUMN restored_from TEXT")
            con.execute("CREATE INDEX IF NOT EXISTS configs_snapshot_file ON configs(snapshot_id, source_file)")

    def connect(self):
        con = sqlite3.connect(self.path)
        con.row_factory = sqlite3.Row
        con.execute("PRAGMA foreign_keys = ON")
        return con

    def create(self, name: str, items: list[tuple[str, str, CanonicalConfig]], *,
               parser_version: str = "0.1.0", restored_from: dict | None = None) -> str:
        snapshot_id = str(uuid.uuid4())
        with self.connect() as con:
            con.execute("INSERT INTO snapshots (id, name, created_at, parser_version, restored_from) VALUES (?, ?, ?, ?, ?)",
                        (snapshot_id, name, datetime.now(UTC).isoformat(), parser_version, json.dumps(restored_from) if restored_from else None))
            con.executemany("INSERT INTO configs VALUES (?, ?, ?, ?, ?)", [
                (str(uuid.uuid4()), snapshot_id, filename, mask_config(raw), mask_canonical(cfg).model_dump_json())
                for filename, raw, cfg in items
            ])
        return snapshot_id

    def list(self):
        with self.connect() as con:
            return [self._metadata(r) for r in con.execute("SELECT s.*, COUNT(c.id) device_count FROM snapshots s LEFT JOIN configs c ON c.snapshot_id=s.id GROUP BY s.id ORDER BY s.created_at DESC")]

    def load(self, snapshot_id: str) -> list[CanonicalConfig]:
        with self.connect() as con:
            rows = con.execute("SELECT canonical_json FROM configs WHERE snapshot_id=? ORDER BY source_file", (snapshot_id,)).fetchall()
        return [CanonicalConfig.model_validate_json(r[0]) for r in rows]

    def get(self, snapshot_id: str):
        with self.connect() as con:
            row = con.execute("SELECT s.*, COUNT(c.id) device_count FROM snapshots s LEFT JOIN configs c ON c.snapshot_id=s.id WHERE s.id=? GROUP BY s.id", (snapshot_id,)).fetchone()
        return self._metadata(row) if row else None

    def latest_id(self) -> str | None:
        with self.connect() as con:
            row = con.execute("SELECT id FROM snapshots ORDER BY created_at DESC LIMIT 1").fetchone()
        return row[0] if row else None

    def rename(self, snapshot_id: str, name: str) -> bool:
        with self.connect() as con:
            return con.execute("UPDATE snapshots SET name=? WHERE id=?", (name, snapshot_id)).rowcount == 1

    def delete(self, snapshot_id: str) -> bool:
        with self.connect() as con:
            if con.execute("SELECT 1 FROM snapshots WHERE id=?", (snapshot_id,)).fetchone() is None:
                return False
            con.execute("DELETE FROM configs WHERE snapshot_id=?", (snapshot_id,))
            con.execute("DELETE FROM snapshots WHERE id=?", (snapshot_id,))
        return True

    @staticmethod
    def _metadata(row):
        result = dict(row)
        result["restored_from"] = json.loads(result["restored_from"]) if result["restored_from"] else None
        return result

    def backup(self, snapshot_id: str):
        # A read transaction keeps metadata and configs from different revisions
        # out of a single archive when rename/delete happens concurrently.
        with self.connect() as con:
            con.execute("BEGIN")
            row = con.execute("SELECT s.*, COUNT(c.id) device_count FROM snapshots s LEFT JOIN configs c ON c.snapshot_id=s.id WHERE s.id=? GROUP BY s.id", (snapshot_id,)).fetchone()
            if row is None:
                return None
            rows = con.execute("SELECT source_file, raw_config, canonical_json FROM configs WHERE snapshot_id=? ORDER BY source_file", (snapshot_id,)).fetchall()
        return self._metadata(row), [(r[0], r[1], CanonicalConfig.model_validate_json(r[2])) for r in rows]
