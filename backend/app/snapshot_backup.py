"""Versioned, bounded JSON backups. Uploaded config text is never executed or reparsed."""
from __future__ import annotations

import hashlib
import hmac
import json
import ipaddress
from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator

from .models import CanonicalConfig
from .security import mask_canonical, mask_config

MAX_BACKUP_BYTES = 50 * 1024 * 1024
MAX_BACKUP_CONFIGS = 500


class BackupInvalid(ValueError):
    pass


class BackupModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class SnapshotOrigin(BackupModel):
    id: str = Field(min_length=1)
    name: str = Field(min_length=1)
    created_at: str
    parser_version: str = Field(min_length=1)

    @field_validator("created_at")
    @classmethod
    def timestamp(cls, value: str) -> str:
        if datetime.fromisoformat(value).tzinfo is None:
            raise ValueError("timezone required")
        return value


class BackupMetadata(SnapshotOrigin):
    device_count: int = Field(ge=1, le=MAX_BACKUP_CONFIGS)
    restored_from: SnapshotOrigin | None = None


class BackupConfig(BackupModel):
    source_file: str = Field(min_length=1)
    raw_config: str
    canonical: CanonicalConfig


class SnapshotBackup(BackupModel):
    format: Literal["netpolicy-lens-snapshot"]
    format_version: int
    canonical_schema_version: int
    snapshot: BackupMetadata
    configs: list[BackupConfig] = Field(min_length=1, max_length=MAX_BACKUP_CONFIGS)
    checksum: str = Field(pattern=r"^[0-9a-f]{64}$")

    @field_validator("format_version", "canonical_schema_version")
    @classmethod
    def version(cls, value: int) -> int:
        if value != 1:
            raise ValueError("unsupported backup version")
        return value


def _json(value: dict) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")


def checksum(payload: dict) -> str:
    return hashlib.sha256(_json({k: v for k, v in payload.items() if k != "checksum"})).hexdigest()


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise BackupInvalid("JSONに重複したキーがあります")
        result[key] = value
    return result


def _same_shape(raw, normalized):
    # Canonical models allow defaults/extra fields for parsers. Backup restore
    # must reject missing or ignored fields instead of silently changing policy.
    if isinstance(raw, dict):
        if not isinstance(normalized, dict) or raw.keys() != normalized.keys():
            raise BackupInvalid("解析モデルのフィールドが欠落、または未対応です")
        for key in raw:
            _same_shape(raw[key], normalized[key])
    elif isinstance(raw, list):
        for item, other in zip(raw, normalized, strict=True):
            _same_shape(item, other)


def decode_backup(data: bytes) -> SnapshotBackup:
    try:
        raw = json.loads(data.decode("utf-8"), object_pairs_hook=_unique_object)
        backup = SnapshotBackup.model_validate_json(_json(raw), strict=True)
        if not hmac.compare_digest(backup.checksum, checksum(raw)):
            raise BackupInvalid("バックアップの整合性チェックに失敗しました")
        if backup.snapshot.device_count != len(backup.configs):
            raise BackupInvalid("機器数と保存config数が一致しません")
        devices, segments = set(), set()
        for item, original in zip(backup.configs, raw["configs"], strict=True):
            cfg = item.canonical
            _same_shape(original["canonical"], cfg.model_dump(mode="json"))
            if not cfg.device.id or cfg.device.id in devices:
                raise BackupInvalid("機器IDが空または重複しています")
            devices.add(cfg.device.id)
            for segment in cfg.segments:
                if not segment.id or segment.id in segments:
                    raise BackupInvalid("Segment IDが空または重複しています")
                segments.add(segment.id)
                for network in segment.networks:
                    ipaddress.ip_network(network, strict=False)
            for interface in cfg.interfaces:
                for address in interface.addresses:
                    ipaddress.ip_interface(address)
            for route in cfg.routes:
                ipaddress.ip_network(route.destination, strict=False)
            for field in ("interfaces", "vlans", "segments", "zones", "routes", "policies", "nat", "address_objects", "service_objects", "warnings", "unsupported"):
                if any(value.device != cfg.device.id for value in getattr(cfg, field)):
                    raise BackupInvalid("解析モデルの機器参照が一致しません")
        return backup
    except BackupInvalid:
        raise
    except (ValueError, TypeError, KeyError, AttributeError, RecursionError, ValidationError) as exc:
        # Do not echo validation inputs: they can contain config credentials.
        raise BackupInvalid("バックアップの形式・バージョン・解析モデルを確認してください") from exc


def encode_backup(metadata: dict, items: list[tuple[str, str, CanonicalConfig]]) -> bytes:
    payload = {
        "format": "netpolicy-lens-snapshot", "format_version": 1, "canonical_schema_version": 1,
        "snapshot": metadata,
        "configs": [{"source_file": filename, "raw_config": mask_config(raw),
                     "canonical": mask_canonical(cfg).model_dump(mode="json")} for filename, raw, cfg in items],
    }
    payload["checksum"] = checksum(payload)
    data = _json(payload)
    if len(data) > MAX_BACKUP_BYTES:
        raise BackupInvalid("バックアップが50 MiBの上限を超えています")
    decode_backup(data)  # Never offer an archive this version cannot restore.
    return data
