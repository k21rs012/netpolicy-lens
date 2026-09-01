from __future__ import annotations

import re
from typing import Any

from .models import CanonicalConfig


MASK = "<masked>"

# These patterns intentionally operate one line at a time.  The command name
# remains visible for troubleshooting while only the credential value is
# removed from stored snapshots and API responses.
SECRET_PATTERNS = (
    re.compile(r"(?i)^(\s*(?:enable\s+)?secret(?:\s+\d+)?\s+)\S+.*$"),
    re.compile(r"(?i)^(\s*(?:set\s+)?password(?:\s+encrypted)?\s+)\S+.*$"),
    re.compile(r"(?i)^(\s*username\s+\S+\s+(?:password|secret)(?:\s+\d+)?\s+)\S+.*$"),
    re.compile(r"(?i)^(\s*snmp-server\s+community\s+)\S+(.*)$"),
    re.compile(r"(?i)^(\s*set\s+snmp\s+community\s+)\S+(.*)$"),
    re.compile(r"(?i)^(\s*set\s+system\s+login\s+user\s+\S+\s+authentication\s+encrypted-password\s+)\S+.*$"),
    re.compile(r"(?i)^(\s*(?:authentication-key|privacy-key|pre-shared-key)\s+)\S+.*$"),
)


def mask_config(value: str) -> str:
    masked: list[str] = []
    for line in value.splitlines():
        result = line
        for pattern in SECRET_PATTERNS:
            if match := pattern.match(result):
                suffix = match.group(2) if pattern.groups >= 2 and match.lastindex and match.lastindex >= 2 else ""
                result = f"{match.group(1)}{MASK}{suffix}"
                break
        masked.append(result)
    return "\n".join(masked)


def mask_canonical(config: CanonicalConfig) -> CanonicalConfig:
    def walk(value: Any, key: str | None = None) -> Any:
        if isinstance(value, dict):
            return {name: walk(item, name) for name, item in value.items()}
        if isinstance(value, list):
            return [walk(item, key) for item in value]
        if isinstance(value, str) and key in {"raw_config", "config"}:
            return mask_config(value)
        return value

    return CanonicalConfig.model_validate(walk(config.model_dump()))
