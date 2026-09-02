from __future__ import annotations

import ipaddress
import re
import shlex


def slug(value: str) -> str:
    return re.sub(r"[^a-zA-Z0-9_-]+", "-", value).strip("-").lower()


def hostname_from(config: str, fallback: str) -> str:
    patterns = [r"(?m)^hostname\s+(\S+)", r"(?m)^host\s+(\S+)", r"(?m)^set system host-name\s+(\S+)"]
    for pattern in patterns:
        if match := re.search(pattern, config):
            return match.group(1).strip('"')
    return slug(fallback.rsplit(".", 1)[0]) or "unknown-device"


def mask_to_prefix(mask: str) -> int:
    return ipaddress.IPv4Network(f"0.0.0.0/{mask}").prefixlen


def wildcard_to_network(ip: str, wildcard: str) -> str:
    mask = ".".join(str(255 - int(x)) for x in wildcard.split("."))
    return str(ipaddress.IPv4Network(f"{ip}/{mask}", strict=False))


def interface_networks(addresses: list[str]) -> list[str]:
    out: list[str] = []
    for value in addresses:
        try:
            out.append(str(ipaddress.ip_interface(value).network))
        except ValueError:
            pass
    return out


def network_value(address: str, mask: str | None = None) -> str:
    """Normalize an address/mask pair without discarding unknown syntax."""
    try:
        value = f"{address}/{mask_to_prefix(mask)}" if mask else address
        return str(ipaddress.ip_network(value, strict=False))
    except ValueError:
        return address


def key_value_tokens(line: str) -> dict[str, str]:
    """Parse RouterOS-style key=value tokens with quoted values."""
    values: dict[str, str] = {}
    try:
        tokens = shlex.split(line.replace("=\"", '=\"'))
    except ValueError:
        tokens = line.split()
    for token in tokens:
        if "=" in token:
            key, value = token.split("=", 1)
            values[key] = value.strip('"')
    return values
