from __future__ import annotations

from .models import Policy


SERVICE_PORTS = {
    "http": 80,
    "https": 443,
    "ssh": 22,
    "domain": 53,
    "dns": 53,
}


def policy_chain_key(policy: Policy) -> tuple[str, ...]:
    """Return the stable chain identity shared by Matrix and Path Trace."""
    if policy.chain_id:
        return policy.device, policy.chain_id
    if policy.direction == "zone":
        return policy.device, "zone", policy.from_zone or "", policy.to_zone or ""
    if policy.direction in {"forward", "global"}:
        return policy.device, policy.direction
    return policy.device, policy.direction, policy.interface or "", policy.name


def policy_order(policy: Policy) -> int:
    return policy.order if policy.order is not None else policy.sequence


def service_labels(policy: Policy) -> list[str]:
    labels: list[str] = []
    for protocol in policy.protocol:
        for port in policy.dst_ports:
            if protocol in ("ip", "any", "*") and port in ("any", "*"):
                labels.append("ANY")
            elif port in ("any", "*"):
                labels.append(protocol.upper())
            else:
                labels.append(f"{protocol.upper()}/{port}")
    return list(dict.fromkeys(labels))


def port_matches(values: list[str], port: int | None) -> bool:
    if port is None or any(value.lower() in ("any", "*") for value in values):
        return True
    for raw in values:
        value = raw.lower().replace("eq ", "").strip()
        if value in SERVICE_PORTS and SERVICE_PORTS[value] == port:
            return True
        if value.isdigit() and int(value) == port:
            return True
        if value.startswith("lt ") and value[3:].isdigit() and port < int(value[3:]):
            return True
        if value.startswith("gt ") and value[3:].isdigit() and port > int(value[3:]):
            return True
        if value.startswith("neq ") and value[4:].strip().isdigit() and port != int(value[4:].strip()):
            return True
        if value.startswith("range "):
            value = value.removeprefix("range ")
        if "-" in value:
            bounds = value.split("-")
            if len(bounds) == 2 and all(bound.isdigit() for bound in bounds):
                if int(bounds[0]) <= port <= int(bounds[1]):
                    return True
    return False


def packet_matches(policy: Policy, protocol: str, port: int | None) -> bool:
    protocols = {value.lower() for value in policy.protocol}
    protocol_ok = protocol.lower() in protocols or bool(protocols & {"ip", "any", "*"})
    return protocol_ok and port_matches(policy.dst_ports, port)
