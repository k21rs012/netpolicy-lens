"""AlliedWare Plus VLAN hardware filter bindings.

Reference: x540L 5.5.5, overview-30 (hardware packet filters).
Hardware ACLs are ordered and default to forwarding, not implicit deny.
"""
from __future__ import annotations

import re
from collections import defaultdict

from ..models import CanonicalConfig, Confidence, ParserWarning, Policy
from .base import BaseConfigParser


def vlan_numbers(value: str) -> list[int]:
    values: list[int] = []
    for part in value.split(","):
        match = re.fullmatch(r"(\d+)(?:-(\d+))?", part)
        if not match:
            raise ValueError("unsupported VLAN list")
        first, last = int(match[1]), int(match[2] or match[1])
        if not 1 <= first <= last <= 4094:
            raise ValueError("invalid VLAN range")
        values.extend(range(first, last + 1))
    return list(dict.fromkeys(values))


def expanded_interface_lines(lines: list[str]) -> list[tuple[int, str]]:
    """Expand same-stack port ranges while preserving original source lines."""
    expanded: list[tuple[int, str]] = []
    index = 0
    while index < len(lines):
        match = re.fullmatch(r"interface port(\d+\.\d+)\.(\d+)-(?:port)?(\d+\.\d+)\.(\d+)", lines[index].strip())
        if match and match[1] == match[3] and 1 <= int(match[2]) <= int(match[4]) <= 128:
            end = index + 1
            while end < len(lines) and lines[end].startswith((" ", "\t")):
                end += 1
            for port in range(int(match[2]), int(match[4]) + 1):
                expanded.append((index + 1, f"interface port{match[1]}.{port}"))
                expanded.extend((line + 1, lines[line]) for line in range(index + 1, end))
            index = end
        else:
            expanded.append((index + 1, lines[index]))
            index += 1
    return expanded


def apply_vlan_filters(parser: BaseConfigParser, config: CanonicalConfig) -> None:
    maps: dict[str, list[str]] = {}
    map_unknown: dict[str, list[str]] = defaultdict(list)
    bindings: list[tuple[str, list[int], int, str, list[str]]] = []
    current_map: str | None = None
    current_acl: str | None = None
    hardware_acls: set[str] = set()
    acl_unknown: dict[str, list[str]] = defaultdict(list)
    active_interface: str | None = None
    other_filters = False
    for number, raw in enumerate(parser.lines, 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if not raw.startswith((" ", "\t")):
            current_map = None
            current_acl = None
            active_interface = None
        if match := re.fullmatch(r"access-list hardware (\S+)", line):
            current_acl = match[1]
            hardware_acls.add(current_acl)
            continue
        if match := re.match(r"access-list (\S+) (?:permit|deny) ", line):
            if not match[1].isdigit() or 3000 <= int(match[1]) <= 3699:
                hardware_acls.add(match[1])
        if current_acl:
            if not re.match(r"(?:\d+ )?(?:permit|deny|remark|description)\b", line):
                acl_unknown[current_acl].append(line)
            continue
        if match := re.fullmatch(r"interface (.+)", line):
            active_interface = match[1]
        if match := re.fullmatch(r"vlan access-map (\S+)", line):
            current_map = match[1]
            maps.setdefault(current_map, [])
            continue
        if current_map:
            if match := re.fullmatch(r"match access-group (\S+)", line):
                maps[current_map].append(match[1])
            elif line not in {"!", "exit"}:
                map_unknown[current_map].append(line)
            continue
        if line.startswith("vlan filter "):
            match = re.fullmatch(r"vlan filter (\S+) vlan-list (\S+) input", line)
            unknown: list[str] = []
            try:
                if match is None:
                    raise ValueError("unsupported VLAN filter binding")
                vlans = vlan_numbers(match[2])
                name = match[1]
            except ValueError:
                name = line.split()[2]
                vlans = [segment.vlan_id for segment in config.segments if segment.vlan_id]
                unknown = [line]
            bindings.append((name, vlans, number, raw, unknown))
        if re.match(r"(?:ip |ipv6 )?(?:access-group|traffic-filter|service-policy)\b", line):
            other_filters = True
        if active_interface and (match := re.fullmatch(r"switchport trunk allowed vlan(?: add)? (\S+)", line)):
            interface = next((i for i in config.interfaces if i.name == active_interface), None)
            if interface:
                try:
                    interface.trunk_vlans = vlan_numbers(match[1])
                except ValueError:
                    pass

    templates: dict[str, list[Policy]] = defaultdict(list)
    for policy in config.policies:
        templates[policy.name].append(policy)
    bound_names: set[str] = set()
    generated: list[Policy] = []
    # One chain per receiving VLAN, including multiple maps in binding order.
    chains: dict[int, list[Policy]] = defaultdict(list)
    binding_traces = {}
    for name, vlans, number, raw, unknown in bindings:
        references = maps.get(name, [])
        for vlan in vlans:
            segment = next((s for s in config.segments if s.vlan_id == vlan), None)
            if segment is None:
                config.warnings.append(ParserWarning(device=config.device.id, line=number,
                    config=raw, reason=f"VLAN filter {name}: VLAN {vlan} has no segment", parser=parser.parser_id))
                continue
            iface = next((i for i in config.interfaces if i.segment_id == segment.id
                          and re.fullmatch(r"vlan\s*\d+", i.name, re.I)), None)
            chain = chains[vlan]
            binding_traces[vlan] = parser.trace(number, raw)
            problems = [*unknown, *map_unknown[name]]
            if not references:
                problems.append(f"unresolved or empty VLAN access-map {name}")
            if other_filters:
                problems.append("combined port/global/QoS filtering order is not evaluated")

            def append(rule: Policy) -> None:
                item = rule.model_copy(deep=True)
                item.id = f"{rule.id}:vlan:{vlan}:{len(chain)}"
                item.interface = iface.name if iface else f"vlan{vlan}"
                item.direction = "in"
                item.src_segments, item.dst_segments = [segment.id], []
                item.chain_id = f"allied-vlan:{vlan}"
                item.order = len(chain)
                item.default_action = "permit"
                chain.append(item)

            def uncertain(reason: str) -> None:
                config.warnings.append(ParserWarning(device=config.device.id, line=number,
                    config=raw, reason=reason, parser=parser.parser_id))
                append(Policy(id=f"{config.device.id}:{name}:unresolved", device=config.device.id,
                    name=name, sequence=0, action="unknown", confidence=Confidence.PARTIAL,
                    unsupported_matches=[reason], trace=parser.trace(number, raw)))

            if problems:
                uncertain("; ".join(problems))
            for acl in references:
                rules = templates.get(acl, []) if acl in hardware_acls else []
                if acl_unknown[acl]:
                    uncertain(f"unsupported hardware ACL {acl}: {'; '.join(acl_unknown[acl])}")
                if not rules:
                    uncertain(f"unresolved or empty hardware ACL {acl} in VLAN access-map {name}")
                    continue
                bound_names.add(acl)
                if iface and acl not in iface.acl_in:
                    iface.acl_in.append(acl)
                for rule in sorted(rules, key=lambda p: p.sequence):
                    append(rule)
            # Chain defaults are evaluated by Path trace. A terminal fallback
            # also makes the default visible in Policy/Matrix with binding trace.
    for vlan, chain in chains.items():
        last = chain[-1]
        fallback = last.model_copy(deep=True, update={
            "id": f"{config.device.id}:vlan:{vlan}:default", "name": "hardware default permit",
            "sequence": 2147483647, "order": len(chain), "src": ["any"], "dst": ["any"],
            "src_ports": ["any"], "dst_ports": ["any"], "protocol": ["ip"],
            "action": "permit", "confidence": Confidence.EXACT, "unsupported_matches": [],
            "icmp_type": None, "states": [], "src_negate": False, "dst_negate": False,
            "terminal": True, "jump_target": None, "trace": binding_traces[vlan],
        })
        generated.extend([*chain, fallback])
    config.policies = [p for p in config.policies if p.name not in bound_names or p.direction != "unknown"] + generated
