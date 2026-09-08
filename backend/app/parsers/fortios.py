from __future__ import annotations

import ipaddress
import re
from collections import defaultdict
from dataclasses import dataclass, field

from ..models import (
    AddressObject, CanonicalConfig, Confidence, Device, Interface, NATRule, ParserCapabilities,
    ParserWarning, Policy, Route, Segment, ServiceObject, VLAN, Zone,
)
from .base import BaseConfigParser
from .common import interface_networks, mask_to_prefix, slug
from .registry import ParserRegistry


def _values(raw: str) -> list[str]:
    return re.findall(r'"([^"]+)"|(\S+)', raw) and [a or b for a, b in re.findall(r'"([^"]+)"|(\S+)', raw)]


def _network(ip: str, mask: str) -> str:
    try:
        return str(ipaddress.ip_network(f"{ip}/{mask}", strict=False))
    except ValueError:
        return ip


@dataclass
class Block:
    section: str
    name: str
    line_start: int
    raw_start: str
    line_end: int = 0
    raw_lines: list[str] = field(default_factory=list)
    values: dict[str, list[str]] = field(default_factory=lambda: defaultdict(list))


@ParserRegistry.register
class FortiOSParser(BaseConfigParser):
    parser_id = "fortinet_fortios"
    capabilities = ParserCapabilities(
        parser_id=parser_id, label="Fortinet FortiOS", interfaces=True, vlans=True,
        zones=True, routes=True, acl=True, firewall_policy=True, nat=True,
        address_objects=True, service_objects=True, ipv6=True,
    )

    @classmethod
    def detect(cls, config: str) -> float:
        score = 0.0
        score += 0.28 if re.search(r"(?m)^config system interface\s*$", config) else 0
        score += 0.28 if re.search(r"(?m)^config firewall policy\s*$", config) else 0
        score += 0.18 if re.search(r"(?m)^config firewall address\s*$", config) else 0
        score += 0.16 if re.search(r"(?m)^\s*set (?:srcintf|dstintf|srcaddr|dstaddr) ", config) else 0
        score += 0.10 if re.search(r"(?m)^\s*set hostname ", config) else 0
        return min(score, 1.0)

    def _blocks(self) -> tuple[list[Block], list[ParserWarning]]:
        section = ""
        block: Block | None = None
        blocks: list[Block] = []
        warnings: list[ParserWarning] = []
        for number, raw in enumerate(self.lines, 1):
            line = raw.strip()
            if match := re.match(r"config\s+(.+)", line):
                section = match.group(1)
                continue
            if match := re.match(r"edit\s+(.+)", line):
                name = match.group(1).strip('"')
                block = Block(section=section, name=name, line_start=number, line_end=number,
                              raw_start=raw, raw_lines=[raw])
                blocks.append(block)
                continue
            if line == "next":
                if block:
                    block.raw_lines.append(raw); block.line_end = number
                block = None
                continue
            if line == "end":
                block = None; section = ""
                continue
            if match := re.match(r"set\s+(\S+)\s+(.+)", line):
                if block:
                    block.values[match.group(1)] = _values(match.group(2))
                    block.raw_lines.append(raw); block.line_end = number
                elif section == "system global":
                    blocks.append(Block(section=section, name="global", line_start=number, raw_start=raw,
                                        values=defaultdict(list, {match.group(1): _values(match.group(2))})))
                continue
            if line and not line.startswith(("#", "unset", "config", "end")) and section:
                warnings.append(ParserWarning(device="unknown", line=number, config=line,
                    reason=f"unsupported statement in {section}", parser=self.parser_id))
        return blocks, warnings

    def _block_trace(self, block: Block):
        return self.trace(block.line_start, "\n".join(block.raw_lines) or block.raw_start,
                          block.line_end or block.line_start)

    def parse(self) -> CanonicalConfig:
        blocks, unsupported = self._blocks()
        global_block = next((b for b in blocks if b.section == "system global" and "hostname" in b.values), None)
        hostname = global_block.values["hostname"][0] if global_block else slug(self.source_file.rsplit(".", 1)[0])
        device_id = slug(hostname)
        device = Device(id=device_id, hostname=hostname, vendor="fortinet", network_os="fortios",
                        platform="FortiGate", source_file=self.source_file)
        device.features["dynamic_routing"] = any(block.section in {"router ospf", "router ospf6", "router bgp", "router rip"} for block in blocks)
        for warning in unsupported: warning.device = device_id
        warnings: list[ParserWarning] = []

        interfaces: list[Interface] = []
        vlans: list[VLAN] = []
        iface_by_name: dict[str, Interface] = {}
        for block in [b for b in blocks if b.section == "system interface"]:
            values = block.values
            iface = Interface(device=device_id, name=block.name,
                description=(values.get("description") or values.get("alias") or [None])[0],
                vrf=(values.get("vrf") or [None])[0],
                trace=self._block_trace(block))
            if len(values.get("ip", [])) >= 2:
                iface.addresses.append(f"{values['ip'][0]}/{mask_to_prefix(values['ip'][1])}")
            iface.addresses.extend(values.get("ip6-address", []))
            if values.get("vlanid"):
                iface.vlan_id = int(values["vlanid"][0])
                vlan = VLAN(device=device_id, id=iface.vlan_id, name=block.name,
                    subnets=interface_networks(iface.addresses),
                    gateway=iface.addresses[0].split("/")[0] if iface.addresses else None,
                    trace=self._block_trace(block))
                vlans.append(vlan)
            interfaces.append(iface); iface_by_name[iface.name] = iface

        address_objects: list[AddressObject] = []
        address_values: dict[str, list[str]] = {"all": ["any"], "any": ["any"]}
        for block in [b for b in blocks if b.section in ("firewall address", "firewall address6")]:
            values: list[str] = []
            if len(block.values.get("subnet", [])) >= 2:
                values.append(_network(block.values["subnet"][0], block.values["subnet"][1]))
            values.extend(block.values.get("ip6", []))
            if block.values.get("start-ip") and block.values.get("end-ip"):
                values.append(f"{block.values['start-ip'][0]}-{block.values['end-ip'][0]}")
            if block.values.get("fqdn"): values.extend(block.values["fqdn"])
            address_values[block.name] = values or ["unknown"]
            address_objects.append(AddressObject(device=device_id, name=block.name, values=address_values[block.name]))
        group_members = {b.name: b.values.get("member", []) for b in blocks if b.section in ("firewall addrgrp", "firewall addrgrp6")}

        def resolve_addresses(names: list[str], seen: set[str] | None = None) -> list[str]:
            seen = seen or set(); result: list[str] = []
            for name in names or ["all"]:
                if name in seen: continue
                if name in group_members: result.extend(resolve_addresses(group_members[name], seen | {name}))
                else: result.extend(address_values.get(name, [name]))
            return list(dict.fromkeys(result))

        service_objects: list[ServiceObject] = []
        service_values: dict[str, tuple[str, list[str]]] = {
            "ALL": ("any", ["any"]), "HTTPS": ("tcp", ["443"]), "HTTP": ("tcp", ["80"]),
            "SSH": ("tcp", ["22"]), "DNS": ("udp", ["53"]), "PING": ("icmp", ["any"]),
        }
        for block in [b for b in blocks if b.section == "firewall service custom"]:
            if block.values.get("tcp-portrange"): proto, ports = "tcp", block.values["tcp-portrange"]
            elif block.values.get("udp-portrange"): proto, ports = "udp", block.values["udp-portrange"]
            elif (block.values.get("protocol") or [""])[0].upper() in ("ICMP", "ICMP6"): proto, ports = "icmp", ["any"]
            else: proto, ports = "any", ["any"]
            service_values[block.name] = (proto, ports)
            service_objects.append(ServiceObject(device=device_id, name=block.name, protocol=proto, ports=ports))
        service_groups = {b.name: b.values.get("member", []) for b in blocks if b.section == "firewall service group"}

        def resolve_services(names: list[str], seen: set[str] | None = None) -> tuple[list[str], list[str]]:
            seen = seen or set(); protocols: list[str] = []; ports: list[str] = []
            for name in names or ["ALL"]:
                if name in seen: continue
                if name in service_groups:
                    p, q = resolve_services(service_groups[name], seen | {name}); protocols += p; ports += q
                else:
                    proto, values = service_values.get(name, ("any", ["any"])); protocols.append(proto); ports += values
            return list(dict.fromkeys(protocols)), list(dict.fromkeys(ports))

        zones: list[Zone] = []
        zone_members: dict[str, list[str]] = {}
        for block in [b for b in blocks if b.section == "system zone"]:
            members = block.values.get("interface", []); zone_members[block.name] = members
            zones.append(Zone(device=device_id, name=block.name, interfaces=members,
                segment_id=f"{device_id}-zone-{slug(block.name)}", trace=self._block_trace(block)))
            for member in members:
                if member in iface_by_name: iface_by_name[member].zone = block.name

        segments: list[Segment] = []
        for zone in zones:
            networks = [net for name in zone.interfaces if name in iface_by_name for net in interface_networks(iface_by_name[name].addresses)]
            segments.append(Segment(id=zone.segment_id, name=zone.name.upper(), type="zone", device=device_id, networks=networks,
                vrf=next((iface_by_name[name].vrf for name in zone.interfaces if name in iface_by_name and iface_by_name[name].vrf), None)))
            for name in zone.interfaces:
                if name in iface_by_name: iface_by_name[name].segment_id = zone.segment_id
        for iface in interfaces:
            if not iface.segment_id:
                iface.segment_id = f"{device_id}-if-{slug(iface.name)}"
                segments.append(Segment(id=iface.segment_id, name=iface.name.upper(), type="vlan" if iface.vlan_id else "interface",
                    device=device_id, vlan_id=iface.vlan_id, networks=interface_networks(iface.addresses), vrf=iface.vrf))

        segment_by_name = {s.name.lower(): s.id for s in segments}
        segment_by_name.update({i.name.lower(): i.segment_id for i in interfaces if i.segment_id})
        segment_by_name.update({z.name.lower(): z.segment_id for z in zones})

        policies: list[Policy] = []
        nat_rules: list[NATRule] = []

        def unknown_addresses(names: list[str], seen: set[str] | None = None) -> set[str]:
            seen = seen or set(); result: set[str] = set()
            for name in names:
                if name in seen or name in address_values: continue
                if name in group_members:
                    result.update(unknown_addresses(group_members[name], seen | {name})); continue
                try:
                    ipaddress.ip_network(name, strict=False)
                except ValueError:
                    result.add(name)
            return result

        def unknown_services(names: list[str], seen: set[str] | None = None) -> set[str]:
            seen = seen or set(); result: set[str] = set()
            for name in names:
                if name in seen or name in service_values: continue
                if name in service_groups:
                    result.update(unknown_services(service_groups[name], seen | {name}))
                else:
                    result.add(name)
            return result

        policy_blocks = [b for b in blocks if b.section == "firewall policy"]
        policy_order = [block.name for block in policy_blocks]
        section = ""
        for raw in self.lines:
            line = raw.strip()
            if line == "config firewall policy": section = "firewall policy"; continue
            if line == "end" and section: section = ""; continue
            if section != "firewall policy": continue
            if match := re.match(r"move\s+(\S+)\s+(before|after)\s+(\S+)", line):
                item, where, anchor = match.groups()
                if item in policy_order and anchor in policy_order and item != anchor:
                    policy_order.remove(item); index = policy_order.index(anchor)
                    policy_order.insert(index + (1 if where == "after" else 0), item)
        by_policy_id = {block.name: block for block in policy_blocks}
        ordered_policy_blocks = [by_policy_id[name] for name in policy_order]
        for order, block in enumerate(ordered_policy_blocks, 1):
            if (block.values.get("status") or ["enable"])[0] == "disable":
                continue
            source_names = block.values.get("srcintf", []); destination_names = block.values.get("dstintf", [])
            protocols, ports = resolve_services(block.values.get("service", []))
            action = (block.values.get("action") or ["deny"])[0]
            canonical_action = "permit" if action in ("accept", "allow") else "deny" if action == "deny" else "unknown"
            supported_fields = {"name", "status", "srcintf", "dstintf", "srcaddr", "dstaddr", "service",
                                "action", "nat", "comments", "logtraffic", "schedule", "srcaddr-negate", "dstaddr-negate"}
            partial = bool(set(block.values) - supported_fields)
            if block.values.get("schedule") and block.values["schedule"][0].lower() != "always": partial = True
            policy = Policy(id=f"{device_id}:policy:{block.name}", device=device_id,
                name=(block.values.get("name") or [f"policy-{block.name}"])[0],
                sequence=int(block.name) if block.name.isdigit() else order, order=order,
                src=resolve_addresses(block.values.get("srcaddr", [])), dst=resolve_addresses(block.values.get("dstaddr", [])),
                src_negate=(block.values.get("srcaddr-negate") or ["disable"])[0] == "enable",
                dst_negate=(block.values.get("dstaddr-negate") or ["disable"])[0] == "enable",
                src_segments=[segment_by_name[x.lower()] for x in source_names if x.lower() in segment_by_name],
                dst_segments=[segment_by_name[x.lower()] for x in destination_names if x.lower() in segment_by_name],
                protocol=protocols, dst_ports=ports, action=canonical_action, direction="zone",
                chain_id="fortios:policy",
                confidence=Confidence.PARTIAL if partial else Confidence.EXACT,
                from_zone=", ".join(source_names) or None, to_zone=", ".join(destination_names) or None,
                trace=self._block_trace(block))
            policies.append(policy)
            unresolved = unknown_addresses([*block.values.get("srcaddr", []), *block.values.get("dstaddr", [])])
            unresolved.update(x for x in [*source_names, *destination_names] if x.lower() not in segment_by_name)
            unresolved.update(unknown_services(block.values.get("service", [])))
            for reference in sorted(unresolved):
                warnings.append(ParserWarning(device=device_id, line=block.line_start,
                    config="\n".join(block.raw_lines), reason=f"unresolved policy reference: {reference}", parser=self.parser_id))
            if (block.values.get("nat") or ["disable"])[0] == "enable":
                nat_rules.append(NATRule(device=device_id, name=f"policy-{block.name}-snat", type="source",
                    original_src=policy.src[0], original_dst=policy.dst[0], translated_src="interface-address",
                    protocol=protocols[0], sequence=order,
                    destination_ports=ports if ports != ["any"] else [],
                    in_interfaces=source_names, out_interfaces=destination_names,
                    trace=self._block_trace(block)))

        routes: list[Route] = []
        for block in [b for b in blocks if b.section in ("router static", "router static6")]:
            destination = (block.values.get("dst") or block.values.get("dst6") or ["0.0.0.0", "0.0.0.0"])
            dest = _network(destination[0], destination[1]) if len(destination) >= 2 else destination[0]
            routes.append(Route(device=device_id, destination=dest,
                next_hop=(block.values.get("gateway") or block.values.get("gateway6") or [None])[0],
                interface=(block.values.get("device") or [None])[0],
                vrf=(block.values.get("vrf") or [None])[0],
                metric=int(block.values["distance"][0]) if block.values.get("distance") and block.values["distance"][0].isdigit() else None,
                trace=self._block_trace(block)))
        return CanonicalConfig(device=device, interfaces=interfaces, vlans=vlans, segments=segments, zones=zones,
            routes=routes, policies=policies, nat=nat_rules, address_objects=address_objects,
            service_objects=service_objects, warnings=warnings, unsupported=unsupported)
