from __future__ import annotations

import re
from collections import defaultdict

from ..models import CanonicalConfig, Device, Interface, ParserCapabilities, Policy, Route, Segment, VLAN
from .base import BaseConfigParser
from .common import hostname_from, interface_networks, mask_to_prefix, network_value, slug
from .registry import ParserRegistry


class ExtremeBaseParser(BaseConfigParser):
    network_os = "exos"
    capabilities = ParserCapabilities(parser_id="extreme_exos", label="ExtremeXOS",
        interfaces=True, vlans=True, routes=True, acl=True, ipv6=True)

    def parse(self) -> CanonicalConfig:
        match = re.search(r'(?m)^configure snmp sysName\s+"?([^"\s]+)', self.config)
        match = match or re.search(r"(?m)^snmp-server name\s+(.+)", self.config)
        hostname = match.group(1).strip('"') if match else hostname_from(self.config, self.source_file)
        device = Device(id=slug(hostname), hostname=hostname, vendor="extreme",
            network_os=self.network_os, source_file=self.source_file)
        device.features["dynamic_routing"] = bool(re.search(r"(?m)^(?:enable|configure) (?:ospf|bgp|isis|rip)\b|^router (?:ospf|bgp|isis|rip)\b", self.config))
        vlans: dict[int, VLAN] = {}
        vlan_names: dict[str, int] = {}
        interfaces: list[Interface] = []
        routes: list[Route] = []
        policies: list[Policy] = []
        exos_bindings: list[tuple[str, str, str]] = []
        voss_bindings: list[tuple[int, int, str]] = []
        voss_aces: dict[tuple[int, int], dict[str, str | int]] = defaultdict(dict)
        voss_acl_direction: dict[int, str] = {}
        current_if: Interface | None = None
        for number, raw in enumerate(self.lines, 1):
            line = raw.strip()
            if match := re.match(r"create vlan\s+\"?([^\"\s]+)\"?\s+tag\s+(\d+)", line):
                vid = int(match.group(2)); vlan_names[match.group(1)] = vid
                vlans[vid] = VLAN(device=device.id, id=vid, name=match.group(1), trace=self.trace(number, raw)); continue
            if match := re.match(r"vlan create\s+(\d+)(?:\s+name\s+\"?([^\"\s]+))?", line):
                vid = int(match.group(1)); name = match.group(2) or f"VLAN{vid}"
                vlan_names[name] = vid; vlans[vid] = VLAN(device=device.id, id=vid, name=name, trace=self.trace(number, raw)); continue
            if match := re.match(r"configure vlan\s+\"?([^\"\s]+)\"?\s+ipaddress\s+(\S+)\s+(\S+)", line):
                vid = vlan_names.get(match.group(1))
                if vid is not None:
                    vlans[vid].gateway = match.group(2); vlans[vid].subnets = [network_value(match.group(2), match.group(3))]
                continue
            if match := re.match(r"interface Vlan\s*(\d+)", line, re.I):
                vid = int(match.group(1)); current_if = Interface(device=device.id, name=f"Vlan{vid}", vlan_id=vid, trace=self.trace(number, raw))
                interfaces.append(current_if); continue
            if current_if and raw.startswith((" ", "\t")) and (match := re.match(r"ip address\s+(\S+)(?:\s+(\S+))?", line)):
                address = match.group(1) if "/" in match.group(1) else f"{match.group(1)}/{mask_to_prefix(match.group(2) or '255.255.255.255')}"
                current_if.addresses.append(address); continue
            if not raw.startswith((" ", "\t")): current_if = None
            if match := re.match(r"(?:configure iproute add|ip route)\s+(\S+)\s+(\S+)", line):
                routes.append(Route(device=device.id, destination=match.group(1), next_hop=match.group(2), trace=self.trace(number, raw))); continue
            if match := re.match(r"create access-list\s+(\S+)\s+\"?(permit|deny)\s+(\S+)(.*)", line):
                name, action, protocol, tail = match.groups()
                src = re.search(r"source-address\s+(\S+)", tail); dst = re.search(r"destination-address\s+(\S+)", tail)
                port_match = re.search(r"destination-port\s+(?:eq\s+)?(\S+)", tail)
                policies.append(Policy(id=f"{device.id}:{name}:{number}", device=device.id,
                    name=name, sequence=number, src=[src.group(1).strip('"') if src else "any"],
                    dst=[dst.group(1).strip('"') if dst else "any"], protocol=[protocol.strip('"')],
                    dst_ports=[port_match.group(1).strip('"') if port_match else "any"], action=action,
                    default_action="permit", trace=self.trace(number, raw)))
                continue
            if match := re.match(r"configure access-list\s+(\S+)\s+(?:vlan\s+|ports\s+)(\S+).*\s+(ingress|egress)$", line):
                exos_bindings.append((match.group(1), match.group(2), "in" if match.group(3) == "ingress" else "out")); continue
            if match := re.match(r"filter acl\s+(\d+)\s+type\s+(\S+)", line):
                voss_acl_direction[int(match.group(1))] = "out" if "out" in match.group(2).lower() else "in"; continue
            if match := re.match(r"filter acl vlan\s+(\d+)\s+(\d+)(?:\s+(in|out))?", line):
                voss_bindings.append((int(match.group(2)), int(match.group(1)), match.group(3) or voss_acl_direction.get(int(match.group(2)), "in"))); continue
            if match := re.match(r"filter acl ace\s+(\d+)\s+(\d+)$", line):
                voss_aces[(int(match.group(1)), int(match.group(2)))]["line"] = number; continue
            if match := re.match(r"filter acl ace action\s+(\d+)\s+(\d+)\s+(permit|deny|drop)", line):
                data = voss_aces[(int(match.group(1)), int(match.group(2)))]; data["action"] = "permit" if match.group(3) == "permit" else "deny"; data["line"] = number; continue
            if match := re.match(r"filter acl ace (?:ip|ipv6)\s+(\d+)\s+(\d+)\s+(.+)", line):
                data = voss_aces[(int(match.group(1)), int(match.group(2)))]; tail = match.group(3); data["line"] = number
                for key, pattern in (("src", r"(?:src-ip|src)\s+(\S+)"), ("dst", r"(?:dst-ip|dst)\s+(\S+)"),
                                     ("protocol", r"protocol\s+(\S+)"), ("port", r"(?:dst-port|destination-port)\s+(\S+)")):
                    if found := re.search(pattern, tail): data[key] = found.group(1)
                continue
        segments: list[Segment] = []
        for vlan in vlans.values():
            svi = next((item for item in interfaces if item.vlan_id == vlan.id), None)
            if svi and svi.addresses: vlan.subnets = interface_networks(svi.addresses); vlan.gateway = svi.addresses[0].split("/")[0]
            seg_id = f"{device.id}-vlan-{vlan.id}"
            segments.append(Segment(id=seg_id, name=vlan.name, type="vlan", device=device.id,
                vlan_id=vlan.id, networks=vlan.subnets))
            if svi: svi.segment_id = seg_id
        segment_by_vlan = {segment.vlan_id: segment.id for segment in segments if segment.vlan_id is not None}
        interface_by_name = {interface.name: interface for interface in interfaces}
        for acl, target, direction in exos_bindings:
            segment_id = next((segment.id for segment in segments
                               if segment.name.lower() == target.strip('"').lower()), None)
            iface = interface_by_name.get(target)
            if iface: segment_id = iface.segment_id
            for policy in policies:
                if policy.name != acl: continue
                policy.direction = direction; policy.interface = target
                policy.chain_id = f"{direction}:{target}:{acl}"
                if segment_id and direction == "in": policy.src_segments = [segment_id]
                if segment_id and direction == "out": policy.dst_segments = [segment_id]
        for (acl, ace), data in voss_aces.items():
            binding = next((item for item in voss_bindings if item[0] == acl), None)
            direction = binding[2] if binding else "unknown"; vlan_id = binding[1] if binding else None
            segment_id = segment_by_vlan.get(vlan_id) if vlan_id is not None else None
            policies.append(Policy(id=f"{device.id}:acl-{acl}:{ace}", device=device.id,
                name=f"acl-{acl}", sequence=ace, src=[str(data.get("src", "any"))],
                dst=[str(data.get("dst", "any"))], protocol=[str(data.get("protocol", "ip"))],
                dst_ports=[str(data.get("port", "any"))], action=str(data.get("action", "unknown")),
                direction=direction, interface=f"Vlan{vlan_id}" if vlan_id is not None else None,
                src_segments=[segment_id] if segment_id and direction == "in" else [],
                chain_id=f"{direction}:vlan-{vlan_id}:acl-{acl}" if binding else None,
                trace=self.trace(int(data.get("line", 0)), self.lines[int(data.get("line", 1)) - 1]) if data.get("line") else None))
        return CanonicalConfig(device=device, interfaces=interfaces, vlans=list(vlans.values()),
            segments=segments, routes=routes, policies=policies)
@ParserRegistry.register
class ExtremeEXOSParser(ExtremeBaseParser):
    parser_id = "extreme_exos"

    @classmethod
    def detect(cls, config: str) -> float:
        score = 0.55 if re.search(r"(?m)^create vlan .+ tag \d+", config) else 0
        score += 0.25 if re.search(r"(?m)^configure (?:snmp sysName|vlan|ports)", config) else 0
        score += 0.15 if re.search(r"(?m)^configure iproute add", config) else 0
        return min(score, 1.0)


@ParserRegistry.register
class ExtremeVOSSParser(ExtremeBaseParser):
    parser_id = "extreme_voss"
    network_os = "voss"
    capabilities = ExtremeBaseParser.capabilities.model_copy(
        update={"parser_id": "extreme_voss", "label": "Extreme VOSS"}
    )

    @classmethod
    def detect(cls, config: str) -> float:
        score = 0.55 if re.search(r"(?m)^vlan create \d+", config) else 0
        score += 0.25 if re.search(r"(?m)^snmp-server name ", config) else 0
        score += 0.15 if re.search(r"(?m)^interface Vlan \d+", config) else 0
        return min(score, 1.0)
