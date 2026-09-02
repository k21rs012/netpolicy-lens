from __future__ import annotations

import ipaddress
import re
import shlex
from collections import defaultdict

from ..models import (
    AddressObject, CanonicalConfig, Confidence, Device, Interface, NATRule, ParserCapabilities,
    ParserWarning, Policy, Route, Segment, ServiceObject, VLAN, Zone,
)
from .base import BaseConfigParser
from .common import hostname_from, interface_networks, mask_to_prefix, slug
from .registry import ParserRegistry


def _network(address: str, mask: str | None = None) -> str:
    try:
        value = f"{address}/{mask_to_prefix(mask)}" if mask else address
        return str(ipaddress.ip_network(value, strict=False))
    except ValueError:
        return address


def _kv(line: str) -> dict[str, str]:
    values: dict[str, str] = {}
    try:
        tokens = shlex.split(line.replace("=\"", '="'))
    except ValueError:
        tokens = line.split()
    for token in tokens:
        if "=" in token:
            key, value = token.split("=", 1)
            values[key] = value.strip('"')
    return values


class CiscoASABaseParser(BaseConfigParser):
    network_os = "asa"
    capabilities = ParserCapabilities(
        parser_id="cisco_asa", label="Cisco ASA", interfaces=True, zones=True,
        routes=True, acl=True, firewall_policy=True, nat=True,
        address_objects=True, service_objects=True, ipv6=True,
    )

    @classmethod
    def detect(cls, config: str) -> float:
        score = 0.0
        score += 0.5 if re.search(r"(?mi)^(?:ASA Version|: Written by enable_15|Cryptochecksum:)", config) else 0
        score += 0.2 if re.search(r"(?m)^nameif \S+", config) else 0
        score += 0.15 if re.search(r"(?m)^access-group \S+ (?:in|out) interface \S+", config) else 0
        score += 0.15 if re.search(r"(?m)^object network \S+", config) else 0
        return min(score, 1.0)

    def _acl_address(self, tokens: list[str], pos: int) -> tuple[str, int]:
        if pos >= len(tokens) or tokens[pos] in {"any", "any4", "any6"}:
            return "any", pos + 1
        if tokens[pos] == "host" and pos + 1 < len(tokens):
            value = tokens[pos + 1]
            return f"{value}/128" if ":" in value else f"{value}/32", pos + 2
        if tokens[pos] in {"object", "object-group"} and pos + 1 < len(tokens):
            return tokens[pos + 1], pos + 2
        if pos + 1 < len(tokens) and re.fullmatch(r"\d+(?:\.\d+){3}", tokens[pos + 1]):
            return _network(tokens[pos], tokens[pos + 1]), pos + 2
        return tokens[pos], pos + 1

    def _acl(self, device: str, name: str, body: str, number: int, sequence: int,
             services: list[ServiceObject] | None = None) -> Policy | None:
        tokens = body.split()
        if tokens and tokens[0] == "line" and len(tokens) > 2 and tokens[1].isdigit():
            sequence, tokens = int(tokens[1]), tokens[2:]
        standard = bool(tokens and tokens[0] == "standard")
        if tokens and tokens[0] in {"extended", "standard"}:
            tokens = tokens[1:]
        if len(tokens) < 2 or tokens[0] not in {"permit", "deny"}:
            return None
        if standard:
            action = tokens[0]; src, _ = self._acl_address(tokens, 1)
            return Policy(id=f"{device}:{name}:{sequence}", device=device, name=name,
                sequence=sequence, src=[src], dst=["any"], protocol=["ip"], action=action,
                trace=self.trace(number, body))
        action, protocol = tokens[0], tokens[1]
        ports = ["any"]
        if protocol in {"object", "object-group"} and len(tokens) > 2:
            service = next((item for item in services or [] if item.name == tokens[2]), None)
            if service:
                protocol = service.protocol; ports = service.ports or ["any"]; pos = 3
            else:
                protocol = "any"; pos = 3
        else:
            pos = 2
        src, pos = self._acl_address(tokens, pos)
        dst, pos = self._acl_address(tokens, pos)
        if pos < len(tokens) and tokens[pos] in {"eq", "range", "lt", "gt", "neq"}:
            operator = tokens[pos]
            count = 2 if operator == "range" else 1
            values = tokens[pos + 1:pos + 1 + count]
            ports = [values[0] if operator == "eq" and values else f"{operator} {'-'.join(values)}"]
            pos += 1 + len(values)
        remaining = [token for token in tokens[pos:] if token not in {"log", "inactive"}]
        states = ["established"] if "established" in remaining else []
        remaining = [token for token in remaining if token != "established"]
        return Policy(id=f"{device}:{name}:{sequence}", device=device, name=name,
            sequence=sequence, src=[src], dst=[dst], protocol=[protocol],
            dst_ports=ports, action=action, states=states,
            confidence=Confidence.PARTIAL if remaining else Confidence.EXACT,
            trace=self.trace(number, body))

    def parse(self) -> CanonicalConfig:
        hostname = hostname_from(self.config, self.source_file)
        device = Device(id=slug(hostname), hostname=hostname, vendor="cisco",
            network_os=self.network_os, source_file=self.source_file)
        device.features["dynamic_routing"] = bool(re.search(r"(?m)^router (?:ospf|bgp|eigrp|rip)\b", self.config))
        interfaces: list[Interface] = []
        routes: list[Route] = []
        policies: list[Policy] = []
        nat: list[NATRule] = []
        objects: list[AddressObject] = []
        services: list[ServiceObject] = []
        unsupported: list[ParserWarning] = []
        current_if: Interface | None = None
        current_object: AddressObject | None = None
        current_service: ServiceObject | None = None
        acl_bindings: list[tuple[str, str, str]] = []
        for number, raw in enumerate(self.lines, 1):
            line = raw.strip()
            if not line or line.startswith("!"):
                continue
            if match := re.match(r"interface\s+(.+)", line):
                current_if = Interface(device=device.id, name=match.group(1), trace=self.trace(number, raw))
                interfaces.append(current_if); current_object = None; current_service = None; continue
            if match := re.match(r"object(?:-group)? network\s+(\S+)", line):
                current_object = AddressObject(device=device.id, name=match.group(1), values=[])
                objects.append(current_object); current_if = None; current_service = None; continue
            if match := re.match(r"object(?:-group)? service\s+(\S+)(?:\s+(tcp|udp|tcp-udp))?", line):
                current_service = ServiceObject(device=device.id, name=match.group(1),
                    protocol=match.group(2) or "ip", ports=[])
                services.append(current_service); current_if = None; current_object = None; continue
            if not raw.startswith((" ", "\t")):
                current_if = None; current_object = None; current_service = None
            if current_if:
                if match := re.match(r"description\s+(.+)", line): current_if.description = match.group(1)
                elif match := re.match(r"nameif\s+(\S+)", line): current_if.zone = match.group(1)
                elif match := re.match(r"security-level\s+(\d+)", line): current_if.security_level = int(match.group(1))
                elif match := re.match(r"ip address\s+(\S+)\s+(\S+)", line):
                    current_if.addresses.append(f"{match.group(1)}/{mask_to_prefix(match.group(2))}")
                elif match := re.match(r"ipv6 address\s+(\S+)", line): current_if.addresses.append(match.group(1))
                continue
            if current_object:
                if match := re.match(r"host\s+(\S+)", line): current_object.values.append(_network(match.group(1) + "/32"))
                elif match := re.match(r"subnet\s+(\S+)\s+(\S+)", line): current_object.values.append(_network(match.group(1), match.group(2)))
                elif match := re.match(r"range\s+(\S+)\s+(\S+)", line): current_object.values.append(f"{match.group(1)}-{match.group(2)}")
                elif match := re.match(r"network-object host\s+(\S+)", line): current_object.values.append(_network(match.group(1) + "/32"))
                elif match := re.match(r"network-object object\s+(\S+)", line): current_object.values.append(match.group(1))
                elif match := re.match(r"network-object\s+(\S+)\s+(\S+)", line): current_object.values.append(_network(match.group(1), match.group(2)))
                elif match := re.match(r"nat\s+\(([^,]+),([^\)]+)\)\s+(?:source\s+)?static\s+(\S+)", line):
                    nat.append(NATRule(device=device.id, name=f"{current_object.name}-{number}", type="static",
                        original_src=current_object.name, translated_src=match.group(3), trace=self.trace(number, raw)))
                continue
            if current_service:
                if match := re.match(r"service\s+(tcp|udp)(?:\s+source\s+\S+\s+\S+)?(?:\s+destination\s+(eq|range)\s+(.+))?", line):
                    current_service.protocol = match.group(1)
                    if match.group(3): current_service.ports.append(match.group(3).replace(" ", "-"))
                elif match := re.match(r"service-object\s+(tcp|udp)(?:\s+destination\s+(eq|range)\s+(.+))?", line):
                    current_service.protocol = match.group(1)
                    if match.group(3): current_service.ports.append(match.group(3).replace(" ", "-"))
                elif match := re.match(r"service-object object\s+(\S+)", line): current_service.ports.append(match.group(1))
                continue
            if match := re.match(r"access-list\s+(\S+)\s+(.+)", line):
                parsed = self._acl(device.id, match.group(1), match.group(2), number, len(policies) + 10, services)
                if parsed: policies.append(parsed)
                else: unsupported.append(ParserWarning(device=device.id, line=number, config=line,
                    reason="unsupported ASA ACL statement", parser=self.parser_id))
                continue
            if match := re.match(r"access-group\s+(\S+)\s+(in|out)\s+interface\s+(\S+)", line):
                acl_bindings.append((match.group(1), match.group(3), match.group(2))); continue
            if match := re.match(r"access-group\s+(\S+)\s+global", line):
                acl_bindings.append((match.group(1), "global", "global")); continue
            if line == "same-security-traffic permit inter-interface":
                device.features["same_security_inter_interface"] = True; continue
            if match := re.match(r"route\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)", line):
                routes.append(Route(device=device.id, destination=_network(match.group(2), match.group(3)),
                    next_hop=match.group(4), interface=match.group(1), trace=self.trace(number, raw))); continue
            if match := re.match(r"nat\s+\(([^,]+),([^\)]+)\)\s+(?:source\s+dynamic\s+)?(\S+)\s+(\S+)", line):
                nat.append(NATRule(device=device.id, name=f"nat-{number}", type="source",
                    original_src=match.group(3), translated_src=match.group(4), trace=self.trace(number, raw)))

        segments: list[Segment] = []
        zones: list[Zone] = []
        for interface in interfaces:
            if interface.zone:
                interface.segment_id = f"{device.id}-zone-{slug(interface.zone)}"
                segments.append(Segment(id=interface.segment_id, name=interface.zone, type="zone",
                    device=device.id, networks=interface_networks(interface.addresses)))
                zones.append(Zone(device=device.id, name=interface.zone,
                    interfaces=[interface.name], segment_id=interface.segment_id, trace=interface.trace))
        bound_policies: list[Policy] = []
        for policy in policies:
            matches = [binding for binding in acl_bindings if binding[0] == policy.name]
            if not matches: bound_policies.append(policy); continue
            for _, interface_name, direction in matches:
                item = policy.model_copy(deep=True); item.interface, item.direction = interface_name, direction
                item.chain_id = f"{direction}:{interface_name}:{item.name}"
                if len(matches) > 1: item.id = f"{policy.id}:{direction}:{interface_name}"
                interface = next((value for value in interfaces if value.zone == interface_name), None)
                if interface and interface.segment_id and direction == "in": item.src_segments = [interface.segment_id]
                if interface and interface.segment_id and direction == "out": item.dst_segments = [interface.segment_id]
                bound_policies.append(item)
        policies = bound_policies
        object_values = {item.name: item.values for item in objects}
        for policy in policies:
            policy.src = [value for name in policy.src for value in object_values.get(name, [name])]
            policy.dst = [value for name in policy.dst for value in object_values.get(name, [name])]
        return CanonicalConfig(device=device, interfaces=interfaces, segments=segments, zones=zones,
            routes=routes, policies=policies, nat=nat, address_objects=objects,
            service_objects=services, unsupported=unsupported)


@ParserRegistry.register
class CiscoASAParser(CiscoASABaseParser):
    parser_id = "cisco_asa"


@ParserRegistry.register
class CiscoFTDParser(CiscoASABaseParser):
    parser_id = "cisco_ftd"
    network_os = "ftd"
    capabilities = CiscoASABaseParser.capabilities.model_copy(
        update={"parser_id": "cisco_ftd", "label": "Cisco FTD"}
    )

    @classmethod
    def detect(cls, config: str) -> float:
        base = super().detect(config)
        ftd = 0.65 if re.search(r"(?mi)^(?:FTD Version|Firepower Threat Defense|: Device Manager Version)", config) else 0
        return min(max(base - 0.1, ftd) + (0.2 if "access-control-policy" in config else 0), 1.0)


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
                    vlans[vid].gateway = match.group(2); vlans[vid].subnets = [_network(match.group(2), match.group(3))]
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


@ParserRegistry.register
class MikroTikRouterOSParser(BaseConfigParser):
    parser_id = "mikrotik_routeros"
    capabilities = ParserCapabilities(parser_id=parser_id, label="MikroTik RouterOS",
        interfaces=True, vlans=True, routes=True, acl=True, firewall_policy=True,
        nat=True, address_objects=True, ipv6=True)

    @classmethod
    def detect(cls, config: str) -> float:
        score = 0.45 if re.search(r"(?m)^# (?:RouterOS|software id =)", config) else 0
        score += 0.25 if re.search(r"(?m)^/ip firewall (?:filter|nat)", config) else 0
        score += 0.2 if re.search(r"(?m)^/interface (?:vlan|bridge)", config) else 0
        score += 0.1 if re.search(r"(?m)^/system identity", config) else 0
        return min(score, 1.0)

    def parse(self) -> CanonicalConfig:
        identity = re.search(r"(?m)^/system identity(?:\s*\n)?set .*?name=\"?([^\s\"]+)", self.config)
        hostname = identity.group(1) if identity else hostname_from(self.config, self.source_file)
        device = Device(id=slug(hostname), hostname=hostname, vendor="mikrotik",
            network_os="routeros", source_file=self.source_file)
        device.features["dynamic_routing"] = bool(re.search(r"(?m)^/routing (?:bgp|ospf|rip)\b", self.config))
        interfaces: dict[str, Interface] = {}
        vlans: dict[int, VLAN] = {}
        routes: list[Route] = []
        policies: list[Policy] = []
        nat: list[NATRule] = []
        address_values: dict[str, list[str]] = {}
        interface_lists: dict[str, list[str]] = defaultdict(list)
        interface_vrfs: dict[str, str] = {}
        section = ""
        logical_lines: list[tuple[int, int, str]] = []
        pending = ""; start = 0
        for number, raw in enumerate(self.lines, 1):
            stripped = raw.rstrip()
            if pending:
                pending += " " + stripped.lstrip()
            else:
                pending = stripped; start = number
            if pending.endswith("\\"):
                pending = pending[:-1].rstrip(); continue
            logical_lines.append((start, number, pending)); pending = ""
        if pending: logical_lines.append((start, len(self.lines), pending))
        pending_policies: list[tuple[int, int, str, dict[str, str]]] = []
        for number, line_end, raw in logical_lines:
            line = raw.strip()
            if not line or line.startswith("#"): continue
            if line.startswith("/"): section = line; continue
            if not line.startswith(("add ", "set ")): continue
            values = _kv(line)
            if section == "/interface vlan" and line.startswith("add "):
                name = values.get("name", f"vlan{values.get('vlan-id', number)}")
                vid = int(values.get("vlan-id", "0")); vlans[vid] = VLAN(device=device.id, id=vid, name=name, trace=self.trace(number, raw))
                interfaces[name] = Interface(device=device.id, name=name, vlan_id=vid, trace=self.trace(number, raw))
            elif section == "/ip address" and line.startswith("add "):
                name, address = values.get("interface", "unknown"), values.get("address")
                interface = interfaces.setdefault(name, Interface(device=device.id, name=name, trace=self.trace(number, raw)))
                if address: interface.addresses.append(address)
            elif section == "/ip route" and line.startswith("add "):
                routes.append(Route(device=device.id, destination=values.get("dst-address", "0.0.0.0/0"),
                    next_hop=values.get("gateway"), vrf=None if values.get("routing-table", "main") == "main" else values.get("routing-table"),
                    metric=int(values["distance"]) if values.get("distance", "").isdigit() else None,
                    trace=self.trace(number, raw)))
            elif section == "/ip vrf" and line.startswith("add "):
                for member in values.get("interfaces", "").split(","):
                    if member: interface_vrfs[member] = values.get("name", "main")
            elif section == "/ip firewall address-list" and line.startswith("add "):
                address_values.setdefault(values.get("list", "unnamed"), []).append(values.get("address", "any"))
            elif section == "/interface list member" and line.startswith("add "):
                interface_lists[values.get("list", "unnamed")].append(values.get("interface", "unknown"))
            elif section == "/ip firewall filter" and line.startswith("add "):
                pending_policies.append((number, line_end, raw, values))
            elif section == "/ip firewall nat" and line.startswith("add "):
                action = values.get("action", "nat")
                nat.append(NATRule(device=device.id, name=values.get("comment", f"nat-{number}"),
                    type="destination" if values.get("chain") == "dstnat" else "source",
                    original_src=values.get("src-address", "any"), original_dst=values.get("dst-address", "any"),
                    translated_src=values.get("to-addresses") if values.get("chain") != "dstnat" else None,
                    translated_dst=values.get("to-addresses") if values.get("chain") == "dstnat" else None,
                    protocol=values.get("protocol", "any"), trace=self.trace(number, raw)))
        for number, line_end, raw, values in pending_policies:
            if values.get("disabled", "no").lower() in {"yes", "true"}: continue
            action = values.get("action", "drop"); chain = values.get("chain", "forward")
            action_map = {"accept": "permit", "fasttrack-connection": "permit", "drop": "deny",
                          "reject": "reject", "tarpit": "deny", "jump": "jump", "return": "return"}
            canonical_action = action_map.get(action, "continue")
            terminal = canonical_action not in {"continue", "return"}
            src_name = values.get("src-address-list"); dst_name = values.get("dst-address-list")
            raw_src = values.get("src-address", src_name or "any"); raw_dst = values.get("dst-address", dst_name or "any")
            src_negate = raw_src.startswith("!"); dst_negate = raw_dst.startswith("!")
            raw_src = raw_src.removeprefix("!"); raw_dst = raw_dst.removeprefix("!")
            in_names = [values["in-interface"]] if values.get("in-interface") else interface_lists.get(values.get("in-interface-list", ""), [])
            out_names = [values["out-interface"]] if values.get("out-interface") else interface_lists.get(values.get("out-interface-list", ""), [])
            supported = {"chain", "action", "disabled", "src-address", "dst-address", "src-address-list",
                         "dst-address-list", "protocol", "dst-port", "in-interface", "out-interface",
                         "in-interface-list", "out-interface-list", "connection-state", "jump-target", "comment"}
            confidence = Confidence.PARTIAL if set(values) - supported else Confidence.EXACT
            policies.append(Policy(id=f"{device.id}:filter:{number}", device=device.id,
                name=values.get("comment", chain), sequence=number, order=len(policies) + 1,
                src=address_values.get(src_name, [raw_src]), dst=address_values.get(dst_name, [raw_dst]),
                src_negate=src_negate, dst_negate=dst_negate,
                protocol=[values.get("protocol", "ip")], dst_ports=values.get("dst-port", "any").split(","),
                action=canonical_action, direction="forward" if chain == "forward" else "unknown",
                interface=values.get("in-interface") or values.get("out-interface"),
                in_interfaces=in_names, out_interfaces=out_names,
                chain_id=f"routeros:{chain}", default_action="permit" if chain == "forward" else "unknown",
                terminal=terminal, jump_target=values.get("jump-target"),
                states=values.get("connection-state", "").split(",") if values.get("connection-state") else [],
                entrypoint=chain == "forward", confidence=confidence, trace=self.trace(number, raw, line_end)))
        segments: list[Segment] = []
        for interface in interfaces.values():
            interface.vrf = None if interface_vrfs.get(interface.name) in {None, "main"} else interface_vrfs[interface.name]
            interface.segment_id = f"{device.id}-{slug(interface.name)}"
            segments.append(Segment(id=interface.segment_id, name=interface.name,
                type="vlan" if interface.vlan_id is not None else "interface", device=device.id,
                vlan_id=interface.vlan_id, networks=interface_networks(interface.addresses), vrf=interface.vrf))
            if interface.vlan_id in vlans:
                vlans[interface.vlan_id].subnets = interface_networks(interface.addresses)
        objects = [AddressObject(device=device.id, name=name, values=values) for name, values in address_values.items()]
        return CanonicalConfig(device=device, interfaces=list(interfaces.values()), vlans=list(vlans.values()),
            segments=segments, routes=routes, policies=policies, nat=nat, address_objects=objects)
