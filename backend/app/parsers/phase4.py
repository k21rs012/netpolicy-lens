from __future__ import annotations

import ipaddress
import re
import shlex

from ..models import (
    AddressObject, CanonicalConfig, Device, Interface, NATRule, ParserCapabilities,
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

    def _acl(self, device: str, name: str, body: str, number: int, sequence: int) -> Policy | None:
        tokens = body.split()
        if tokens and tokens[0] == "line" and len(tokens) > 2 and tokens[1].isdigit():
            sequence, tokens = int(tokens[1]), tokens[2:]
        if tokens and tokens[0] in {"extended", "standard"}:
            tokens = tokens[1:]
        if len(tokens) < 2 or tokens[0] not in {"permit", "deny"}:
            return None
        action, protocol = tokens[0], tokens[1]
        pos = 2
        src, pos = self._acl_address(tokens, pos)
        dst, pos = self._acl_address(tokens, pos)
        ports = ["any"]
        if pos < len(tokens) and tokens[pos] in {"eq", "range", "lt", "gt", "neq"}:
            operator = tokens[pos]
            count = 2 if operator == "range" else 1
            values = tokens[pos + 1:pos + 1 + count]
            ports = [values[0] if operator == "eq" and values else f"{operator} {'-'.join(values)}"]
        return Policy(id=f"{device}:{name}:{sequence}", device=device, name=name,
            sequence=sequence, src=[src], dst=[dst], protocol=[protocol],
            dst_ports=ports, action=action, trace=self.trace(number, body))

    def parse(self) -> CanonicalConfig:
        hostname = hostname_from(self.config, self.source_file)
        device = Device(id=slug(hostname), hostname=hostname, vendor="cisco",
            network_os=self.network_os, source_file=self.source_file)
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
        acl_bindings: dict[str, tuple[str, str]] = {}
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
                parsed = self._acl(device.id, match.group(1), match.group(2), number, len(policies) + 10)
                if parsed: policies.append(parsed)
                else: unsupported.append(ParserWarning(device=device.id, line=number, config=line,
                    reason="unsupported ASA ACL statement", parser=self.parser_id))
                continue
            if match := re.match(r"access-group\s+(\S+)\s+(in|out)\s+interface\s+(\S+)", line):
                acl_bindings[match.group(1)] = (match.group(3), match.group(2)); continue
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
        for policy in policies:
            if policy.name in acl_bindings:
                policy.interface, policy.direction = acl_bindings[policy.name]
                interface = next((item for item in interfaces if item.zone == policy.interface), None)
                if interface and interface.segment_id and policy.direction == "in":
                    policy.src_segments = [interface.segment_id]
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
        vlans: dict[int, VLAN] = {}
        vlan_names: dict[str, int] = {}
        interfaces: list[Interface] = []
        routes: list[Route] = []
        policies: list[Policy] = []
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
            if match := re.match(r"create access-list\s+(\S+)\s+\"?(permit|deny)\s+(\S+).*", line):
                policies.append(Policy(id=f"{device.id}:{match.group(1)}:{number}", device=device.id,
                    name=match.group(1), sequence=number, protocol=[match.group(3)], action=match.group(2),
                    trace=self.trace(number, raw)))
        segments: list[Segment] = []
        for vlan in vlans.values():
            svi = next((item for item in interfaces if item.vlan_id == vlan.id), None)
            if svi and svi.addresses: vlan.subnets = interface_networks(svi.addresses); vlan.gateway = svi.addresses[0].split("/")[0]
            seg_id = f"{device.id}-vlan-{vlan.id}"
            segments.append(Segment(id=seg_id, name=vlan.name, type="vlan", device=device.id,
                vlan_id=vlan.id, networks=vlan.subnets))
            if svi: svi.segment_id = seg_id
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
        interfaces: dict[str, Interface] = {}
        vlans: dict[int, VLAN] = {}
        routes: list[Route] = []
        policies: list[Policy] = []
        nat: list[NATRule] = []
        address_values: dict[str, list[str]] = {}
        section = ""
        for number, raw in enumerate(self.lines, 1):
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
                    next_hop=values.get("gateway"), trace=self.trace(number, raw)))
            elif section == "/ip firewall address-list" and line.startswith("add "):
                address_values.setdefault(values.get("list", "unnamed"), []).append(values.get("address", "any"))
            elif section == "/ip firewall filter" and line.startswith("add "):
                action = values.get("action", "drop")
                policies.append(Policy(id=f"{device.id}:filter:{number}", device=device.id,
                    name=values.get("comment", values.get("chain", "filter")), sequence=number,
                    src=[values.get("src-address", values.get("src-address-list", "any"))],
                    dst=[values.get("dst-address", values.get("dst-address-list", "any"))],
                    protocol=[values.get("protocol", "ip")], dst_ports=[values.get("dst-port", "any")],
                    action="permit" if action in {"accept", "fasttrack-connection"} else "reject" if action == "reject" else "deny",
                    direction="in" if values.get("chain") == "input" else "out" if values.get("chain") == "output" else "unknown",
                    interface=values.get("in-interface") or values.get("out-interface"), trace=self.trace(number, raw)))
            elif section == "/ip firewall nat" and line.startswith("add "):
                action = values.get("action", "nat")
                nat.append(NATRule(device=device.id, name=values.get("comment", f"nat-{number}"),
                    type="destination" if values.get("chain") == "dstnat" else "source",
                    original_src=values.get("src-address", "any"), original_dst=values.get("dst-address", "any"),
                    translated_src=values.get("to-addresses") if values.get("chain") != "dstnat" else None,
                    translated_dst=values.get("to-addresses") if values.get("chain") == "dstnat" else None,
                    protocol=values.get("protocol", "any"), trace=self.trace(number, raw)))
        segments: list[Segment] = []
        for interface in interfaces.values():
            interface.segment_id = f"{device.id}-{slug(interface.name)}"
            segments.append(Segment(id=interface.segment_id, name=interface.name,
                type="vlan" if interface.vlan_id is not None else "interface", device=device.id,
                vlan_id=interface.vlan_id, networks=interface_networks(interface.addresses)))
            if interface.vlan_id in vlans:
                vlans[interface.vlan_id].subnets = interface_networks(interface.addresses)
        objects = [AddressObject(device=device.id, name=name, values=values) for name, values in address_values.items()]
        return CanonicalConfig(device=device, interfaces=list(interfaces.values()), vlans=list(vlans.values()),
            segments=segments, routes=routes, policies=policies, nat=nat, address_objects=objects)
