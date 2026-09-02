from __future__ import annotations

import re

from ..models import (
    AddressObject, CanonicalConfig, Confidence, Device, Interface, NATRule,
    ParserCapabilities, ParserWarning, Policy, Route, Segment, ServiceObject, Zone,
)
from .base import BaseConfigParser
from .common import hostname_from, interface_networks, mask_to_prefix, network_value, slug
from .registry import ParserRegistry


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
            return network_value(tokens[pos], tokens[pos + 1]), pos + 2
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
                if match := re.match(r"host\s+(\S+)", line): current_object.values.append(network_value(match.group(1) + "/32"))
                elif match := re.match(r"subnet\s+(\S+)\s+(\S+)", line): current_object.values.append(network_value(match.group(1), match.group(2)))
                elif match := re.match(r"range\s+(\S+)\s+(\S+)", line): current_object.values.append(f"{match.group(1)}-{match.group(2)}")
                elif match := re.match(r"network-object host\s+(\S+)", line): current_object.values.append(network_value(match.group(1) + "/32"))
                elif match := re.match(r"network-object object\s+(\S+)", line): current_object.values.append(match.group(1))
                elif match := re.match(r"network-object\s+(\S+)\s+(\S+)", line): current_object.values.append(network_value(match.group(1), match.group(2)))
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
                routes.append(Route(device=device.id, destination=network_value(match.group(2), match.group(3)),
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
