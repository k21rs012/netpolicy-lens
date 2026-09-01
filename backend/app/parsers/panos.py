from __future__ import annotations

import re
from collections import defaultdict

from ..models import (
    AddressObject, CanonicalConfig, Device, Interface, NATRule, ParserCapabilities,
    ParserWarning, Policy, Route, Segment, ServiceObject, Zone,
)
from .base import BaseConfigParser
from .common import interface_networks, slug
from .registry import ParserRegistry


APPLICATIONS = {
    "web-browsing": ("tcp", "80"), "ssl": ("tcp", "443"), "ssh": ("tcp", "22"),
    "dns": ("udp", "53"), "ping": ("icmp", "any"), "icmp": ("icmp", "any"),
}


def _tokens(raw: str) -> list[str]:
    return [a or b for a, b in re.findall(r'"([^"]+)"|(\S+)', raw.strip(" []"))]


@ParserRegistry.register
class PANOSParser(BaseConfigParser):
    parser_id = "paloalto_panos"
    capabilities = ParserCapabilities(
        parser_id=parser_id, label="Palo Alto PAN-OS", interfaces=True, vlans=True,
        zones=True, routes=True, firewall_policy=True, nat=True, address_objects=True,
        service_objects=True, ipv6=True,
    )

    @classmethod
    def detect(cls, config: str) -> float:
        score = 0.0
        score += 0.28 if re.search(r"(?m)^set deviceconfig system hostname ", config) else 0
        score += 0.24 if re.search(r"(?m)^set network interface (?:ethernet|aggregate-ethernet|loopback|vlan) ", config) else 0
        score += 0.24 if re.search(r"(?m)^set rulebase security rules ", config) else 0
        score += 0.14 if re.search(r"(?m)^set zone \S+ network ", config) else 0
        score += 0.10 if re.search(r"(?m)^set address \S+ (?:ip-netmask|ip-range|fqdn) ", config) else 0
        return min(score, 1.0)

    def parse(self) -> CanonicalConfig:
        hostname_match = re.search(r"(?m)^set deviceconfig system hostname\s+(\S+)", self.config)
        hostname = hostname_match.group(1).strip('"') if hostname_match else slug(self.source_file.rsplit(".", 1)[0])
        device_id = slug(hostname)
        device = Device(id=device_id, hostname=hostname, vendor="paloalto", network_os="panos",
                        platform="PA-Series", source_file=self.source_file)
        interfaces: dict[str, Interface] = {}
        zone_members: dict[str, list[str]] = defaultdict(list)
        address_values: dict[str, list[str]] = {"any": ["any"]}
        address_objects: list[AddressObject] = []
        address_groups: dict[str, list[str]] = {}
        service_values: dict[str, tuple[str, list[str]]] = {"any": ("any", ["any"])}
        service_objects: list[ServiceObject] = []
        service_groups: dict[str, list[str]] = {}
        policy_data: dict[str, dict[str, list[str]]] = defaultdict(lambda: defaultdict(list))
        policy_lines: dict[str, list[tuple[int, str]]] = defaultdict(list)
        nat_data: dict[str, dict[str, list[str]]] = defaultdict(lambda: defaultdict(list))
        nat_lines: dict[str, list[tuple[int, str]]] = defaultdict(list)
        routes: list[Route] = []
        warnings: list[ParserWarning] = []

        for number, raw in enumerate(self.lines, 1):
            line = raw.strip()
            if match := re.match(r"set network interface (?:ethernet|aggregate-ethernet|loopback|vlan) (\S+)(?: layer3)? (?:units (\S+) )?ip (\S+)", line):
                name = match.group(1) if not match.group(2) else match.group(2)
                iface = interfaces.setdefault(name, Interface(device=device_id, name=name, trace=self.trace(number, raw)))
                iface.addresses.append(match.group(3))
            elif match := re.match(r"set zone (\S+) network (?:layer3|layer2|virtual-wire|tap) (.+)", line):
                zone_members[match.group(1)].extend(_tokens(match.group(2)))
            elif match := re.match(r"set address (\S+) (ip-netmask|ip-range|fqdn) (.+)", line):
                values = _tokens(match.group(3)); address_values[match.group(1)] = values
                address_objects.append(AddressObject(device=device_id, name=match.group(1), values=values))
            elif match := re.match(r"set address-group (\S+) static (.+)", line):
                address_groups[match.group(1)] = _tokens(match.group(2))
            elif match := re.match(r"set service (\S+) protocol (tcp|udp) port (.+)", line):
                ports = _tokens(match.group(3)); service_values[match.group(1)] = (match.group(2), ports)
                service_objects.append(ServiceObject(device=device_id, name=match.group(1), protocol=match.group(2), ports=ports))
            elif match := re.match(r"set service-group (\S+) members (.+)", line):
                service_groups[match.group(1)] = _tokens(match.group(2))
            elif match := re.match(r"set rulebase security rules (\S+) (from|to|source|destination|application|service|action) (.+)", line):
                policy_data[match.group(1)][match.group(2)] = _tokens(match.group(3)); policy_lines[match.group(1)].append((number, raw))
            elif match := re.match(r"set rulebase nat rules (\S+) (from|to|source|destination|service|source-translation|destination-translation) (.+)", line):
                nat_data[match.group(1)][match.group(2)] = _tokens(match.group(3)); nat_lines[match.group(1)].append((number, raw))
            elif match := re.match(r"set network virtual-router (\S+) routing-table (?:ip|ipv6) static-route (\S+) destination (\S+)", line):
                routes.append(Route(device=device_id, destination=match.group(3), trace=self.trace(number, raw)))
            elif match := re.match(r"set network virtual-router (\S+) routing-table (?:ip|ipv6) static-route (\S+) (?:nexthop ip-address|interface) (\S+)", line):
                route = next((r for r in reversed(routes) if r.trace and r.trace.raw_config.find(f"static-route {match.group(2)} ") >= 0), None)
                if route:
                    if "nexthop" in line: route.next_hop = match.group(3)
                    else: route.interface = match.group(3)
            elif line.startswith("set ") and not line.startswith("set deviceconfig system hostname "):
                warnings.append(ParserWarning(device=device_id, line=number, config=line,
                    reason="unsupported statement", parser=self.parser_id))

        zones: list[Zone] = []
        segments: list[Segment] = []
        for name, members in zone_members.items():
            segment_id = f"{device_id}-zone-{slug(name)}"
            zones.append(Zone(device=device_id, name=name, interfaces=members, segment_id=segment_id))
            networks = [net for member in members if member in interfaces for net in interface_networks(interfaces[member].addresses)]
            segments.append(Segment(id=segment_id, name=name.upper(), type="zone", device=device_id, networks=networks))
            for member in members:
                if member in interfaces: interfaces[member].zone = name; interfaces[member].segment_id = segment_id
        for iface in interfaces.values():
            if not iface.segment_id:
                iface.segment_id = f"{device_id}-if-{slug(iface.name)}"
                segments.append(Segment(id=iface.segment_id, name=iface.name.upper(), type="interface", device=device_id,
                                        networks=interface_networks(iface.addresses)))

        def resolve_addresses(names: list[str], seen: set[str] | None = None) -> list[str]:
            seen = seen or set(); out: list[str] = []
            for name in names or ["any"]:
                if name in seen: continue
                if name in address_groups: out += resolve_addresses(address_groups[name], seen | {name})
                else: out += address_values.get(name, [name])
            return list(dict.fromkeys(out))

        def resolve_services(names: list[str], apps: list[str]) -> tuple[list[str], list[str]]:
            protocols: list[str] = []; ports: list[str] = []
            def add(name: str, seen: set[str]):
                if name in seen: return
                if name in service_groups:
                    for member in service_groups[name]: add(member, seen | {name})
                elif name in service_values:
                    proto, values = service_values[name]; protocols.append(proto); ports.extend(values)
                elif name in ("application-default", "any"):
                    for app_name in apps or ["any"]:
                        proto, port = APPLICATIONS.get(app_name, ("any", "any")); protocols.append(proto); ports.append(port)
                else: protocols.append("any"); ports.append("any")
            for name in names or ["application-default"]: add(name, set())
            return list(dict.fromkeys(protocols)), list(dict.fromkeys(ports))

        segment_by_name = {z.name: z.segment_id for z in zones}
        policies: list[Policy] = []
        for sequence, (name, data) in enumerate(policy_data.items(), 1):
            protocols, ports = resolve_services(data.get("service", []), data.get("application", []))
            action = (data.get("action") or ["deny"])[0]
            canonical_action = "permit" if action in ("allow", "permit") else "deny" if action in ("deny", "drop", "reset-client", "reset-server", "reset-both") else "unknown"
            lines = policy_lines[name]; line_no = lines[0][0]; line_end = lines[-1][0]
            raw = "\n".join(x[1] for x in lines)
            policies.append(Policy(id=f"{device_id}:security:{name}", device=device_id, name=name, sequence=sequence,
                src=resolve_addresses(data.get("source", [])), dst=resolve_addresses(data.get("destination", [])),
                src_segments=[segment_by_name[x] for x in data.get("from", []) if x in segment_by_name],
                dst_segments=[segment_by_name[x] for x in data.get("to", []) if x in segment_by_name],
                protocol=protocols, dst_ports=ports, action=canonical_action, direction="zone",
                from_zone=", ".join(data.get("from", [])) or None, to_zone=", ".join(data.get("to", [])) or None,
                trace=self.trace(line_no, raw, line_end)))

        nat_rules: list[NATRule] = []
        for name, data in nat_data.items():
            lines = nat_lines[name]; line_no = lines[0][0]; line_end = lines[-1][0]
            raw = "\n".join(x[1] for x in lines)
            joined = " ".join(data.get("destination-translation", []))
            translated_dst = next(iter(re.findall(r"(?:translated-address|dynamic-ip-and-port)\s+(\S+)", joined)), None)
            translated_port_match = re.search(r"translated-port\s+(\d+)", joined)
            nat_type = "destination" if data.get("destination-translation") else "source"
            nat_protocols, nat_ports = resolve_services(data.get("service", []), [])
            original_port = int(nat_ports[0]) if nat_ports and nat_ports[0].isdigit() else None
            nat_rules.append(NATRule(device=device_id, name=name, type=nat_type,
                original_src=resolve_addresses(data.get("source", []))[0],
                original_dst=resolve_addresses(data.get("destination", []))[0],
                translated_dst=translated_dst, protocol=nat_protocols[0], original_port=original_port,
                translated_port=int(translated_port_match.group(1)) if translated_port_match else None,
                trace=self.trace(line_no, raw, line_end)))
        return CanonicalConfig(device=device, interfaces=list(interfaces.values()), segments=segments, zones=zones,
            routes=routes, policies=policies, nat=nat_rules, address_objects=address_objects,
            service_objects=service_objects, warnings=warnings)
