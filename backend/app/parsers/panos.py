from __future__ import annotations

import ipaddress
import re
from collections import defaultdict

from ..models import (
    AddressObject, CanonicalConfig, Confidence, Device, Interface, NATRule, ParserCapabilities,
    ParserWarning, Policy, Route, Segment, ServiceObject, VLAN, Zone,
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
        config = re.sub(r"(?m)^set vsys \S+ ", "set ", config)
        score = 0.0
        score += 0.28 if re.search(r"(?m)^set deviceconfig system hostname ", config) else 0
        score += 0.24 if re.search(r"(?m)^set network interface (?:ethernet|aggregate-ethernet|loopback|vlan) ", config) else 0
        score += 0.24 if re.search(r"(?m)^set rulebase security rules ", config) else 0
        score += 0.14 if re.search(r"(?m)^set zone \S+ network ", config) else 0
        score += 0.10 if re.search(r"(?m)^set address \S+ (?:ip-netmask|ip-range|fqdn) ", config) else 0
        return min(score, 1.0)

    def __init__(self, config: str, source_file: str):
        # A PAN-OS set export may scope policy objects under ``vsys <name>``.
        # Removing that prefix one line at a time keeps source line traces exact.
        self.original_lines = config.splitlines()
        config = re.sub(r"(?m)^set vsys \S+ ", "set ", config)
        super().__init__(config, source_file)

    def trace(self, line: int, raw: str, end: int | None = None):
        trace = super().trace(line, raw, end)
        line_end = end or line
        if 0 < line <= line_end <= len(self.original_lines):
            trace.raw_config = "\n".join(self.original_lines[line - 1:line_end])
        return trace

    def parse(self) -> CanonicalConfig:
        hostname_match = re.search(r"(?m)^set deviceconfig system hostname\s+(\S+)", self.config)
        hostname = hostname_match.group(1).strip('"') if hostname_match else slug(self.source_file.rsplit(".", 1)[0])
        device_id = slug(hostname)
        device = Device(id=device_id, hostname=hostname, vendor="paloalto", network_os="panos",
                        platform="PA-Series", source_file=self.source_file)
        device.features["dynamic_routing"] = bool(re.search(r"(?m)^set network virtual-router \S+ protocol (?:bgp|ospf|ospfv3|rip)\b", self.config))
        interfaces: dict[str, Interface] = {}
        vlan_ids: dict[str, int] = {}
        zone_members: dict[str, list[str]] = defaultdict(list)
        address_values: dict[str, list[str]] = {"any": ["any"]}
        address_objects: list[AddressObject] = []
        address_groups: dict[str, list[str]] = {}
        service_values: dict[str, tuple[str, list[str]]] = {"any": ("any", ["any"])}
        service_objects: list[ServiceObject] = []
        service_groups: dict[str, list[str]] = {}
        policy_data: dict[str, dict[str, list[str]]] = defaultdict(lambda: defaultdict(list))
        policy_lines: dict[str, list[tuple[int, str]]] = defaultdict(list)
        policy_names: dict[str, str] = {}
        policy_tiers: dict[str, int] = {}
        partial_policies: set[str] = set()
        nat_data: dict[str, dict[str, list[str]]] = defaultdict(lambda: defaultdict(list))
        nat_lines: dict[str, list[tuple[int, str]]] = defaultdict(list)
        route_data: dict[tuple[str, str], Route] = {}
        interface_vrfs: dict[str, str] = {}
        warnings: list[ParserWarning] = []
        unsupported: list[ParserWarning] = []
        policy_moves: list[tuple[str, str, str | None]] = []

        for number, raw in enumerate(self.lines, 1):
            line = raw.strip()
            if match := re.match(r"set network interface (?:ethernet|aggregate-ethernet) \S+ layer3 units (\S+) tag (\d+)", line):
                name = match.group(1); vlan_ids[name] = int(match.group(2))
                interfaces.setdefault(name, Interface(device=device_id, name=name, vlan_id=int(match.group(2)), trace=self.trace(number, raw)))
            elif match := re.match(r"set network interface vlan units (\S+) tag (\d+)", line):
                name = match.group(1); vlan_ids[name] = int(match.group(2))
                interfaces.setdefault(name, Interface(device=device_id, name=name, vlan_id=int(match.group(2)), trace=self.trace(number, raw)))
            elif match := re.match(r"set network interface vlan units (\S+) ip (\S+)", line):
                name = match.group(1); iface = interfaces.setdefault(name, Interface(device=device_id, name=name, trace=self.trace(number, raw)))
                iface.addresses.append(match.group(2))
            elif match := re.match(r"set network interface (?:ethernet|aggregate-ethernet|loopback|vlan) (\S+)(?: layer3)? (?:units (\S+) )?ip (\S+)", line):
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
            elif match := re.match(r"set network virtual-router (\S+) interface (.+)", line):
                for member in _tokens(match.group(2)): interface_vrfs[member] = match.group(1)
            elif match := re.match(r"set (?:(shared|vsys \S+|device-group \S+|policy panorama) )?(pre-rulebase|post-rulebase|rulebase) security rules (\S+) (from|to|source|destination|application|service|action|disabled) (.+)", line):
                scope, tier, name, field, value = match.groups(); key = f"{scope or 'local'}:{tier}:{name}"
                policy_names[key] = name; policy_tiers[key] = {"pre-rulebase": 0, "rulebase": 1, "post-rulebase": 2}[tier]
                policy_data[key][field] = _tokens(value); policy_lines[key].append((number, raw))
            elif match := re.match(r"move (?:(shared|vsys \S+|device-group \S+|policy panorama) )?(pre-rulebase|post-rulebase|rulebase) security rules (\S+) (top|bottom|before|after)(?:\s+(\S+))?", line):
                scope, tier, name, where, anchor = match.groups(); prefix = f"{scope or 'local'}:{tier}:"
                policy_moves.append((prefix + name, where, prefix + anchor if anchor else None))
            elif match := re.match(r"set (?:(shared|vsys \S+|device-group \S+|policy panorama) )?(pre-rulebase|post-rulebase|rulebase) security rules (\S+) (\S+) .+", line):
                scope, tier, name, field = match.groups()
                if field not in {"description", "tag", "log-start", "log-end", "log-setting", "profile-setting"}:
                    partial_policies.add(f"{scope or 'local'}:{tier}:{name}")
                unsupported.append(ParserWarning(device=device_id, line=number, config=line,
                    reason="unsupported security policy field", parser=self.parser_id))
            elif match := re.match(r"set rulebase nat rules (\S+) (from|to|source|destination|service|source-translation|destination-translation) (.+)", line):
                nat_data[match.group(1)][match.group(2)] = _tokens(match.group(3)); nat_lines[match.group(1)].append((number, raw))
            elif match := re.match(r"set network virtual-router (\S+) routing-table (?:ip|ipv6) static-route (\S+) destination (\S+)", line):
                key = (match.group(1), match.group(2)); route = route_data.setdefault(key,
                    Route(device=device_id, destination=match.group(3), vrf=match.group(1), trace=self.trace(number, raw)))
                route.destination = match.group(3)
            elif match := re.match(r"set network virtual-router (\S+) routing-table (?:ip|ipv6) static-route (\S+) (?:nexthop ip-address|interface) (\S+)", line):
                key = (match.group(1), match.group(2)); route = route_data.setdefault(key,
                    Route(device=device_id, destination="0.0.0.0/0", vrf=match.group(1), trace=self.trace(number, raw)))
                if "nexthop" in line: route.next_hop = match.group(3)
                else: route.interface = match.group(3)
            elif match := re.match(r"set network virtual-router (\S+) routing-table (?:ip|ipv6) static-route (\S+) metric (\d+)", line):
                key = (match.group(1), match.group(2)); route = route_data.setdefault(key,
                    Route(device=device_id, destination="0.0.0.0/0", vrf=match.group(1), trace=self.trace(number, raw)))
                route.metric = int(match.group(3))
            elif line.startswith("set ") and not line.startswith("set deviceconfig system hostname "):
                unsupported.append(ParserWarning(device=device_id, line=number, config=line,
                    reason="unsupported statement", parser=self.parser_id))

        routes = list(route_data.values())
        for name, vrf in interface_vrfs.items():
            if name in interfaces: interfaces[name].vrf = vrf
        zones: list[Zone] = []
        segments: list[Segment] = []
        for name, members in zone_members.items():
            segment_id = f"{device_id}-zone-{slug(name)}"
            zones.append(Zone(device=device_id, name=name, interfaces=members, segment_id=segment_id))
            networks = [net for member in members if member in interfaces for net in interface_networks(interfaces[member].addresses)]
            segments.append(Segment(id=segment_id, name=name.upper(), type="zone", device=device_id, networks=networks,
                vrf=next((interfaces[member].vrf for member in members if member in interfaces and interfaces[member].vrf), None)))
            for member in members:
                if member in interfaces: interfaces[member].zone = name; interfaces[member].segment_id = segment_id
        for iface in interfaces.values():
            if not iface.segment_id:
                iface.segment_id = f"{device_id}-if-{slug(iface.name)}"
                segments.append(Segment(id=iface.segment_id, name=iface.name.upper(), type="vlan" if iface.vlan_id else "interface", device=device_id,
                                        vlan_id=iface.vlan_id, networks=interface_networks(iface.addresses), vrf=iface.vrf))
        vlans = [VLAN(device=device_id, id=vlan_id, name=name, subnets=interface_networks(interfaces[name].addresses),
            gateway=interfaces[name].addresses[0].split("/")[0] if interfaces[name].addresses else None,
            trace=interfaces[name].trace) for name, vlan_id in vlan_ids.items()]

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

        def unknown_addresses(names: list[str], seen: set[str] | None = None) -> set[str]:
            seen = seen or set(); result: set[str] = set()
            for name in names:
                if name in seen or name in address_values: continue
                if name in address_groups:
                    result.update(unknown_addresses(address_groups[name], seen | {name})); continue
                try:
                    ipaddress.ip_network(name, strict=False)
                except ValueError:
                    result.add(name)
            return result

        def unknown_services(names: list[str], seen: set[str] | None = None) -> set[str]:
            seen = seen or set(); result: set[str] = set()
            for name in names:
                if name in seen or name in service_values or name == "application-default": continue
                if name in service_groups:
                    result.update(unknown_services(service_groups[name], seen | {name}))
                else:
                    result.add(name)
            return result

        policy_order = sorted(policy_data, key=lambda key: (policy_tiers.get(key, 1), list(policy_data).index(key)))
        for name, where, anchor in policy_moves:
            if name not in policy_order: continue
            policy_order.remove(name)
            if where == "top": policy_order.insert(0, name)
            elif where == "bottom": policy_order.append(name)
            elif anchor in policy_order:
                index = policy_order.index(anchor); policy_order.insert(index + (1 if where == "after" else 0), name)
            else: policy_order.append(name)
        for sequence, key in enumerate(policy_order, 1):
            data = policy_data[key]; name = policy_names.get(key, key.rsplit(":", 1)[-1])
            if (data.get("disabled") or ["no"])[0] == "yes":
                continue
            protocols, ports = resolve_services(data.get("service", []), data.get("application", []))
            action = (data.get("action") or ["deny"])[0]
            canonical_action = "permit" if action in ("allow", "permit") else "deny" if action in ("deny", "drop", "reset-client", "reset-server", "reset-both") else "unknown"
            lines = policy_lines[key]; line_no = lines[0][0]; line_end = lines[-1][0]
            raw = "\n".join(x[1] for x in lines)
            policies.append(Policy(id=f"{device_id}:security:{name}", device=device_id, name=name, sequence=sequence,
                src=resolve_addresses(data.get("source", [])), dst=resolve_addresses(data.get("destination", [])),
                src_segments=[segment_by_name[x] for x in data.get("from", []) if x in segment_by_name],
                dst_segments=[segment_by_name[x] for x in data.get("to", []) if x in segment_by_name],
                protocol=protocols, dst_ports=ports, action=canonical_action, direction="zone",
                chain_id="panos:security",
                confidence=Confidence.PARTIAL if key in partial_policies else Confidence.EXACT,
                from_zone=", ".join(data.get("from", [])) or None, to_zone=", ".join(data.get("to", [])) or None,
                trace=self.trace(line_no, raw, line_end)))
            unresolved = unknown_addresses([*data.get("source", []), *data.get("destination", [])])
            unresolved.update(x for x in [*data.get("from", []), *data.get("to", [])] if x not in segment_by_name)
            unresolved.update(unknown_services(data.get("service", [])))
            for reference in sorted(unresolved):
                warnings.append(ParserWarning(device=device_id, line=line_no, config=raw,
                    reason=f"unresolved policy reference: {reference}", parser=self.parser_id))

        nat_rules: list[NATRule] = []
        for sequence, (name, data) in enumerate(nat_data.items(), 1):
            lines = nat_lines[name]; line_no = lines[0][0]; line_end = lines[-1][0]
            raw = "\n".join(x[1] for x in lines)
            joined = " ".join(data.get("destination-translation", []))
            joined_source = " ".join(data.get("source-translation", []))
            translated_dst = next(iter(re.findall(r"(?:translated-address|dynamic-ip-and-port)\s+(\S+)", joined)), None)
            translated_src = next(iter(re.findall(
                r"(?:translated-address|dynamic-ip-and-port|dynamic-ip)\s+(\S+)", joined_source
            )), None)
            if joined_source and not translated_src and "interface-address" in joined_source:
                translated_src = "interface-address"
            translated_port_match = re.search(r"translated-port\s+(\d+)", joined)
            nat_type = "destination" if data.get("destination-translation") else "source"
            nat_protocols, nat_ports = resolve_services(data.get("service", []), [])
            original_port = int(nat_ports[0]) if nat_ports and nat_ports[0].isdigit() else None
            nat_rules.append(NATRule(device=device_id, name=name, type=nat_type,
                original_src=resolve_addresses(data.get("source", []))[0],
                original_dst=resolve_addresses(data.get("destination", []))[0],
                translated_src=translated_src, translated_dst=translated_dst,
                protocol=nat_protocols[0], original_port=original_port,
                sequence=sequence, destination_ports=nat_ports if nat_ports != ["any"] else [],
                in_interfaces=data.get("from", []), out_interfaces=data.get("to", []),
                translated_port=int(translated_port_match.group(1)) if translated_port_match else None,
                trace=self.trace(line_no, raw, line_end)))
        return CanonicalConfig(device=device, interfaces=list(interfaces.values()), vlans=vlans, segments=segments, zones=zones,
            routes=routes, policies=policies, nat=nat_rules, address_objects=address_objects,
            service_objects=service_objects, warnings=warnings, unsupported=unsupported)
