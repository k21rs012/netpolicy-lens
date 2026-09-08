from __future__ import annotations

import ipaddress
import re
from collections import defaultdict

from ..models import AddressObject, CanonicalConfig, Confidence, Device, Interface, NATRule, ParserCapabilities, ParserWarning, Policy, Route, Segment, ServiceObject, Trace, VLAN, Zone
from .base import BaseConfigParser
from .common import hostname_from, interface_networks, slug
from .junos_hier import hierarchical_to_set, is_hierarchical_junos
from .registry import ParserRegistry


APPS = {"junos-http": ("tcp", "80"), "junos-https": ("tcp", "443"), "junos-ssh": ("tcp", "22"),
        "junos-dns-udp": ("udp", "53"), "junos-dns-tcp": ("tcp", "53"), "junos-icmp-all": ("icmp", "any"),
        "junos-dhcp-client": ("udp", "68"), "junos-dhcp-relay": ("udp", "67"), "junos-dhcp-server": ("udp", "67")}


class JunosBaseParser(BaseConfigParser):
    parser_id = "juniper_junos"
    network_os = "junos"
    capabilities = ParserCapabilities(parser_id="juniper_junos", label="Juniper Junos", interfaces=True, vlans=True, routes=True, acl=True, ipv6=True)

    @classmethod
    def detect(cls, config: str) -> float:
        score = 0.0
        score += 0.4 if re.search(r"(?m)^set interfaces \S+", config) else 0
        score += 0.25 if re.search(r"(?m)^set system host-name", config) else 0
        score += 0.25 if re.search(r"(?m)^set security (?:zones|policies)", config) else 0
        score += 0.1 if re.search(r"(?m)^set routing-options", config) else 0
        if is_hierarchical_junos(config):
            score = max(score, 0.35)
            score += 0.2 if re.search(r"(?m)^security\s*\{", config) else 0
            score += 0.1 if re.search(r"(?m)^routing-options\s*\{", config) else 0
        return min(score, 1.0)

    def __init__(self, config: str, source_file: str):
        self.hierarchical = is_hierarchical_junos(config)
        if self.hierarchical:
            normalized = hierarchical_to_set(config)
            self.source_lines = [item.source_line for item in normalized]
            config = "\n".join(item.text for item in normalized)
        else:
            self.source_lines = []
        super().__init__(config, source_file)

    def trace(self, line: int, raw: str, end: int | None = None) -> Trace:
        if self.hierarchical and 0 < line <= len(self.source_lines):
            source_line = self.source_lines[line - 1]
            return Trace(source_file=self.source_file, line_start=source_line, line_end=source_line, raw_config=raw.strip())
        return super().trace(line, raw, end)

    def parse(self) -> CanonicalConfig:
        hostname = hostname_from(self.config, self.source_file); device_id = slug(hostname)
        device = Device(id=device_id, hostname=hostname, vendor="juniper", network_os=self.network_os, source_file=self.source_file)
        device.features["dynamic_routing"] = bool(re.search(r"(?m)^set protocols (?:ospf|ospf3|bgp|isis|rip)\b", self.config))
        ifaces: dict[str, Interface] = {}; zones: dict[str, Zone] = {}; addresses: list[AddressObject] = []; routes: list[Route] = []
        custom_apps: dict[str, dict[str, str]] = defaultdict(dict); app_sets: dict[str, list[str]] = defaultdict(list)
        address_sets: dict[str, list[str]] = defaultdict(list)
        interface_vrfs: dict[str, str] = {}
        vlan_data: dict[str, dict[str, str]] = defaultdict(dict); nat_pools: dict[tuple[str, str], dict[str, str]] = defaultdict(dict)
        nat_data: dict[tuple[str, str, str], dict[str, str | int]] = defaultdict(dict)
        policy_data: dict[tuple[str, str, str], dict] = defaultdict(lambda: {"src": [], "dst": [], "apps": [], "action": "unknown", "line": 0, "raw": "", "partial": False})
        global_policy_data: dict[str, dict] = defaultdict(lambda: {"from": [], "to": [], "src": [], "dst": [], "apps": [], "action": "unknown", "line": 0, "raw": "", "partial": False})
        unsupported: list[ParserWarning] = []
        applied_groups = {match.group(1) for raw in self.lines
                          if (match := re.match(r"set apply-groups\s+(\S+)", raw.strip()))}
        for n, raw in enumerate(self.lines, 1):
            line = raw.strip()
            if match := re.match(r"set groups (\S+) (.+)", line):
                if match.group(1) not in applied_groups: continue
                line = "set " + match.group(2)
            if match := re.match(r"set interfaces (\S+) unit (\S+) family (inet6?|ethernet-switching) address (\S+)", line):
                name = f"{match.group(1)}.{match.group(2)}"; iface = ifaces.setdefault(name, Interface(device=device_id, name=name, trace=self.trace(n, raw)))
                if match.group(4) not in iface.addresses: iface.addresses.append(match.group(4))
            elif match := re.match(r"set interfaces (\S+) description \"?(.+?)\"?$", line):
                iface = ifaces.setdefault(match.group(1), Interface(device=device_id, name=match.group(1), trace=self.trace(n, raw))); iface.description = match.group(2)
            elif match := re.match(r"set security zones security-zone (\S+) interfaces (\S+)", line):
                zone = zones.setdefault(match.group(1), Zone(device=device_id, name=match.group(1), segment_id=f"{device_id}-zone-{slug(match.group(1))}")); zone.interfaces.append(match.group(2))
            elif match := re.match(r"set security zones security-zone (\S+) address-book address (\S+) (\S+)", line):
                addresses.append(AddressObject(device=device_id, name=match.group(2), values=[match.group(3)]))
            elif match := re.match(r"set security address-book \S+ address (\S+) (\S+)", line):
                addresses.append(AddressObject(device=device_id, name=match.group(1), values=[match.group(2)]))
            elif match := re.match(r"set security address-book \S+ address-set (\S+) address (\S+)", line):
                address_sets[match.group(1)].append(match.group(2))
            elif match := re.match(r"set applications application (\S+) (protocol|destination-port) (\S+)", line):
                custom_apps[match.group(1)][match.group(2)] = match.group(3)
            elif match := re.match(r"set applications application-set (\S+) application (\S+)", line):
                app_sets[match.group(1)].append(match.group(2))
            elif match := re.match(r"set vlans (\S+) vlan-id (\d+)", line):
                vlan_data[match.group(1)]["id"] = match.group(2)
            elif match := re.match(r"set vlans (\S+) l3-interface (\S+)", line):
                vlan_data[match.group(1)]["interface"] = match.group(2)
            elif match := re.match(r"set routing-instances (\S+) interface (\S+)", line):
                interface_vrfs[match.group(2)] = match.group(1)
            elif match := re.match(r"set security nat destination pool (\S+) address port (\d+)", line):
                nat_pools[("destination", match.group(1))]["port"] = match.group(2)
            elif match := re.match(r"set security nat (source|destination) pool (\S+) address (\S+)", line):
                nat_pools[(match.group(1), match.group(2))]["address"] = match.group(3)
            elif match := re.match(r"set security nat (source|destination|static) rule-set (\S+) rule (\S+) match (source-address|destination-address|source-port|destination-port|protocol) (\S+)", line):
                key = match.group(1), match.group(2), match.group(3); nat_data[key][match.group(4)] = match.group(5)
                nat_data[key]["line"] = n; nat_data[key]["raw"] = raw
            elif match := re.match(r"set security nat (source|destination|static) rule-set (\S+) rule (\S+) then (?:source-nat|destination-nat|static-nat) (.+)", line):
                key = match.group(1), match.group(2), match.group(3); nat_data[key]["translation"] = match.group(4)
                nat_data[key]["line"] = n; nat_data[key]["raw"] = raw
            elif match := re.match(r"set security policies from-zone (\S+) to-zone (\S+) policy (\S+) match (source-address|destination-address|application) (.+)", line):
                key = match.group(1), match.group(2), match.group(3); data = policy_data[key]; data[{"source-address": "src", "destination-address": "dst", "application": "apps"}[match.group(4)]].extend(match.group(5).strip("[]").split()); data["line"] = n; data["raw"] = raw
            elif match := re.match(r"set security policies from-zone (\S+) to-zone (\S+) policy (\S+) then (permit|deny|reject)", line):
                key = match.group(1), match.group(2), match.group(3); policy_data[key]["action"] = match.group(4); policy_data[key]["line"] = n; policy_data[key]["raw"] = raw
            elif match := re.match(r"set security policies global policy (\S+) match (from-zone|to-zone|source-address|destination-address|application) (.+)", line):
                name, field, values = match.groups(); data = global_policy_data[name]
                key = {"from-zone": "from", "to-zone": "to", "source-address": "src",
                       "destination-address": "dst", "application": "apps"}[field]
                data[key].extend(values.strip("[]").split()); data["line"] = n; data["raw"] = raw
            elif match := re.match(r"set security policies global policy (\S+) then (permit|deny|reject)", line):
                data = global_policy_data[match.group(1)]; data["action"] = match.group(2); data["line"] = n; data["raw"] = raw
            elif match := re.match(r"set security policies from-zone (\S+) to-zone (\S+) policy (\S+) match \S+ .+", line):
                policy_data[(match.group(1), match.group(2), match.group(3))]["partial"] = True
            elif match := re.match(r"set security policies global policy (\S+) match \S+ .+", line):
                global_policy_data[match.group(1)]["partial"] = True
            elif match := re.match(r"set (?:routing-options|routing-options rib \S+) static route (\S+) (?:next-hop|qualified-next-hop) (\S+)", line):
                routes.append(Route(device=device_id, destination=match.group(1), next_hop=match.group(2), trace=self.trace(n, raw)))
            elif match := re.match(r"set routing-instances \S+ routing-options static route (\S+) (?:next-hop|qualified-next-hop) (\S+)", line):
                instance = line.split()[2]
                routes.append(Route(device=device_id, destination=match.group(1), next_hop=match.group(2), vrf=instance, trace=self.trace(n, raw)))
            elif line.startswith(("set security policies ", "set security nat ", "set security zones ")):
                unsupported.append(ParserWarning(device=device_id, line=self.trace(n, raw).line_start,
                    config=line, reason="unsupported security statement", parser=self.parser_id))
        vlans: list[VLAN] = []
        for name, vrf in interface_vrfs.items():
            if name in ifaces: ifaces[name].vrf = vrf
        for name, data in vlan_data.items():
            if "id" not in data: continue
            vlan_id = int(data["id"]); interface = data.get("interface")
            iface = ifaces.get(interface or "")
            if iface: iface.vlan_id = vlan_id
            vlans.append(VLAN(device=device_id, id=vlan_id, name=name,
                subnets=interface_networks(iface.addresses) if iface else [],
                gateway=iface.addresses[0].split("/")[0] if iface and iface.addresses else None,
                trace=iface.trace if iface else None))
        segments = [Segment(id=z.segment_id, name=z.name.upper(), type="zone", device=device_id,
                            networks=[net for name in z.interfaces if name in ifaces for net in interface_networks(ifaces[name].addresses)],
                            vrf=next((ifaces[name].vrf for name in z.interfaces if name in ifaces and ifaces[name].vrf), None)) for z in zones.values()]
        for z in zones.values():
            for name in z.interfaces:
                if name in ifaces: ifaces[name].zone = z.name; ifaces[name].segment_id = z.segment_id
        for vlan in vlans:
            interface = vlan_data[vlan.name].get("interface"); iface = ifaces.get(interface or "")
            if iface and not iface.segment_id:
                iface.segment_id = f"{device_id}-vlan-{vlan.id}"
                segments.append(Segment(id=iface.segment_id, name=vlan.name, type="vlan", device=device_id,
                    vlan_id=vlan.id, networks=vlan.subnets, vrf=iface.vrf))
        policies: list[Policy] = []
        warnings: list[ParserWarning] = []
        address_values = {item.name: item.values for item in addresses}

        def resolve_address_set(name: str, seen: set[str] | None = None) -> list[str]:
            seen = seen or set()
            if name in seen: return []
            if name in address_values: return address_values[name]
            return [value for member in address_sets.get(name, [])
                    for value in resolve_address_set(member, seen | {name})]

        def resolve_policy_addresses(names: list[str]) -> list[str]:
            result: list[str] = []
            for name in names or ["any"]:
                resolved = resolve_address_set(name)
                result.extend(resolved or [name])
            return list(dict.fromkeys(result))

        addresses.extend(AddressObject(device=device_id, name=name, values=resolve_address_set(name))
            for name in address_sets)
        address_names = {item.name for item in addresses}

        def known_address(name: str) -> bool:
            if name.lower() in ("any", "any-ipv4", "any-ipv6") or name in address_names:
                return True
            try:
                ipaddress.ip_network(name, strict=False)
                return True
            except ValueError:
                return False
        def resolve_app(name: str, seen: set[str] | None = None) -> list[tuple[str, str]]:
            if name in APPS: return [APPS[name]]
            if name.lower() == "any": return [("any", "any")]
            if name in custom_apps:
                app = custom_apps[name]
                return [(app.get("protocol", "any"), app.get("destination-port", "any"))]
            seen = set() if seen is None else seen
            if name in app_sets and name not in seen:
                return [service for member in app_sets[name] for service in resolve_app(member, seen | {name})]
            return [("any", "any")]
        for seq, ((from_zone, to_zone, name), data) in enumerate(policy_data.items(), 1):
            protocols, ports = [], []
            for app in data["apps"] or ["any"]:
                for proto, port in resolve_app(app): protocols.append(proto); ports.append(port)
            policies.append(Policy(id=f"{device_id}:{from_zone}:{to_zone}:{name}", device=device_id, name=name, sequence=seq,
                src=data["src"] or ["any"], dst=data["dst"] or ["any"], src_segments=[zones[from_zone].segment_id] if from_zone in zones else [],
                dst_segments=[zones[to_zone].segment_id] if to_zone in zones else [], protocol=list(dict.fromkeys(protocols)), dst_ports=list(dict.fromkeys(ports)),
                action=data["action"], direction="zone", from_zone=from_zone, to_zone=to_zone,
                chain_id=f"zone:{from_zone}:{to_zone}",
                confidence=Confidence.PARTIAL if data["partial"] else Confidence.EXACT,
                trace=self.trace(data["line"], data["raw"])))
            for reference in [*data["src"], *data["dst"]]:
                if not known_address(reference):
                    warnings.append(ParserWarning(device=device_id, line=self.trace(data["line"], data["raw"]).line_start,
                        config=data["raw"].strip(), reason=f"unresolved address reference: {reference}", parser=self.parser_id))
            for zone_name in (from_zone, to_zone):
                if zone_name not in zones and zone_name != "junos-host":
                    warnings.append(ParserWarning(device=device_id, line=self.trace(data["line"], data["raw"]).line_start,
                        config=data["raw"].strip(), reason=f"unresolved zone reference: {zone_name}", parser=self.parser_id))
        sequence = len(policies)
        zone_names = list(zones)
        for name, data in global_policy_data.items():
            from_zones = data["from"] or zone_names
            to_zones = data["to"] or zone_names
            protocols: list[str] = []; ports: list[str] = []
            for app in data["apps"] or ["any"]:
                for proto, port in resolve_app(app): protocols.append(proto); ports.append(port)
            for from_zone in from_zones:
                for to_zone in to_zones:
                    if from_zone not in zones or to_zone not in zones: continue
                    sequence += 1
                    policies.append(Policy(id=f"{device_id}:global:{name}:{from_zone}:{to_zone}", device=device_id,
                        name=name, sequence=sequence, order=1_000_000 + sequence,
                        src=data["src"] or ["any"], dst=data["dst"] or ["any"],
                        src_segments=[zones[from_zone].segment_id], dst_segments=[zones[to_zone].segment_id],
                        protocol=list(dict.fromkeys(protocols)), dst_ports=list(dict.fromkeys(ports)),
                        action=data["action"], direction="zone", from_zone=from_zone, to_zone=to_zone,
                        chain_id=f"zone:{from_zone}:{to_zone}",
                        confidence=Confidence.PARTIAL if data["partial"] else Confidence.EXACT,
                        trace=self.trace(data["line"], data["raw"])))
        services = [ServiceObject(device=device_id, name=k, protocol=v[0], ports=[v[1]]) for k, v in APPS.items()]
        services.extend(ServiceObject(device=device_id, name=name, protocol=data.get("protocol", "any"), ports=[data.get("destination-port", "any")]) for name, data in custom_apps.items())
        nat_rules: list[NATRule] = []
        for sequence, ((kind, rule_set, rule), data) in enumerate(nat_data.items(), 1):
            translation = str(data.get("translation", "")); translated_src = None; translated_dst = None; translated_port = None
            if kind == "source":
                if translation == "interface": translated_src = "interface-address"
                elif translation.startswith("pool "):
                    pool = translation.removeprefix("pool "); translated_src = nat_pools.get(("source", pool), {}).get("address", pool)
            elif kind == "destination" and translation.startswith("pool "):
                pool = translation.removeprefix("pool "); values = nat_pools.get(("destination", pool), {})
                translated_dst = values.get("address", pool); translated_port = int(values["port"]) if values.get("port", "").isdigit() else None
            elif kind == "static":
                # SRX uses `static-nat inet` for stateless NAT64, where the
                # embedded IPv4 address is derived from the matched IPv6
                # destination rather than configured as a literal address.
                translated_dst = "embedded-ipv4" if translation == "inet" else translation
            original_port = str(data.get("destination-port", ""))
            nat_rules.append(NATRule(device=device_id, name=f"{rule_set}/{rule}", type=kind,
                original_src=str(data.get("source-address", "any")), original_dst=str(data.get("destination-address", "any")),
                translated_src=translated_src, translated_dst=translated_dst, protocol=str(data.get("protocol", "any")),
                original_port=int(original_port) if original_port.isdigit() else None, translated_port=translated_port,
                sequence=sequence,
                source_ports=[str(data["source-port"])] if data.get("source-port") else [],
                destination_ports=[original_port] if original_port else [],
                trace=self.trace(int(data.get("line", 0)), str(data.get("raw", ""))) if data.get("line") else None))
        return CanonicalConfig(device=device, interfaces=list(ifaces.values()), vlans=vlans, segments=segments,
            zones=list(zones.values()), routes=routes, policies=policies, nat=nat_rules,
            address_objects=addresses, service_objects=services, warnings=warnings, unsupported=unsupported)


@ParserRegistry.register
class JunosParser(JunosBaseParser): pass


@ParserRegistry.register
class JuniperSRXParser(JunosBaseParser):
    parser_id = "juniper_srx"; network_os = "srx"
    capabilities = ParserCapabilities(parser_id="juniper_srx", label="Juniper SRX", interfaces=True, vlans=True, zones=True, routes=True, acl=True, firewall_policy=True, nat=True, address_objects=True, service_objects=True, ipv6=True)

    @classmethod
    def detect(cls, config: str) -> float:
        base = super().detect(config)
        if "set security policies" in config and "set security zones" in config: base += 0.2
        elif "set security zones" in config and "set security nat" in config: base += 0.2
        if is_hierarchical_junos(config) and re.search(r"(?m)^\s*(?:policies|zones)\s*\{", config): base += 0.25
        return min(base, 1.0)
