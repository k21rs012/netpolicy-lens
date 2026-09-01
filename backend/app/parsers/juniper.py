from __future__ import annotations

import re
from collections import defaultdict

from ..models import AddressObject, CanonicalConfig, Device, Interface, ParserCapabilities, Policy, Segment, ServiceObject, Zone
from .base import BaseConfigParser
from .common import hostname_from, interface_networks, slug
from .registry import ParserRegistry


APPS = {"junos-http": ("tcp", "80"), "junos-https": ("tcp", "443"), "junos-ssh": ("tcp", "22"),
        "junos-dns-udp": ("udp", "53"), "junos-dns-tcp": ("tcp", "53"), "junos-icmp-all": ("icmp", "any")}


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
        return min(score, 1.0)

    def parse(self) -> CanonicalConfig:
        hostname = hostname_from(self.config, self.source_file); device_id = slug(hostname)
        device = Device(id=device_id, hostname=hostname, vendor="juniper", network_os=self.network_os, source_file=self.source_file)
        ifaces: dict[str, Interface] = {}; zones: dict[str, Zone] = {}; addresses: list[AddressObject] = []
        policy_data: dict[tuple[str, str, str], dict] = defaultdict(lambda: {"src": [], "dst": [], "apps": [], "action": "unknown", "line": 0, "raw": ""})
        for n, raw in enumerate(self.lines, 1):
            line = raw.strip()
            if match := re.match(r"set interfaces (\S+) unit (\S+) family (inet6?|ethernet-switching) address (\S+)", line):
                name = f"{match.group(1)}.{match.group(2)}"; iface = ifaces.setdefault(name, Interface(device=device_id, name=name, trace=self.trace(n, raw))); iface.addresses.append(match.group(4))
            elif match := re.match(r"set interfaces (\S+) description \"?(.+?)\"?$", line):
                iface = ifaces.setdefault(match.group(1), Interface(device=device_id, name=match.group(1), trace=self.trace(n, raw))); iface.description = match.group(2)
            elif match := re.match(r"set security zones security-zone (\S+) interfaces (\S+)", line):
                zone = zones.setdefault(match.group(1), Zone(device=device_id, name=match.group(1), segment_id=f"{device_id}-zone-{slug(match.group(1))}")); zone.interfaces.append(match.group(2))
            elif match := re.match(r"set security zones security-zone (\S+) address-book address (\S+) (\S+)", line):
                addresses.append(AddressObject(device=device_id, name=match.group(2), values=[match.group(3)]))
            elif match := re.match(r"set security policies from-zone (\S+) to-zone (\S+) policy (\S+) match (source-address|destination-address|application) (.+)", line):
                key = match.group(1), match.group(2), match.group(3); data = policy_data[key]; data[{"source-address": "src", "destination-address": "dst", "application": "apps"}[match.group(4)]].extend(match.group(5).strip("[]").split()); data["line"] = n; data["raw"] = raw
            elif match := re.match(r"set security policies from-zone (\S+) to-zone (\S+) policy (\S+) then (permit|deny|reject)", line):
                key = match.group(1), match.group(2), match.group(3); policy_data[key]["action"] = match.group(4); policy_data[key]["line"] = n; policy_data[key]["raw"] = raw
        segments = [Segment(id=z.segment_id, name=z.name.upper(), type="zone", device=device_id,
                            networks=[net for name in z.interfaces if name in ifaces for net in interface_networks(ifaces[name].addresses)]) for z in zones.values()]
        for z in zones.values():
            for name in z.interfaces:
                if name in ifaces: ifaces[name].zone = z.name; ifaces[name].segment_id = z.segment_id
        policies: list[Policy] = []
        for seq, ((from_zone, to_zone, name), data) in enumerate(policy_data.items(), 1):
            protocols, ports = [], []
            for app in data["apps"] or ["any"]:
                proto, port = APPS.get(app, ("any", "any")); protocols.append(proto); ports.append(port)
            policies.append(Policy(id=f"{device_id}:{from_zone}:{to_zone}:{name}", device=device_id, name=name, sequence=seq,
                src=data["src"] or ["any"], dst=data["dst"] or ["any"], src_segments=[zones[from_zone].segment_id] if from_zone in zones else [],
                dst_segments=[zones[to_zone].segment_id] if to_zone in zones else [], protocol=list(dict.fromkeys(protocols)), dst_ports=list(dict.fromkeys(ports)),
                action=data["action"], direction="zone", from_zone=from_zone, to_zone=to_zone, trace=self.trace(data["line"], data["raw"])))
        services = [ServiceObject(device=device_id, name=k, protocol=v[0], ports=[v[1]]) for k, v in APPS.items()]
        return CanonicalConfig(device=device, interfaces=list(ifaces.values()), segments=segments, zones=list(zones.values()), policies=policies, address_objects=addresses, service_objects=services)


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
        return min(base, 1.0)

