from __future__ import annotations

import re

from ..models import CanonicalConfig, Device, Interface, NATRule, ParserCapabilities, ParserWarning, Policy, Route, Segment, VLAN
from .base import BaseConfigParser
from .common import hostname_from, interface_networks, slug
from .registry import ParserRegistry


@ParserRegistry.register
class YamahaRTXParser(BaseConfigParser):
    parser_id = "yamaha_rtx"
    capabilities = ParserCapabilities(parser_id="yamaha_rtx", label="Yamaha RTX", interfaces=True, vlans=True, routes=True, acl=True, firewall_policy=True, nat=True, ipv6=True)

    @classmethod
    def detect(cls, config: str) -> float:
        score = 0.0
        score += 0.38 if re.search(r"(?m)^ip (?:lan|vlan)\S* address ", config) else 0
        score += 0.32 if re.search(r"(?m)^(?:ip|ipv6) filter \d+ ", config) else 0
        score += 0.2 if re.search(r"(?m)^(?:ip|ipv6) \S+ secure filter (?:in|out)", config) else 0
        score += 0.1 if re.search(r"(?m)^(?:ip|ipv6) route default gateway", config) else 0
        return min(score, 1.0)

    def parse(self) -> CanonicalConfig:
        hostname = hostname_from(self.config, self.source_file); device_id = slug(hostname)
        device = Device(id=device_id, hostname=hostname, vendor="yamaha", network_os="rtx", source_file=self.source_file)
        ifaces: dict[str, Interface] = {}; vlans: list[VLAN] = []; policies: list[Policy] = []; routes: list[Route] = []; bindings: list[tuple[str, str, list[str]]] = []
        vlan_ifaces: dict[int, str] = {}; nat_types: dict[str, str] = {}; nat_bindings: dict[str, str] = {}; nat_static: list[tuple[int, re.Match[str]]] = []
        unsupported: list[ParserWarning] = []
        for n, raw in enumerate(self.lines, 1):
            line = raw.strip()
            if match := re.match(r"ip (\S+) address (\S+)", line):
                iface = ifaces.setdefault(match.group(1), Interface(device=device_id, name=match.group(1), trace=self.trace(n, raw))); iface.addresses.append(match.group(2))
            elif match := re.match(r"ipv6 (\S+) address (\S+)", line):
                iface = ifaces.setdefault(match.group(1), Interface(device=device_id, name=match.group(1), trace=self.trace(n, raw))); iface.addresses.append(match.group(2))
            elif match := re.match(r"vlan (\S+) 802\.1q vid=(\d+)(?: name=(\S+))?", line):
                vlan_id = int(match.group(2)); vlan_ifaces[vlan_id] = match.group(1)
                vlans.append(VLAN(device=device_id, id=vlan_id, name=match.group(3) or f"VLAN{match.group(2)}", trace=self.trace(n, raw)))
            elif match := re.match(r"(?:ip|ipv6) filter (\d+) (pass|reject|restrict) (\S+) (\S+) (\S+) (\S+) (\S+)", line):
                action = {"pass": "permit", "reject": "reject", "restrict": "restrict"}[match.group(2)]
                policies.append(Policy(id=f"{device_id}:filter:{match.group(1)}", device=device_id, name=f"filter-{match.group(1)}", sequence=int(match.group(1)), src=[match.group(3)], dst=[match.group(4)], protocol=[match.group(5)], src_ports=[match.group(6)], dst_ports=[match.group(7)], action=action, trace=self.trace(n, raw)))
            elif match := re.match(r"(?:ip|ipv6) (\S+) secure filter (in|out) (.+)", line): bindings.append((match.group(1), match.group(2), match.group(3).split()))
            elif match := re.match(r"(ip|ipv6) route (\S+) gateway (\S+)(?: (\S+))?", line):
                default = "::/0" if match.group(1) == "ipv6" else "0.0.0.0/0"
                routes.append(Route(device=device_id, destination=default if match.group(2) == "default" else match.group(2), next_hop=match.group(3), interface=match.group(4), trace=self.trace(n, raw)))
            elif match := re.match(r"nat descriptor type (\S+) (\S+)", line): nat_types[match.group(1)] = match.group(2)
            elif match := re.match(r"ip (\S+) nat descriptor (\S+)", line): nat_bindings[match.group(2)] = match.group(1)
            elif match := re.match(r"nat descriptor masquerade static (\S+) (\S+) (\S+) (tcp|udp) (\d+)(?:-(\d+))?", line): nat_static.append((n, match))
            elif line.startswith(("ip filter ", "ipv6 filter ", "nat descriptor ")):
                unsupported.append(ParserWarning(device=device_id, line=n, config=line,
                    reason="unsupported security statement", parser=self.parser_id))
        segments: list[Segment] = []
        for iface in ifaces.values():
            vlan = next((item for item in vlans if vlan_ifaces.get(item.id) == iface.name), None)
            if vlan:
                iface.vlan_id = vlan.id; vlan.subnets = interface_networks(iface.addresses)
                vlan.gateway = iface.addresses[0].split("/")[0] if iface.addresses else None
            iface.segment_id = f"{device_id}-{slug(iface.name)}"; segments.append(Segment(id=iface.segment_id, name=vlan.name if vlan else iface.name.upper(), type="vlan" if vlan else "interface", device=device_id, vlan_id=vlan.id if vlan else None, networks=interface_networks(iface.addresses)))
        pmap = {str(p.sequence): p for p in policies}
        for iface_name, direction, ids in bindings:
            iface = ifaces.setdefault(iface_name, Interface(device=device_id, name=iface_name))
            target = iface.acl_in if direction == "in" else iface.acl_out; target.extend(ids)
            for pid in ids:
                if pid in pmap:
                    pmap[pid].interface = iface_name; pmap[pid].direction = direction
                    if iface.segment_id and direction == "in": pmap[pid].src_segments = [iface.segment_id]
        nat_rules: list[NATRule] = []
        for descriptor, kind in nat_types.items():
            if kind in ("masquerade", "nat-masquerade"):
                nat_rules.append(NATRule(device=device_id, name=f"descriptor-{descriptor}", type="source",
                    translated_src=f"interface:{nat_bindings.get(descriptor, 'unknown')}"))
        for number, match in nat_static:
            port = int(match.group(5))
            nat_rules.append(NATRule(device=device_id, name=f"descriptor-{match.group(1)}-static-{match.group(2)}",
                type="destination", original_dst=f"interface:{nat_bindings.get(match.group(1), 'unknown')}",
                translated_dst=match.group(3), protocol=match.group(4), original_port=port,
                translated_port=port, trace=self.trace(number, self.lines[number - 1])))
        return CanonicalConfig(device=device, interfaces=list(ifaces.values()), vlans=vlans, segments=segments,
            routes=routes, policies=policies, nat=nat_rules, unsupported=unsupported)
