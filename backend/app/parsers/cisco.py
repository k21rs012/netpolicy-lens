from __future__ import annotations

import ipaddress
import re

from ..models import CanonicalConfig, Device, Interface, NATRule, ParserCapabilities, ParserWarning, Policy, Route, Segment, VLAN
from .base import BaseConfigParser
from .common import hostname_from, interface_networks, mask_to_prefix, slug, wildcard_to_network
from .registry import ParserRegistry


def _acl_address(tokens: list[str], pos: int) -> tuple[str, int]:
    if pos >= len(tokens) or tokens[pos] == "any":
        return "any", pos + 1
    if tokens[pos] == "host" and pos + 1 < len(tokens):
        value = tokens[pos + 1]
        return f"{value}/128" if ":" in value else f"{value}/32", pos + 2
    if pos + 1 < len(tokens) and re.fullmatch(r"\d+\.\d+\.\d+\.\d+", tokens[pos + 1]):
        try:
            return wildcard_to_network(tokens[pos], tokens[pos + 1]), pos + 2
        except ValueError:
            pass
    return tokens[pos], pos + 1


class CiscoBaseParser(BaseConfigParser):
    capabilities = ParserCapabilities(
        parser_id="cisco_ios", label="Cisco IOS", interfaces=True, vlans=True, routes=True,
        acl=True, nat=True, ipv6=True,
    )
    network_os = "ios"

    @classmethod
    def detect(cls, config: str) -> float:
        score = 0.0
        score += 0.32 if re.search(r"(?m)^interface (?:Gigabit|Fast|TenGigabit|Vlan|Loopback)", config) else 0
        score += 0.28 if re.search(r"(?m)^(?:ip access-list (?:standard|extended)|ipv6 access-list) ", config) else 0
        score += 0.2 if re.search(r"(?m)^version \d+(?:\.\d+)*\s*$", config) else 0
        score += 0.1 if re.search(r"(?m)^vlan \d+", config) else 0
        score += 0.1 if re.search(r"(?m)^hostname \S+", config) else 0
        return min(score, 1.0)

    def parse(self) -> CanonicalConfig:
        hostname = hostname_from(self.config, self.source_file)
        device = Device(id=slug(hostname), hostname=hostname, vendor="cisco", network_os=self.network_os,
                        platform=None, source_file=self.source_file)
        interfaces: list[Interface] = []
        vlans: list[VLAN] = []
        routes: list[Route] = []
        nat_rules: list[NATRule] = []
        policies: list[Policy] = []
        warnings: list[ParserWarning] = []
        unsupported: list[ParserWarning] = []
        current_if: Interface | None = None
        current_vlan: VLAN | None = None
        current_acl: str | None = None
        acl_seq = 0
        for number, raw in enumerate(self.lines, 1):
            line = raw.strip()
            if not line or line.startswith("!"):
                continue
            if match := re.match(r"interface\s+(.+)", line):
                current_if = Interface(device=device.id, name=match.group(1), trace=self.trace(number, raw))
                interfaces.append(current_if); current_vlan = None; current_acl = None
                continue
            if match := re.match(r"vlan\s+(\d+)$", line):
                current_vlan = VLAN(device=device.id, id=int(match.group(1)), name=f"VLAN{match.group(1)}", trace=self.trace(number, raw))
                vlans.append(current_vlan); current_if = None; current_acl = None
                continue
            if match := re.match(r"(?:ip access-list\s+(?:standard|extended)|ipv6 access-list)\s+(.+)", line):
                current_acl = match.group(1); current_if = None; current_vlan = None; acl_seq = 0
                continue
            if not raw.startswith((" ", "\t")):
                current_if = None; current_vlan = None; current_acl = None
            if current_if:
                if match := re.match(r"description\s+(.+)", line): current_if.description = match.group(1)
                elif match := re.match(r"ip address\s+(\S+)(?:\s+(\S+))?", line):
                    try:
                        address = match.group(1) if "/" in match.group(1) else f"{match.group(1)}/{mask_to_prefix(match.group(2) or '')}"
                        current_if.addresses.append(address)
                    except ValueError: warnings.append(ParserWarning(device=device.id, line=number, config=line, reason="invalid IPv4 address", parser=self.parser_id))
                elif match := re.match(r"ipv6 address\s+(\S+)", line): current_if.addresses.append(match.group(1))
                elif match := re.match(r"switchport access vlan\s+(\d+)", line): current_if.vlan_id = int(match.group(1))
                elif match := re.match(r"switchport trunk allowed vlan\s+(.+)", line):
                    current_if.trunk_vlans = [int(x) for x in re.findall(r"\d+", match.group(1))]
                elif match := re.match(r"ip access-group\s+(\S+)\s+(in|out)", line):
                    (current_if.acl_in if match.group(2) == "in" else current_if.acl_out).append(match.group(1))
                elif match := re.match(r"ipv6 traffic-filter\s+(\S+)\s+(in|out)", line):
                    (current_if.acl_in if match.group(2) == "in" else current_if.acl_out).append(match.group(1))
                continue
            if current_vlan and (match := re.match(r"name\s+(.+)", line)):
                current_vlan.name = match.group(1); continue
            if current_acl and re.match(r"(?:\d+\s+)?(?:permit|deny)\s+", line):
                parsed = self._parse_acl_rule(device.id, current_acl, line, number, acl_seq)
                if parsed: policies.append(parsed); acl_seq = parsed.sequence
                else: unsupported.append(ParserWarning(device=device.id, line=number, config=line, reason="unsupported ACL statement", parser=self.parser_id))
                continue
            if match := re.match(r"access-list\s+(\S+)\s+(.+)", line):
                parsed = self._parse_acl_rule(device.id, match.group(1), match.group(2), number, len(policies))
                if parsed: policies.append(parsed)
                else: unsupported.append(ParserWarning(device=device.id, line=number, config=line, reason="unsupported ACL statement", parser=self.parser_id))
                continue
            if match := re.match(r"ip route\s+(\S+)\s+(\S+)\s+(\S+)(?:\s+(\S+))?", line):
                try: dest = str(ipaddress.ip_network(f"{match.group(1)}/{match.group(2)}", strict=False))
                except ValueError: dest = match.group(1)
                routes.append(Route(device=device.id, destination=dest, next_hop=match.group(3), trace=self.trace(number, raw)))
                continue
            if match := re.match(r"ip nat inside source static (tcp|udp) (\S+) (\d+) (\S+) (\d+)", line):
                nat_rules.append(NATRule(device=device.id, name=f"static-{number}", type="source",
                    original_src=match.group(2), translated_src=match.group(4), protocol=match.group(1),
                    original_port=int(match.group(3)), translated_port=int(match.group(5)), trace=self.trace(number, raw)))
                continue
            if match := re.match(r"ip nat inside source static (\S+) (\S+)", line):
                nat_rules.append(NATRule(device=device.id, name=f"static-{number}", type="source",
                    original_src=match.group(1), translated_src=match.group(2), trace=self.trace(number, raw)))
                continue
            if match := re.match(r"ip nat inside source (?:list|route-map) (\S+) interface (\S+) overload", line):
                nat_rules.append(NATRule(device=device.id, name=f"overload-{match.group(1)}", type="source",
                    original_src=match.group(1), translated_src=f"interface:{match.group(2)}", trace=self.trace(number, raw)))
                continue
            if line.startswith(("ip nat ", "ipv6 access-list ", "access-list ")):
                unsupported.append(ParserWarning(device=device.id, line=number, config=line,
                    reason="unsupported security statement", parser=self.parser_id))

        segments: list[Segment] = []
        for vlan in vlans:
            svi = next((i for i in interfaces if i.name.lower() == f"vlan{vlan.id}"), None)
            if svi:
                vlan.subnets = interface_networks(svi.addresses)
                vlan.gateway = svi.addresses[0].split("/")[0] if svi.addresses else None
                svi.vlan_id = vlan.id
            seg_id = f"{device.id}-vlan-{vlan.id}"
            segments.append(Segment(id=seg_id, name=vlan.name, type="vlan", device=device.id, vlan_id=vlan.id, networks=vlan.subnets))
            for iface in interfaces:
                if iface.vlan_id == vlan.id: iface.segment_id = seg_id
        for iface in interfaces:
            if iface.addresses and not iface.segment_id:
                iface.segment_id = f"{device.id}-{slug(iface.name)}"
                segments.append(Segment(id=iface.segment_id, name=iface.description or iface.name, type="interface", device=device.id, networks=interface_networks(iface.addresses)))
        bindings = {acl: (iface.name, direction, iface.segment_id) for iface in interfaces for direction, names in (("in", iface.acl_in), ("out", iface.acl_out)) for acl in names}
        for policy in policies:
            if policy.name in bindings:
                policy.interface, policy.direction, seg = bindings[policy.name]
                if seg: policy.src_segments = [seg] if policy.direction == "in" else policy.src_segments
        return CanonicalConfig(device=device, interfaces=interfaces, vlans=vlans, segments=segments,
            routes=routes, policies=policies, nat=nat_rules, warnings=warnings, unsupported=unsupported)

    def _parse_acl_rule(self, device: str, acl: str, line: str, number: int, previous: int) -> Policy | None:
        tokens = line.split(); pos = 0
        sequence = previous + 10
        if tokens and tokens[0].isdigit(): sequence = int(tokens[0]); pos += 1
        if pos >= len(tokens) or tokens[pos] not in ("permit", "deny"): return None
        action = tokens[pos]; pos += 1
        protocol = tokens[pos] if pos < len(tokens) else "ip"; pos += 1
        src, pos = _acl_address(tokens, pos)
        src_ports = ["any"]
        if pos < len(tokens) and tokens[pos] in ("eq", "range", "gt", "lt", "neq"):
            op = tokens[pos]; pos += 1; src_ports = [f"{op} {'-'.join(tokens[pos:pos + (2 if op == 'range' else 1)])}"]; pos += 2 if op == "range" else 1
        dst, pos = _acl_address(tokens, pos)
        dst_ports = ["any"]
        if pos < len(tokens) and tokens[pos] in ("eq", "range", "gt", "lt", "neq"):
            op = tokens[pos]; pos += 1; values = tokens[pos:pos + (2 if op == "range" else 1)]
            dst_ports = [values[0] if op == "eq" else f"{op} {'-'.join(values)}"]
        return Policy(id=f"{device}:{acl}:{sequence}", device=device, name=acl, sequence=sequence, src=[src], dst=[dst],
                      protocol=[protocol], src_ports=src_ports, dst_ports=dst_ports, action=action, trace=self.trace(number, line))


@ParserRegistry.register
class CiscoIOSParser(CiscoBaseParser):
    parser_id = "cisco_ios"

    @classmethod
    def detect(cls, config: str) -> float:
        score = super().detect(config)
        # IOS-XE also accepts much of the classic IOS syntax. A modern major
        # version is a tie-breaker, not a single-signal detector.
        if re.search(r"(?m)^version (?:1[6-9]|[2-9]\d)(?:\.\d+)*\s*$", config):
            score -= 0.08
        return max(score, 0.0)


@ParserRegistry.register
class CiscoIOSXEParser(CiscoBaseParser):
    parser_id = "cisco_iosxe"
    network_os = "ios-xe"
    capabilities = CiscoBaseParser.capabilities.model_copy(update={"parser_id": "cisco_iosxe", "label": "Cisco IOS-XE"})

    @classmethod
    def detect(cls, config: str) -> float:
        base = super().detect(config)
        if re.search(r"(?m)^version (?:1[5-9]|[2-9]\d)(?:\.\d+)*\s*$", config): base += 0.12
        return min(base, 1.0)


@ParserRegistry.register
class CiscoNXOSParser(CiscoBaseParser):
    parser_id = "cisco_nxos"
    network_os = "nx-os"
    capabilities = CiscoBaseParser.capabilities.model_copy(
        update={"parser_id": "cisco_nxos", "label": "Cisco NX-OS"}
    )

    @classmethod
    def detect(cls, config: str) -> float:
        score = 0.0
        score += 0.55 if re.search(r"(?mi)^(?:!Command: show running-config|version .*NX-?OS|boot nxos)", config) else 0
        score += 0.2 if re.search(r"(?m)^feature (?:interface-vlan|nxapi|vpc|ospf)", config) else 0
        score += 0.15 if re.search(r"(?m)^interface Ethernet\d+/", config) else 0
        score += 0.1 if re.search(r"(?m)^hostname \S+", config) else 0
        return min(score, 1.0)

    def parse(self) -> CanonicalConfig:
        self.config = re.sub(
            r"(?m)^ip access-list (?!standard\s|extended\s)(\S+)",
            r"ip access-list extended \1",
            self.config,
        )
        self.lines = self.config.splitlines()
        result = super().parse()
        existing = {(route.destination, route.next_hop) for route in result.routes}
        for number, raw in enumerate(self.lines, 1):
            line = raw.strip()
            match = re.match(r"ip route\s+(\S+/\d+)\s+(?:\S+\s+)?(\d+\.\d+\.\d+\.\d+)", line)
            if match and (match.group(1), match.group(2)) not in existing:
                result.routes.append(Route(device=result.device.id, destination=match.group(1),
                    next_hop=match.group(2), trace=self.trace(number, raw)))
        return result
