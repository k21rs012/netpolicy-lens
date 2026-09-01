from __future__ import annotations

import ipaddress
import re
from collections import defaultdict

from ..models import CanonicalConfig, Device, Interface, ParserCapabilities, ParserWarning, Policy, Route, Segment, VLAN
from .base import BaseConfigParser
from .common import hostname_from, interface_networks, slug, wildcard_to_network
from .registry import ParserRegistry


def _address(tokens: list[str], pos: int) -> tuple[str, int]:
    if pos >= len(tokens) or tokens[pos] in ("any", "*"):
        return "any", pos + 1
    if tokens[pos] == "host" and pos + 1 < len(tokens):
        value = tokens[pos + 1]
        return f"{value}/128" if ":" in value else f"{value}/32", pos + 2
    value = tokens[pos]
    if "/" in value:
        return value, pos + 1
    if pos + 1 < len(tokens) and re.fullmatch(r"\d+\.\d+\.\d+\.\d+", tokens[pos + 1]):
        try: return wildcard_to_network(value, tokens[pos + 1]), pos + 2
        except ValueError: pass
    return value, pos + 1


def parse_acl_rule(parser: BaseConfigParser, device: str, acl: str, line: str, number: int, previous: int) -> Policy | None:
    tokens = line.split(); pos = 0; sequence = previous + 10
    if tokens and tokens[0].isdigit(): sequence = int(tokens[0]); pos += 1
    if pos >= len(tokens) or tokens[pos] not in ("permit", "deny"): return None
    action = tokens[pos]; pos += 1
    protocol = tokens[pos] if pos < len(tokens) else "ip"; pos += 1
    src, pos = _address(tokens, pos); src_ports = ["any"]
    if pos < len(tokens) and tokens[pos] in ("eq", "range", "gt", "lt", "neq"):
        op = tokens[pos]; pos += 1; values = tokens[pos:pos + (2 if op == "range" else 1)]
        src_ports = [values[0] if op == "eq" else f"{op} {'-'.join(values)}"]; pos += len(values)
    dst, pos = _address(tokens, pos); dst_ports = ["any"]
    if pos < len(tokens) and tokens[pos] in ("eq", "range", "gt", "lt", "neq"):
        op = tokens[pos]; pos += 1; values = tokens[pos:pos + (2 if op == "range" else 1)]
        dst_ports = [values[0] if op == "eq" else f"{op} {'-'.join(values)}"]
    return Policy(id=f"{device}:{acl}:{sequence}", device=device, name=acl, sequence=sequence,
        src=[src], dst=[dst], protocol=[protocol], src_ports=src_ports, dst_ports=dst_ports,
        action=action, trace=parser.trace(number, line))


class CampusSwitchParser(BaseConfigParser):
    vendor = "unknown"
    network_os = "unknown"
    platform = None
    interface_pattern = r"interface\s+(.+)"
    acl_pattern = r"(?:ip|ipv6) access-list\s+(.+)"
    vlan_access_patterns = (r"switchport access vlan\s+(\d+)", r"vlan access\s+(\d+)")
    acl_binding_patterns = (r"ip access-group\s+(\S+)\s+(in|out)", r"apply access-list (?:ip|ipv6)\s+(\S+)\s+(in|out)")

    def parse(self) -> CanonicalConfig:
        hostname = hostname_from(self.config, self.source_file); device_id = slug(hostname)
        device = Device(id=device_id, hostname=hostname, vendor=self.vendor, network_os=self.network_os,
            platform=self.platform, source_file=self.source_file)
        interfaces: list[Interface] = []; vlans: list[VLAN] = []; routes: list[Route] = []
        policies: list[Policy] = []; warnings: list[ParserWarning] = []
        current_if: Interface | None = None; current_vlan: VLAN | None = None; current_acl: str | None = None; acl_seq = 0
        for number, raw in enumerate(self.lines, 1):
            line = raw.strip()
            if not line or line in ("!", "exit") or line.startswith("#"): continue
            if match := re.match(self.interface_pattern, line, re.I):
                current_if = Interface(device=device_id, name=match.group(1), trace=self.trace(number, raw))
                interfaces.append(current_if); current_vlan = None; current_acl = None; continue
            if match := re.match(r"vlan\s+(\d+)$", line, re.I):
                current_vlan = VLAN(device=device_id, id=int(match.group(1)), name=f"VLAN{match.group(1)}", trace=self.trace(number, raw))
                vlans.append(current_vlan); current_if = None; current_acl = None; continue
            if match := re.match(self.acl_pattern, line, re.I):
                current_acl = match.group(1); current_if = None; current_vlan = None; acl_seq = 0; continue
            if not raw.startswith((" ", "\t")):
                current_if = None; current_vlan = None; current_acl = None
            if current_if:
                if match := re.match(r"description\s+(.+)", line): current_if.description = match.group(1).strip('"')
                elif match := re.match(r"(?:ip|ipv6) address\s+(\S+)(?:\s+(\S+))?", line):
                    value = match.group(1)
                    if match.group(2) and "/" not in value:
                        try: value = str(ipaddress.ip_interface(f"{value}/{match.group(2)}"))
                        except ValueError: pass
                    current_if.addresses.append(value)
                else:
                    handled = False
                    for pattern in self.vlan_access_patterns:
                        if match := re.match(pattern, line): current_if.vlan_id = int(match.group(1)); handled = True; break
                    if not handled and (match := re.match(r"(?:switchport trunk allowed vlan|vlan trunk allowed)\s+(.+)", line)):
                        current_if.trunk_vlans = [int(x) for x in re.findall(r"\d+", match.group(1))]; handled = True
                    if not handled:
                        for pattern in self.acl_binding_patterns:
                            if match := re.match(pattern, line):
                                (current_if.acl_in if match.group(2) == "in" else current_if.acl_out).append(match.group(1)); handled = True; break
                    if not handled and line.startswith(("apply access-list", "ip access-group", "ipv6 access-group")):
                        warnings.append(ParserWarning(device=device_id, line=number, config=line, reason="unsupported ACL binding", parser=self.parser_id))
                continue
            if current_vlan and (match := re.match(r"name\s+(.+)", line)):
                current_vlan.name = match.group(1); continue
            if current_acl and re.match(r"(?:\d+\s+)?(?:permit|deny)\s+", line):
                policy = parse_acl_rule(self, device_id, current_acl, line, number, acl_seq)
                if policy: policies.append(policy); acl_seq = policy.sequence
                else: warnings.append(ParserWarning(device=device_id, line=number, config=line, reason="unsupported ACL rule", parser=self.parser_id))
                continue
            if match := re.match(r"ip route\s+(\S+)(?:\s+(\S+))?(?:\s+(\S+))?", line):
                destination, second, third = match.group(1), match.group(2), match.group(3)
                if second and re.fullmatch(r"\d+\.\d+\.\d+\.\d+", second) and "/" not in destination:
                    try: destination = str(ipaddress.ip_network(f"{destination}/{second}", strict=False)); next_hop = third
                    except ValueError: next_hop = second
                else: next_hop = second
                routes.append(Route(device=device_id, destination=destination, next_hop=next_hop, trace=self.trace(number, raw)))

        segments: list[Segment] = []
        for vlan in vlans:
            svi = next((i for i in interfaces if re.fullmatch(rf"vlan\s*{vlan.id}", i.name, re.I)), None)
            if svi:
                svi.vlan_id = vlan.id; vlan.subnets = interface_networks(svi.addresses)
                vlan.gateway = svi.addresses[0].split("/")[0] if svi.addresses else None
            seg_id = f"{device_id}-vlan-{vlan.id}"
            segments.append(Segment(id=seg_id, name=vlan.name, type="vlan", device=device_id, vlan_id=vlan.id, networks=vlan.subnets))
            for iface in interfaces:
                if iface.vlan_id == vlan.id: iface.segment_id = seg_id
        for iface in interfaces:
            if iface.addresses and not iface.segment_id:
                iface.segment_id = f"{device_id}-if-{slug(iface.name)}"
                segments.append(Segment(id=iface.segment_id, name=iface.description or iface.name, type="interface",
                    device=device_id, networks=interface_networks(iface.addresses)))
        bindings = {name: (iface.name, direction, iface.segment_id) for iface in interfaces
            for direction, names in (("in", iface.acl_in), ("out", iface.acl_out)) for name in names}
        for policy in policies:
            if policy.name in bindings:
                policy.interface, policy.direction, segment_id = bindings[policy.name]
                if segment_id and policy.direction == "in": policy.src_segments = [segment_id]
        return CanonicalConfig(device=device, interfaces=interfaces, vlans=vlans, segments=segments,
            routes=routes, policies=policies, warnings=warnings)


@ParserRegistry.register
class AOSCXParser(CampusSwitchParser):
    parser_id = "aruba_aoscx"; vendor = "aruba"; network_os = "aos-cx"; platform = "AOS-CX Switch"
    acl_pattern = r"access-list (?:ip|ipv6)\s+(.+)"
    capabilities = ParserCapabilities(parser_id=parser_id, label="HPE Aruba AOS-CX", interfaces=True,
        vlans=True, routes=True, acl=True, ipv6=True)
    @classmethod
    def detect(cls, config: str) -> float:
        score = 0.0
        score += .38 if re.search(r"(?mi)^(?:!Version )?ArubaOS-CX|^!Version (?:FL|LL)\.", config) else 0
        score += .25 if re.search(r"(?m)^interface \d+/\d+/\d+", config) else 0
        score += .25 if re.search(r"(?m)^\s*apply access-list (?:ip|ipv6) ", config) else 0
        score += .12 if re.search(r"(?m)^\s*vlan (?:access|trunk allowed) ", config) else 0
        return min(score, 1.0)


@ParserRegistry.register
class AristaEOSParser(CampusSwitchParser):
    parser_id = "arista_eos"; vendor = "arista"; network_os = "eos"; platform = "Arista Switch"
    acl_pattern = r"(?:ip|ipv6) access-list(?: standard| extended)?\s+(.+)"
    capabilities = ParserCapabilities(parser_id=parser_id, label="Arista EOS", interfaces=True,
        vlans=True, routes=True, acl=True, ipv6=True)
    @classmethod
    def detect(cls, config: str) -> float:
        score = 0.0
        score += .34 if re.search(r"(?m)^(?:daemon TerminAttr|management api http-commands|service routing protocols model multi-agent)", config) else 0
        score += .24 if re.search(r"(?m)^interface Ethernet\d+", config) else 0
        score += .22 if re.search(r"(?m)^ip access-list \S+", config) else 0
        score += .12 if re.search(r"(?m)^transceiver qsfp default-mode ", config) else 0
        score += .08 if re.search(r"(?m)^hostname \S+", config) else 0
        return min(score, 1.0)


@ParserRegistry.register
class AlliedWarePlusParser(CampusSwitchParser):
    parser_id = "alliedware_plus"; vendor = "allied"; network_os = "alliedware-plus"; platform = "Allied Telesis Switch"
    acl_pattern = r"(?:ip |ipv6 )?access-list(?: hardware)?\s+(.+)"
    capabilities = ParserCapabilities(parser_id=parser_id, label="AlliedWare Plus", interfaces=True,
        vlans=True, routes=True, acl=True, ipv6=True)
    @classmethod
    def detect(cls, config: str) -> float:
        score = 0.0
        score += .4 if re.search(r"(?mi)^!.*AlliedWare Plus|^awplus", config) else 0
        score += .24 if re.search(r"(?m)^interface port\d+\.\d+\.\d+", config) else 0
        score += .2 if re.search(r"(?m)^access-list hardware ", config) else 0
        score += .16 if re.search(r"(?m)^(?:ipv6 )?traffic-filter ", config) else 0
        return min(score, 1.0)

    def parse(self) -> CanonicalConfig:
        # Normalize AlliedWare Plus one-line ACLs and VLAN database entries to
        # the same block form used by the campus parser. The original text and
        # line count are preserved by one-to-one rewrites.
        rewritten: list[str] = []
        active_acl: str | None = None
        for raw in self.lines:
            line = raw.strip()
            if match := re.match(r"vlan (\d+) name (\S+)", line):
                rewritten.extend([f"vlan {match.group(1)}", f" name {match.group(2)}"]); continue
            if match := re.match(r"access-list (\S+) ((?:permit|deny) .+)", line):
                if active_acl != match.group(1): rewritten.append(f"ip access-list {match.group(1)}"); active_acl = match.group(1)
                rewritten.append(f" {match.group(2)}"); continue
            rewritten.append(raw)
        original_config, original_lines = self.config, self.lines
        self.config, self.lines = "\n".join(rewritten), rewritten
        result = super().parse()
        self.config, self.lines = original_config, original_lines
        # AlliedWare Plus uses access-group under an interface, without the
        # leading `ip` keyword.
        current_iface: Interface | None = None
        policy_index: dict[str, int] = defaultdict(int)
        for number, raw in enumerate(original_lines, 1):
            line = raw.strip()
            if match := re.match(r"interface\s+(.+)", line):
                current_iface = next((i for i in result.interfaces if i.name == match.group(1)), None)
                if current_iface: current_iface.trace = self.trace(number, raw)
                continue
            if not raw.startswith((" ", "\t")): current_iface = None
            if match := re.match(r"vlan (\d+) name (\S+)", line):
                vlan = next((v for v in result.vlans if v.id == int(match.group(1))), None)
                if vlan: vlan.trace = self.trace(number, raw)
            if match := re.match(r"access-list (\S+) ((?:permit|deny) .+)", line):
                candidates = [p for p in result.policies if p.name == match.group(1)]
                index = policy_index[match.group(1)]
                if index < len(candidates): candidates[index].trace = self.trace(number, raw)
                policy_index[match.group(1)] += 1
            if match := re.match(r"\s*access-group\s+(\S+)", raw):
                iface = current_iface
                if iface:
                    iface.acl_in.append(match.group(1))
                    for policy in result.policies:
                        if policy.name == match.group(1): policy.interface = iface.name; policy.direction = "in"; policy.src_segments = [iface.segment_id] if iface.segment_id else []
        return result
