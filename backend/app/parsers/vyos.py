from __future__ import annotations

import re
from collections import defaultdict

from ..models import AddressObject, CanonicalConfig, Device, Interface, NATRule, ParserCapabilities, ParserWarning, Policy, Route, Segment, ServiceObject, VLAN, Zone
from .base import BaseConfigParser
from .common import interface_networks, slug
from .registry import ParserRegistry


def _unquote(value: str) -> str:
    return value.strip().strip("'").strip('"')


@ParserRegistry.register
class VyOSParser(BaseConfigParser):
    parser_id = "vyos"
    capabilities = ParserCapabilities(parser_id=parser_id, label="VyOS", interfaces=True, vlans=True,
        zones=True, routes=True, acl=True, firewall_policy=True, nat=True, address_objects=True,
        service_objects=True, ipv6=True)

    @classmethod
    def detect(cls, config: str) -> float:
        score = 0.0
        score += .3 if re.search(r"(?m)^set interfaces ethernet \S+ address ", config) else 0
        score += .28 if re.search(r"(?m)^set firewall (?:ipv4 |ipv6 )?(?:name|zone) ", config) else 0
        score += .18 if re.search(r"(?m)^set protocols static route", config) else 0
        score += .14 if re.search(r"(?m)^set nat (?:source|destination) rule", config) else 0
        score += .1 if re.search(r"(?m)^set system host-name", config) else 0
        return min(score, 1.0)

    def parse(self) -> CanonicalConfig:
        host_match = re.search(r"(?m)^set system host-name\s+(.+)$", self.config)
        hostname = _unquote(host_match.group(1)) if host_match else slug(self.source_file.rsplit(".", 1)[0])
        device_id = slug(hostname); device = Device(id=device_id, hostname=hostname, vendor="vyos", network_os="vyos", platform="VyOS Router", source_file=self.source_file)
        device.features["dynamic_routing"] = bool(re.search(r"(?m)^set protocols (?:bgp|ospf|ospfv3|isis|rip)\b", self.config))
        interfaces: dict[str, Interface] = {}; vlan_ids: dict[str, int] = {}; zone_members: dict[str, list[str]] = defaultdict(list)
        zone_policies: dict[str, tuple[str, str]] = {}; firewall_rules: dict[tuple[str, int], dict[str, str]] = defaultdict(dict)
        firewall_lines: dict[tuple[str, int], list[tuple[int, str]]] = defaultdict(list)
        chain_defaults: dict[str, str] = {}; base_chains: set[str] = set(); disabled_rules: set[tuple[str, int]] = set()
        groups: dict[str, list[str]] = defaultdict(list); nat_data: dict[tuple[str, int], dict[str, str]] = defaultdict(dict)
        nat_lines: dict[tuple[str, int], list[tuple[int, str]]] = defaultdict(list); routes: dict[str, Route] = {}
        warnings: list[ParserWarning] = []
        recognized: set[int] = set()
        for number, raw in enumerate(self.lines, 1):
            line = raw.strip()
            if not line or line.startswith("#"): continue
            if line.startswith("set system host-name "): recognized.add(number); continue
            if match := re.match(r"set interfaces ethernet (\S+)(?: vif (\d+))? (address|description|vrf) (.+)", line):
                base, vlan, key, value = match.groups(); name = f"{base}.{vlan}" if vlan else base
                iface = interfaces.setdefault(name, Interface(device=device_id, name=name, trace=self.trace(number, raw)))
                if key == "address": iface.addresses.append(_unquote(value))
                elif key == "description": iface.description = _unquote(value)
                else: iface.vrf = _unquote(value)
                if vlan: iface.vlan_id = int(vlan); vlan_ids[name] = int(vlan)
                recognized.add(number); continue
            if match := re.match(r"set (?:firewall zone|zone-policy zone) (\S+) interface (\S+)", line):
                zone_members[_unquote(match.group(1))].append(_unquote(match.group(2))); recognized.add(number); continue
            if match := re.match(r"set (?:firewall zone|zone-policy zone) (\S+) from (\S+) firewall (?:name|ipv6-name) (\S+)", line):
                zone_policies[_unquote(match.group(3))] = (_unquote(match.group(2)), _unquote(match.group(1))); recognized.add(number); continue
            if match := re.match(r"set firewall (?:ipv4 |ipv6 )?name (\S+) rule (\d+) (action|protocol|source address|destination address|source port|destination port|description|jump-target) (.+)", line):
                key = (_unquote(match.group(1)), int(match.group(2))); firewall_rules[key][match.group(3)] = _unquote(match.group(4)); firewall_lines[key].append((number, raw)); recognized.add(number); continue
            if match := re.match(r"set firewall (?:ipv4 |ipv6 )?(forward|input|output) filter rule (\d+) (action|protocol|source address|destination address|source port|destination port|description|jump-target) (.+)", line):
                name = f"base-{match.group(1)}"; key = (name, int(match.group(2))); base_chains.add(name)
                firewall_rules[key][match.group(3)] = _unquote(match.group(4)); firewall_lines[key].append((number, raw)); recognized.add(number); continue
            if match := re.match(r"set firewall (?:ipv4 |ipv6 )?(?:(forward|input|output) filter|name (\S+)) default-action (accept|drop|reject)", line):
                name = f"base-{match.group(1)}" if match.group(1) else _unquote(match.group(2)); chain_defaults[name] = match.group(3); recognized.add(number); continue
            if match := re.match(r"set firewall (?:ipv4 |ipv6 )?(?:(forward|input|output) filter|name (\S+)) rule (\d+) disable", line):
                name = f"base-{match.group(1)}" if match.group(1) else _unquote(match.group(2)); disabled_rules.add((name, int(match.group(3)))); recognized.add(number); continue
            if match := re.match(r"set firewall group (?:network|address)-group (\S+) (?:network|address) (\S+)", line):
                groups[_unquote(match.group(1))].append(_unquote(match.group(2))); recognized.add(number); continue
            if match := re.match(r"set firewall (?:ipv4 )?name (\S+) rule (\d+) (source|destination) group (?:network|address)-group (\S+)", line):
                key = (_unquote(match.group(1)), int(match.group(2))); firewall_rules[key][f"{match.group(3)} group"] = _unquote(match.group(4)); firewall_lines[key].append((number, raw)); recognized.add(number); continue
            if match := re.match(r"set protocols static route(6)? (\S+) (?:next-hop|interface) (\S+)", line):
                destination, value = _unquote(match.group(2)), _unquote(match.group(3)); route = routes.setdefault(destination, Route(device=device_id, destination=destination, trace=self.trace(number, raw)))
                if "next-hop" in line: route.next_hop = value
                else: route.interface = value
                recognized.add(number); continue
            if match := re.match(r"set protocols static route(?:6)? (\S+) distance (\d+)", line):
                route = routes.setdefault(_unquote(match.group(1)), Route(device=device_id, destination=_unquote(match.group(1)), trace=self.trace(number, raw)))
                route.metric = int(match.group(2)); recognized.add(number); continue
            if match := re.match(r"set vrf name (\S+) protocols static route(?:6)? (\S+) (?:next-hop|interface) (\S+)", line):
                vrf, destination, value = map(_unquote, match.groups()); route = routes.setdefault(f"{vrf}:{destination}",
                    Route(device=device_id, destination=destination, vrf=vrf, trace=self.trace(number, raw)))
                if "next-hop" in line: route.next_hop = value
                else: route.interface = value
                recognized.add(number); continue
            if match := re.match(r"set nat (source|destination) rule (\d+) (source address|destination address|outbound-interface name|inbound-interface name|translation address|translation port|protocol|destination port) (.+)", line):
                key = (match.group(1), int(match.group(2))); nat_data[key][match.group(3)] = _unquote(match.group(4)); nat_lines[key].append((number, raw)); recognized.add(number); continue
            warnings.append(ParserWarning(device=device_id, line=number, config=line, reason="unsupported statement", parser=self.parser_id))

        vlans = [VLAN(device=device_id, id=vlan, name=name.upper(), subnets=interface_networks(interfaces[name].addresses), gateway=interfaces[name].addresses[0].split("/")[0] if interfaces[name].addresses else None, trace=interfaces[name].trace) for name, vlan in vlan_ids.items()]
        zones: list[Zone] = []; segments: list[Segment] = []
        for name, members in zone_members.items():
            segment_id = f"{device_id}-zone-{slug(name)}"; zones.append(Zone(device=device_id, name=name, interfaces=members, segment_id=segment_id))
            networks = [net for member in members if member in interfaces for net in interface_networks(interfaces[member].addresses)]
            segments.append(Segment(id=segment_id, name=name.upper(), type="zone", device=device_id, networks=networks,
                vrf=next((interfaces[member].vrf for member in members if member in interfaces and interfaces[member].vrf), None)))
            for member in members:
                if member in interfaces: interfaces[member].zone = name; interfaces[member].segment_id = segment_id
        for iface in interfaces.values():
            if not iface.segment_id:
                iface.segment_id = f"{device_id}-if-{slug(iface.name)}"; segments.append(Segment(id=iface.segment_id, name=iface.description or iface.name.upper(), type="vlan" if iface.vlan_id else "interface", device=device_id, vlan_id=iface.vlan_id, networks=interface_networks(iface.addresses), vrf=iface.vrf))
        segment_by_zone = {z.name: z.segment_id for z in zones}
        policies: list[Policy] = []
        for (name, sequence), data in firewall_rules.items():
            if (name, sequence) in disabled_rules: continue
            source = groups.get(data.get("source group", ""), [data.get("source address", "any")])
            destination = groups.get(data.get("destination group", ""), [data.get("destination address", "any")])
            src_negate = bool(source and source[0].startswith("!")); dst_negate = bool(destination and destination[0].startswith("!"))
            source = [value.removeprefix("!") for value in source]; destination = [value.removeprefix("!") for value in destination]
            action = {"accept": "permit", "drop": "deny", "reject": "reject", "continue": "continue",
                      "jump": "jump", "return": "return"}.get(data.get("action", ""), "unknown")
            source_zone, destination_zone = zone_policies.get(name, (None, None)); lines = firewall_lines[(name, sequence)]
            base_chain = name.removeprefix("base-") if name in base_chains else None
            default = {"accept": "permit", "drop": "deny", "reject": "reject"}.get(chain_defaults.get(name, ""))
            policies.append(Policy(id=f"{device_id}:{name}:{sequence}", device=device_id, name=name, sequence=sequence,
                src=source, dst=destination, src_segments=[segment_by_zone[source_zone]] if source_zone in segment_by_zone else [],
                dst_segments=[segment_by_zone[destination_zone]] if destination_zone in segment_by_zone else [],
                protocol=[data.get("protocol", "ip")], src_ports=[data.get("source port", "any")], dst_ports=[data.get("destination port", "any")],
                src_negate=src_negate, dst_negate=dst_negate,
                action=action, direction="zone" if source_zone else "forward" if base_chain == "forward" else "unknown",
                from_zone=source_zone, to_zone=destination_zone,
                chain_id=f"zone:{source_zone}:{destination_zone}" if source_zone else f"vyos:{name}",
                default_action=default or ("permit" if name in base_chains else "deny"),
                terminal=action not in {"continue", "return"}, jump_target=data.get("jump-target"),
                entrypoint=bool(source_zone) or base_chain == "forward",
                trace=self.trace(lines[0][0], "\n".join(x[1] for x in lines), lines[-1][0])))
        nat_rules: list[NATRule] = []
        for (kind, sequence), data in nat_data.items():
            lines = nat_lines[(kind, sequence)]; translation = data.get("translation address") or data.get("translation")
            nat_rules.append(NATRule(device=device_id, name=f"{kind}-{sequence}", type=kind,
                original_src=data.get("source address", "any"), original_dst=data.get("destination address", "any"),
                translated_src=translation if kind == "source" else None, translated_dst=translation if kind == "destination" else None,
                protocol=data.get("protocol", "any"), original_port=int(data["destination port"]) if data.get("destination port", "").isdigit() else None,
                translated_port=int(data["translation port"]) if data.get("translation port", "").isdigit() else None,
                trace=self.trace(lines[0][0], "\n".join(x[1] for x in lines), lines[-1][0])))
        address_objects = [AddressObject(device=device_id, name=name, values=values) for name, values in groups.items()]
        return CanonicalConfig(device=device, interfaces=list(interfaces.values()), vlans=vlans, segments=segments, zones=zones,
            routes=list(routes.values()), policies=policies, nat=nat_rules, address_objects=address_objects, warnings=warnings)
