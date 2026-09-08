from __future__ import annotations

import re
import shlex
from collections import defaultdict

from ..models import (
    AddressObject, CanonicalConfig, Confidence, Device, Interface, NATRule,
    ParserCapabilities, ParserWarning, Policy, Route, Segment, ServiceObject,
    VLAN, Zone,
)
from .base import BaseConfigParser
from .common import interface_networks, slug
from .registry import ParserRegistry


Command = tuple[int, str, str, bool]
RuleKey = tuple[str, str, int]
ChainKey = tuple[str, str]


def _unquote(value: str) -> str:
    return value.strip().strip("'").strip('"')


def _tokens(value: str) -> list[str]:
    try:
        return shlex.split(value, posix=True)
    except ValueError:
        return value.split()


def _configuration_commands(config: str) -> list[Command]:
    """Normalize native brace output and ``show configuration commands``."""
    commands: list[Command] = []
    stack: list[list[str]] = []
    for number, raw in enumerate(config.splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith(("#", "//")):
            continue
        if line.startswith("set "):
            commands.append((number, line, raw, False))
            continue
        while line.startswith("}"):
            if stack:
                stack.pop()
            line = line[1:].strip()
        if not line:
            continue
        if line.endswith("{"):
            segment = _tokens(line[:-1].strip())
            if segment:
                stack.append(segment)
                path = [token for part in stack for token in part]
                commands.append((number, "set " + " ".join(path), raw, True))
            continue
        path = [token for part in stack for token in part]
        commands.append((number, "set " + " ".join(path + _tokens(line)), raw, False))
    return commands


def _rule_path(line: str) -> tuple[str, str, int, str, bool] | None:
    custom = re.match(
        r"set firewall (?:(ipv4|ipv6) )?(name|ipv6-name) (\S+) rule (\d+)(?: (.+))?$", line
    )
    if custom:
        family = custom.group(1) or ("ipv6" if custom.group(2) == "ipv6-name" else "ipv4")
        return family, _unquote(custom.group(3)), int(custom.group(4)), custom.group(5) or "", False
    base = re.match(
        r"set firewall (?:(ipv4|ipv6) )?(forward|input|output) filter rule (\d+)(?: (.+))?$", line
    )
    if base:
        return base.group(1) or "ipv4", f"base-{base.group(2)}", int(base.group(3)), base.group(4) or "", True
    return None


def _chain_path(line: str, setting: str) -> tuple[str, str, str] | None:
    custom = re.match(
        rf"set firewall (?:(ipv4|ipv6) )?(name|ipv6-name) (\S+) {setting} (.+)$", line
    )
    if custom:
        family = custom.group(1) or ("ipv6" if custom.group(2) == "ipv6-name" else "ipv4")
        return family, _unquote(custom.group(3)), _unquote(custom.group(4))
    base = re.match(
        rf"set firewall (?:(ipv4|ipv6) )?(forward|input|output) filter {setting} (.+)$", line
    )
    if base:
        return base.group(1) or "ipv4", f"base-{base.group(2)}", _unquote(base.group(3))
    return None


@ParserRegistry.register
class VyOSParser(BaseConfigParser):
    parser_id = "vyos"
    capabilities = ParserCapabilities(
        parser_id=parser_id, label="VyOS", interfaces=True, vlans=True,
        zones=True, routes=True, acl=True, firewall_policy=True, nat=True,
        address_objects=True, service_objects=True, ipv6=True,
    )

    @classmethod
    def detect(cls, config: str) -> float:
        normalized = "\n".join(command for _, command, _, _ in _configuration_commands(config))
        score = 0.0
        score += 0.3 if re.search(r"(?m)^set interfaces ethernet \S+ address ", normalized) else 0
        score += 0.28 if re.search(r"(?m)^set firewall (?:ipv4 |ipv6 )?(?:name|ipv6-name|zone|forward|input|output) ", normalized) else 0
        score += 0.18 if re.search(r"(?m)^set protocols static route", normalized) else 0
        score += 0.14 if re.search(r"(?m)^set nat (?:source|destination) rule", normalized) else 0
        score += 0.1 if re.search(r"(?m)^set system host-name", normalized) else 0
        return min(score, 1.0)

    def parse(self) -> CanonicalConfig:
        commands = _configuration_commands(self.config)
        normalized = "\n".join(command for _, command, _, _ in commands)
        host_match = re.search(r"(?m)^set system host-name\s+(.+)$", normalized)
        hostname = _unquote(host_match.group(1)) if host_match else slug(self.source_file.rsplit(".", 1)[0])
        device_id = slug(hostname)
        device = Device(id=device_id, hostname=hostname, vendor="vyos", network_os="vyos",
                        platform="VyOS Router", source_file=self.source_file)
        device.features["dynamic_routing"] = bool(
            re.search(r"(?m)^set protocols (?:bgp|ospf|ospfv3|isis|rip)\b", normalized)
        )

        interfaces: dict[str, Interface] = {}
        vlan_ids: dict[str, int] = {}
        zone_members: dict[str, list[str]] = defaultdict(list)
        local_zones: set[str] = set()
        zone_defaults: dict[str, str] = {}
        zone_policies: dict[ChainKey, tuple[str, str]] = {}
        rules: dict[RuleKey, dict[str, str]] = defaultdict(dict)
        rule_lines: dict[RuleKey, list[tuple[int, str]]] = defaultdict(list)
        chain_defaults: dict[ChainKey, str] = {}
        default_jump_targets: dict[ChainKey, str] = {}
        base_chains: set[ChainKey] = set()
        disabled_rules: set[RuleKey] = set()
        partial_rules: dict[RuleKey, list[str]] = defaultdict(list)
        address_groups: dict[str, list[str]] = defaultdict(list)
        port_groups: dict[str, list[str]] = defaultdict(list)
        interface_groups: dict[str, list[str]] = defaultdict(list)
        nat_data: dict[tuple[str, int], dict[str, str]] = defaultdict(dict)
        nat_lines: dict[tuple[str, int], list[tuple[int, str]]] = defaultdict(list)
        routes: dict[tuple[str | None, str], Route] = {}
        warnings: list[ParserWarning] = []

        def route_for(destination: str, vrf: str | None, number: int, raw: str) -> Route:
            return routes.setdefault(
                (vrf, destination),
                Route(device=device_id, destination=destination, vrf=vrf,
                      trace=self.trace(number, raw)),
            )

        for number, line, raw, structural in commands:
            if line.startswith("set system host-name "):
                continue
            if match := re.match(
                r"set interfaces (?:ethernet|bonding|bridge|dummy|wireguard|tunnel) (\S+)(?: vif (\d+))? (address|description|vrf) (.+)", line
            ):
                base, vlan, field, value = match.groups()
                name = f"{base}.{vlan}" if vlan else base
                interface = interfaces.setdefault(
                    name, Interface(device=device_id, name=name, trace=self.trace(number, raw))
                )
                value = _unquote(value)
                if field == "address":
                    interface.addresses.append(value)
                elif field == "description":
                    interface.description = value
                else:
                    interface.vrf = value
                if vlan:
                    interface.vlan_id = int(vlan)
                    vlan_ids[name] = int(vlan)
                continue

            if match := re.match(r"set (?:firewall zone|zone-policy zone) (\S+) interface (\S+)", line):
                zone_members[_unquote(match.group(1))].append(_unquote(match.group(2)))
                continue
            if match := re.match(r"set (?:firewall zone|zone-policy zone) (\S+) local-zone$", line):
                local_zones.add(_unquote(match.group(1)))
                continue
            if match := re.match(r"set (?:firewall zone|zone-policy zone) (\S+) default-action (drop|reject)", line):
                zone_defaults[_unquote(match.group(1))] = match.group(2)
                continue
            if match := re.match(
                r"set (?:firewall zone|zone-policy zone) (\S+) from (\S+) firewall (name|ipv6-name) (\S+)", line
            ):
                family = "ipv6" if match.group(3) == "ipv6-name" else "ipv4"
                zone_policies[(family, _unquote(match.group(4)))] = (
                    _unquote(match.group(2)), _unquote(match.group(1))
                )
                continue

            if match := re.match(
                r"set firewall group (address-group|network-group|ipv6-address-group|ipv6-network-group|port-group|interface-group) (\S+) (address|network|port|interface) (.+)", line
            ):
                kind, name, _, value = match.groups()
                target = (port_groups if kind == "port-group"
                          else interface_groups if kind == "interface-group"
                          else address_groups)
                target[_unquote(name)].append(_unquote(value))
                continue

            if chain := _chain_path(line, "default-action"):
                family, name, action = chain
                chain_defaults[(family, name)] = action
                if name.startswith("base-"):
                    base_chains.add((family, name))
                continue
            if chain := _chain_path(line, "default-jump-target"):
                family, name, target = chain
                default_jump_targets[(family, name)] = target
                if name.startswith("base-"):
                    base_chains.add((family, name))
                continue

            if path := _rule_path(line):
                family, name, sequence, rest, is_base = path
                key = family, name, sequence
                if is_base:
                    base_chains.add((family, name))
                if not rest:
                    continue
                rule_lines[key].append((number, raw))
                if direct := re.match(
                    r"(action|protocol|source address|destination address|source port|destination port|description|jump-target|inbound-interface name|outbound-interface name) (.+)", rest
                ):
                    rules[key][direct.group(1)] = _unquote(direct.group(2))
                    if direct.group(1) == "action" and _unquote(direct.group(2)) not in {
                        "accept", "drop", "reject", "continue", "jump", "return"
                    }:
                        partial_rules[key].append(rest)
                        warnings.append(ParserWarning(
                            device=device_id, line=number, config=line,
                            reason="unsupported firewall action; rule marked PARTIAL",
                            parser=self.parser_id,
                        ))
                    continue
                if rest == "disable":
                    disabled_rules.add(key)
                    continue
                if match := re.match(r"(source|destination) group (\S+) (\S+)", rest):
                    side, kind, group = match.groups()
                    suffix = "port group" if kind == "port-group" else "address group"
                    rules[key][f"{side} {suffix}"] = _unquote(group)
                    if _unquote(group).startswith("!") and kind == "port-group":
                        partial_rules[key].append(rest)
                    continue
                if match := re.match(r"(inbound|outbound)-interface group (\S+)", rest):
                    rules[key][f"{match.group(1)}-interface group"] = _unquote(match.group(2))
                    if _unquote(match.group(2)).startswith("!"):
                        partial_rules[key].append(rest)
                    continue
                if match := re.match(r"state (new|established|related|invalid|untracked)(?: enable)?$", rest):
                    current = rules[key].get("states", "")
                    rules[key]["states"] = " ".join(filter(None, (current, match.group(1))))
                    continue
                partial_rules[key].append(rest)
                warnings.append(ParserWarning(
                    device=device_id, line=number, config=line,
                    reason=f"unsupported firewall match ({rest.split(' ', 1)[0]}); rule marked PARTIAL",
                    parser=self.parser_id,
                ))
                continue

            if match := re.match(
                r"set protocols static route(6)? (\S+) (next-hop|interface) (\S+)(?: distance (\d+))?", line
            ):
                _, destination, kind, value, distance = match.groups()
                route = route_for(_unquote(destination), None, number, raw)
                value = _unquote(value)
                if kind == "next-hop":
                    if value not in route.next_hops:
                        route.next_hops.append(value)
                    route.next_hop = route.next_hop or value
                else:
                    route.interface = value
                if distance:
                    route.metric = int(distance)
                continue
            if match := re.match(r"set protocols static route(?:6)? (\S+) (blackhole|reject|unreachable)", line):
                route_for(_unquote(match.group(1)), None, number, raw).route_type = match.group(2)
                continue
            if match := re.match(r"set protocols static route(?:6)? (\S+) distance (\d+)", line):
                route_for(_unquote(match.group(1)), None, number, raw).metric = int(match.group(2))
                continue
            if match := re.match(
                r"set vrf name (\S+) protocols static route(?:6)? (\S+) (next-hop|interface) (\S+)(?: distance (\d+))?", line
            ):
                vrf, destination, kind, value, distance = match.groups()
                route = route_for(_unquote(destination), _unquote(vrf), number, raw)
                value = _unquote(value)
                if kind == "next-hop":
                    if value not in route.next_hops:
                        route.next_hops.append(value)
                    route.next_hop = route.next_hop or value
                else:
                    route.interface = value
                if distance:
                    route.metric = int(distance)
                continue
            if match := re.match(
                r"set vrf name (\S+) protocols static route(?:6)? (\S+) (blackhole|reject|unreachable)", line
            ):
                route_for(_unquote(match.group(2)), _unquote(match.group(1)), number, raw).route_type = match.group(3)
                continue

            if match := re.match(r"set nat (source|destination) rule (\d+)(?: (.+))?$", line):
                kind, sequence, rest = match.group(1), int(match.group(2)), match.group(3) or ""
                if not rest:
                    continue
                key = kind, sequence
                nat_lines[key].append((number, raw))
                if rest in {"disable", "exclude"}:
                    nat_data[key][rest] = "true"
                    continue
                if field := re.match(
                    r"(source address|destination address|source port|destination port|outbound-interface name|inbound-interface name|outbound-interface group|inbound-interface group|translation address|translation port|protocol|description) (.+)", rest
                ):
                    nat_data[key][field.group(1)] = _unquote(field.group(2))
                    continue

            if not structural:
                warnings.append(ParserWarning(device=device_id, line=number, config=line,
                                              reason="unsupported statement", parser=self.parser_id))

        vlans = [
            VLAN(device=device_id, id=vlan, name=name.upper(),
                 subnets=interface_networks(interfaces[name].addresses),
                 gateway=interfaces[name].addresses[0].split("/")[0] if interfaces[name].addresses else None,
                 trace=interfaces[name].trace)
            for name, vlan in vlan_ids.items()
        ]
        zones: list[Zone] = []
        segments: list[Segment] = []
        for name in dict.fromkeys([*zone_members, *local_zones]):
            members = zone_members[name]
            segment_id = f"{device_id}-zone-{slug(name)}"
            zones.append(Zone(device=device_id, name=name, interfaces=members, segment_id=segment_id))
            networks = [network for member in members if member in interfaces
                        for network in interface_networks(interfaces[member].addresses)]
            segments.append(Segment(
                id=segment_id, name=name.upper(), type="zone", device=device_id,
                networks=networks,
                vrf=next((interfaces[item].vrf for item in members
                          if item in interfaces and interfaces[item].vrf), None),
            ))
            for member in members:
                if member in interfaces:
                    interfaces[member].zone = name
                    interfaces[member].segment_id = segment_id
        for interface in interfaces.values():
            if not interface.segment_id:
                interface.segment_id = f"{device_id}-if-{slug(interface.name)}"
                segments.append(Segment(
                    id=interface.segment_id, name=interface.description or interface.name.upper(),
                    type="vlan" if interface.vlan_id else "interface", device=device_id,
                    vlan_id=interface.vlan_id, networks=interface_networks(interface.addresses),
                    vrf=interface.vrf,
                ))

        segment_by_zone = {zone.name: zone.segment_id for zone in zones}
        policies: list[Policy] = []
        action_map = {"accept": "permit", "drop": "deny", "reject": "reject",
                      "continue": "continue", "jump": "jump", "return": "return"}
        default_map = {"accept": "permit", "drop": "deny", "reject": "reject",
                       "jump": "jump", "return": "return"}
        for (family, name, sequence), data in rules.items():
            key = family, name, sequence
            if key in disabled_rules:
                continue
            source_group = data.get("source address group", "")
            destination_group = data.get("destination address group", "")
            source = address_groups.get(source_group.lstrip("!"), [data.get("source address", "any")])
            destination = address_groups.get(destination_group.lstrip("!"), [data.get("destination address", "any")])
            src_negate = source_group.startswith("!") or bool(source and source[0].startswith("!"))
            dst_negate = destination_group.startswith("!") or bool(destination and destination[0].startswith("!"))
            source = [value.removeprefix("!") for value in source]
            destination = [value.removeprefix("!") for value in destination]
            source_ports = port_groups.get(data.get("source port group", "").lstrip("!"), [data.get("source port", "any")])
            destination_ports = port_groups.get(data.get("destination port group", "").lstrip("!"), [data.get("destination port", "any")])
            source_zone, destination_zone = zone_policies.get((family, name), (None, None))
            base_chain = name.removeprefix("base-") if (family, name) in base_chains else None
            direction = ({"input": "in", "output": "out"}.get(base_chain, base_chain)
                         if base_chain else "unknown")
            lines = rule_lines[key]
            unsupported = partial_rules.get(key, [])
            default_action = default_map.get(chain_defaults.get((family, name), ""))
            policies.append(Policy(
                id=f"{device_id}:{family}:{name}:{sequence}", device=device_id,
                name=name, sequence=sequence, src=source, dst=destination,
                src_segments=[segment_by_zone[source_zone]] if source_zone in segment_by_zone else [],
                dst_segments=[segment_by_zone[destination_zone]] if destination_zone in segment_by_zone else [],
                protocol=[data.get("protocol", "ip")], src_ports=source_ports,
                dst_ports=destination_ports, src_negate=src_negate, dst_negate=dst_negate,
                action=action_map.get(data.get("action", ""), "unknown"),
                direction="zone" if source_zone else direction,
                in_interfaces=(interface_groups.get(data.get("inbound-interface group", ""), [])
                               or ([data["inbound-interface name"]] if data.get("inbound-interface name") else [])),
                out_interfaces=(interface_groups.get(data.get("outbound-interface group", ""), [])
                                or ([data["outbound-interface name"]] if data.get("outbound-interface name") else [])),
                from_zone=source_zone, to_zone=destination_zone,
                confidence=Confidence.PARTIAL if unsupported else Confidence.EXACT,
                chain_id=(f"zone:{family}:{source_zone}:{destination_zone}"
                          if source_zone else f"vyos:{family}:{name}"),
                default_action=default_action or ("permit" if base_chain else "deny"),
                default_jump_target=default_jump_targets.get((family, name)),
                terminal=data.get("action") not in {"continue", "return"},
                jump_target=data.get("jump-target"), states=data.get("states", "").split(),
                ip_version=6 if family == "ipv6" else 4,
                unsupported_matches=unsupported,
                entrypoint=bool(source_zone) or base_chain == "forward",
                trace=self.trace(lines[0][0], "\n".join(item[1] for item in lines), lines[-1][0]),
            ))

        for (family, name), configured_default in chain_defaults.items():
            source_zone, destination_zone = zone_policies.get((family, name), (None, None))
            base_chain = name.removeprefix("base-") if (family, name) in base_chains else None
            chain_id = (f"zone:{family}:{source_zone}:{destination_zone}"
                        if source_zone else f"vyos:{family}:{name}")
            if any(policy.chain_id == chain_id for policy in policies):
                continue
            action = default_map.get(configured_default, "unknown")
            direction = ({"input": "in", "output": "out"}.get(base_chain, base_chain)
                         if base_chain else "unknown")
            policies.append(Policy(
                id=f"{device_id}:{family}:{name}:default", device=device_id,
                name=name, sequence=999999,
                src_segments=[segment_by_zone[source_zone]] if source_zone in segment_by_zone else [],
                dst_segments=[segment_by_zone[destination_zone]] if destination_zone in segment_by_zone else [],
                action="continue",
                direction="zone" if source_zone else direction,
                from_zone=source_zone, to_zone=destination_zone,
                chain_id=chain_id, default_action=action, terminal=False,
                default_jump_target=default_jump_targets.get((family, name)),
                ip_version=6 if family == "ipv6" else 4,
                entrypoint=bool(source_zone) or base_chain == "forward",
            ))

        configured_pairs = set(zone_policies.values())
        for destination_zone, default in zone_defaults.items():
            for source_zone in segment_by_zone:
                if source_zone == destination_zone or (source_zone, destination_zone) in configured_pairs:
                    continue
                for family, version in (("ipv4", 4), ("ipv6", 6)):
                    policies.append(Policy(
                        id=f"{device_id}:zone-default:{family}:{source_zone}:{destination_zone}",
                        device=device_id, name=f"zone-default-{destination_zone}", sequence=999999,
                        src_segments=[segment_by_zone[source_zone]],
                        dst_segments=[segment_by_zone[destination_zone]], action=action_map[default],
                        direction="zone", from_zone=source_zone, to_zone=destination_zone,
                        chain_id=f"zone:{family}:{source_zone}:{destination_zone}",
                        default_action=default_map[default], ip_version=version,
                    ))

        nat_rules: list[NATRule] = []
        for (kind, sequence), data in nat_data.items():
            lines = nat_lines[(kind, sequence)]
            translation = data.get("translation address")
            source_port = data.get("source port", "")
            destination_port = data.get("destination port", "")
            inbound = data.get("inbound-interface name")
            outbound = data.get("outbound-interface name")
            inbound_group = data.get("inbound-interface group", "")
            outbound_group = data.get("outbound-interface group", "")
            address_hint = " ".join(filter(None, (data.get("source address"), data.get("destination address"))))
            nat_rules.append(NATRule(
                device=device_id, name=f"{kind}-{sequence}",
                type="exclude" if data.get("exclude") else kind,
                original_src=data.get("source address", "any"),
                original_dst=data.get("destination address", "any"),
                translated_src=translation if kind == "source" else None,
                translated_dst=translation if kind == "destination" else None,
                protocol=data.get("protocol", "any"),
                original_port=int(destination_port) if destination_port.isdigit() else None,
                translated_port=int(data["translation port"]) if data.get("translation port", "").isdigit() else None,
                sequence=sequence, source_ports=[source_port] if source_port else [],
                destination_ports=[destination_port] if destination_port else [],
                in_interfaces=interface_groups.get(inbound_group, []) or ([inbound] if inbound else []),
                out_interfaces=interface_groups.get(outbound_group, []) or ([outbound] if outbound else []),
                disabled=bool(data.get("disable")), ip_version=6 if ":" in address_hint else 4,
                trace=self.trace(lines[0][0], "\n".join(item[1] for item in lines), lines[-1][0]),
            ))

        address_objects = [AddressObject(device=device_id, name=name, values=values)
                           for name, values in address_groups.items()]
        service_objects = [ServiceObject(device=device_id, name=name, protocol="tcp_udp", ports=values)
                           for name, values in port_groups.items()]
        return CanonicalConfig(
            device=device, interfaces=list(interfaces.values()), vlans=vlans,
            segments=segments, zones=zones, routes=list(routes.values()),
            policies=policies, nat=nat_rules, address_objects=address_objects,
            service_objects=service_objects, warnings=warnings,
        )
