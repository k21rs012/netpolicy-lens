from __future__ import annotations

import re
from collections import defaultdict

from ..models import (
    AddressObject, CanonicalConfig, Confidence, Device, Interface, NATRule,
    ParserCapabilities, Policy, Route, Segment, VLAN,
)
from .base import BaseConfigParser
from .common import hostname_from, interface_networks, key_value_tokens, slug
from .registry import ParserRegistry


@ParserRegistry.register
class MikroTikRouterOSParser(BaseConfigParser):
    parser_id = "mikrotik_routeros"
    capabilities = ParserCapabilities(parser_id=parser_id, label="MikroTik RouterOS",
        interfaces=True, vlans=True, routes=True, acl=True, firewall_policy=True,
        nat=True, address_objects=True, ipv6=True)

    @classmethod
    def detect(cls, config: str) -> float:
        score = 0.45 if re.search(r"(?m)^# (?:RouterOS|software id =)", config) else 0
        score += 0.25 if re.search(r"(?m)^/ip firewall (?:filter|nat)", config) else 0
        score += 0.2 if re.search(r"(?m)^/interface (?:vlan|bridge)", config) else 0
        score += 0.1 if re.search(r"(?m)^/system identity", config) else 0
        return min(score, 1.0)

    def parse(self) -> CanonicalConfig:
        identity = re.search(r"(?m)^/system identity(?:\s*\n)?set .*?name=\"?([^\s\"]+)", self.config)
        hostname = identity.group(1) if identity else hostname_from(self.config, self.source_file)
        device = Device(id=slug(hostname), hostname=hostname, vendor="mikrotik",
            network_os="routeros", source_file=self.source_file)
        device.features["dynamic_routing"] = bool(re.search(r"(?m)^/routing (?:bgp|ospf|rip)\b", self.config))
        interfaces: dict[str, Interface] = {}
        vlans: dict[int, VLAN] = {}
        routes: list[Route] = []
        policies: list[Policy] = []
        nat: list[NATRule] = []
        address_values: dict[str, list[str]] = {}
        interface_lists: dict[str, list[str]] = defaultdict(list)
        interface_vrfs: dict[str, str] = {}
        section = ""
        logical_lines: list[tuple[int, int, str]] = []
        pending = ""; start = 0
        for number, raw in enumerate(self.lines, 1):
            stripped = raw.rstrip()
            if pending:
                pending += " " + stripped.lstrip()
            else:
                pending = stripped; start = number
            if pending.endswith("\\"):
                pending = pending[:-1].rstrip(); continue
            logical_lines.append((start, number, pending)); pending = ""
        if pending: logical_lines.append((start, len(self.lines), pending))
        pending_policies: list[tuple[int, int, str, dict[str, str]]] = []
        for number, line_end, raw in logical_lines:
            line = raw.strip()
            if not line or line.startswith("#"): continue
            if line.startswith("/"): section = line; continue
            if not line.startswith(("add ", "set ")): continue
            values = key_value_tokens(line)
            if section == "/interface vlan" and line.startswith("add "):
                name = values.get("name", f"vlan{values.get('vlan-id', number)}")
                vid = int(values.get("vlan-id", "0")); vlans[vid] = VLAN(device=device.id, id=vid, name=name, trace=self.trace(number, raw))
                interfaces[name] = Interface(device=device.id, name=name, vlan_id=vid, trace=self.trace(number, raw))
            elif section == "/ip address" and line.startswith("add "):
                name, address = values.get("interface", "unknown"), values.get("address")
                interface = interfaces.setdefault(name, Interface(device=device.id, name=name, trace=self.trace(number, raw)))
                if address: interface.addresses.append(address)
            elif section == "/ip route" and line.startswith("add "):
                routes.append(Route(device=device.id, destination=values.get("dst-address", "0.0.0.0/0"),
                    next_hop=values.get("gateway"), vrf=None if values.get("routing-table", "main") == "main" else values.get("routing-table"),
                    metric=int(values["distance"]) if values.get("distance", "").isdigit() else None,
                    trace=self.trace(number, raw)))
            elif section == "/ip vrf" and line.startswith("add "):
                for member in values.get("interfaces", "").split(","):
                    if member: interface_vrfs[member] = values.get("name", "main")
            elif section == "/ip firewall address-list" and line.startswith("add "):
                address_values.setdefault(values.get("list", "unnamed"), []).append(values.get("address", "any"))
            elif section == "/interface list member" and line.startswith("add "):
                interface_lists[values.get("list", "unnamed")].append(values.get("interface", "unknown"))
            elif section == "/ip firewall filter" and line.startswith("add "):
                pending_policies.append((number, line_end, raw, values))
            elif section == "/ip firewall nat" and line.startswith("add "):
                action = values.get("action", "nat")
                nat.append(NATRule(device=device.id, name=values.get("comment", f"nat-{number}"),
                    type="destination" if values.get("chain") == "dstnat" else "source",
                    original_src=values.get("src-address", "any"), original_dst=values.get("dst-address", "any"),
                    translated_src=values.get("to-addresses") if values.get("chain") != "dstnat" else None,
                    translated_dst=values.get("to-addresses") if values.get("chain") == "dstnat" else None,
                    protocol=values.get("protocol", "any"), sequence=number,
                    source_ports=[values["src-port"]] if values.get("src-port") else [],
                    destination_ports=[values["dst-port"]] if values.get("dst-port") else [],
                    in_interfaces=([values["in-interface"]] if values.get("in-interface")
                                   else interface_lists.get(values.get("in-interface-list", ""), [])),
                    out_interfaces=([values["out-interface"]] if values.get("out-interface")
                                    else interface_lists.get(values.get("out-interface-list", ""), [])),
                    disabled=values.get("disabled", "no").lower() in {"yes", "true"},
                    trace=self.trace(number, raw)))
        for number, line_end, raw, values in pending_policies:
            if values.get("disabled", "no").lower() in {"yes", "true"}: continue
            action = values.get("action", "drop"); chain = values.get("chain", "forward")
            action_map = {"accept": "permit", "fasttrack-connection": "permit", "drop": "deny",
                          "reject": "reject", "tarpit": "deny", "jump": "jump", "return": "return"}
            canonical_action = action_map.get(action, "continue")
            terminal = canonical_action not in {"continue", "return"}
            src_name = values.get("src-address-list"); dst_name = values.get("dst-address-list")
            raw_src = values.get("src-address", src_name or "any"); raw_dst = values.get("dst-address", dst_name or "any")
            src_negate = raw_src.startswith("!"); dst_negate = raw_dst.startswith("!")
            raw_src = raw_src.removeprefix("!"); raw_dst = raw_dst.removeprefix("!")
            in_names = [values["in-interface"]] if values.get("in-interface") else interface_lists.get(values.get("in-interface-list", ""), [])
            out_names = [values["out-interface"]] if values.get("out-interface") else interface_lists.get(values.get("out-interface-list", ""), [])
            supported = {"chain", "action", "disabled", "src-address", "dst-address", "src-address-list",
                         "dst-address-list", "protocol", "dst-port", "in-interface", "out-interface",
                         "in-interface-list", "out-interface-list", "connection-state", "jump-target", "comment"}
            confidence = Confidence.PARTIAL if set(values) - supported else Confidence.EXACT
            policies.append(Policy(id=f"{device.id}:filter:{number}", device=device.id,
                name=values.get("comment", chain), sequence=number, order=len(policies) + 1,
                src=address_values.get(src_name, [raw_src]), dst=address_values.get(dst_name, [raw_dst]),
                src_negate=src_negate, dst_negate=dst_negate,
                protocol=[values.get("protocol", "ip")], dst_ports=values.get("dst-port", "any").split(","),
                action=canonical_action, direction="forward" if chain == "forward" else "unknown",
                interface=values.get("in-interface") or values.get("out-interface"),
                in_interfaces=in_names, out_interfaces=out_names,
                chain_id=f"routeros:{chain}", default_action="permit" if chain == "forward" else "unknown",
                terminal=terminal, jump_target=values.get("jump-target"),
                states=values.get("connection-state", "").split(",") if values.get("connection-state") else [],
                entrypoint=chain == "forward", confidence=confidence, trace=self.trace(number, raw, line_end)))
        segments: list[Segment] = []
        for interface in interfaces.values():
            interface.vrf = None if interface_vrfs.get(interface.name) in {None, "main"} else interface_vrfs[interface.name]
            interface.segment_id = f"{device.id}-{slug(interface.name)}"
            segments.append(Segment(id=interface.segment_id, name=interface.name,
                type="vlan" if interface.vlan_id is not None else "interface", device=device.id,
                vlan_id=interface.vlan_id, networks=interface_networks(interface.addresses), vrf=interface.vrf))
            if interface.vlan_id in vlans:
                vlans[interface.vlan_id].subnets = interface_networks(interface.addresses)
        objects = [AddressObject(device=device.id, name=name, values=values) for name, values in address_values.items()]
        return CanonicalConfig(device=device, interfaces=list(interfaces.values()), vlans=list(vlans.values()),
            segments=segments, routes=routes, policies=policies, nat=nat, address_objects=objects)
