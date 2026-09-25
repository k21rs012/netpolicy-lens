"""Conservative NAT execution: only deterministic, fully matched rules mutate packets."""
from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from fnmatch import fnmatchcase

from .models import CanonicalConfig, NATRule, Segment
from .policy_utils import SERVICE_PORTS, port_matches
from .reachability_models import NatEffect, Packet


ORDERS = {
    "vyos": "destination NAT → routing → policy → source NAT",
    "routeros": "dstnat → routing → forward → srcnat",
    "srx": "static/destination NAT → routing → policy → reverse static/source NAT",
    "fortios": "routing → policy → policy SNAT",
}


@dataclass
class NatStage:
    packet: Packet
    effects: list[NatEffect] = field(default_factory=list)
    blocked: bool = False


def stage_of(rule: NATRule) -> str:
    return rule.stage or ("destination" if rule.type in {"destination", "static"} else "source")


def _addresses(config: CanonicalConfig, value: str, seen: frozenset[str] = frozenset()) -> list[str]:
    if value in seen:
        raise ValueError("循環するNAT address object")
    if value.startswith("interface:"):
        names = value.split(":", 1)[1]
        values = [str(ipaddress.ip_interface(a).ip) for i in config.interfaces
                  if i.name == names for a in i.addresses]
    else:
        obj = next((o for o in config.address_objects if o.name == value), None)
        if obj is None:
            return [value]
        values = obj.values
    if not values:
        raise ValueError("NAT addressを解決できません")
    return [v for item in values for v in _addresses(config, item, seen | {value})]


def _coverage(config: CanonicalConfig, value: str, scope: tuple[str, ...]) -> str:
    if value.lower() in {"any", "all", "*"}:
        return "FULL"
    try:
        negate = value.startswith("!")
        candidates = [ipaddress.ip_network(v, strict=False) for v in _addresses(config, value.lstrip("!"))]
        networks = [ipaddress.ip_network(v) for v in scope]
    except ValueError:
        return "PARTIAL"
    if not networks:
        return "PARTIAL"
    full = all(any(n.version == c.version and n.subnet_of(c) for c in candidates) for n in networks)
    overlap = any(n.version == c.version and n.overlaps(c) for n in networks for c in candidates)
    result = "FULL" if full else "PARTIAL" if overlap else "NONE"
    return {"FULL": "NONE", "NONE": "FULL", "PARTIAL": "PARTIAL"}[result] if negate else result


def _interface_match(names: list[str], config: CanonicalConfig, segment: Segment | None) -> str:
    if not names or "any" in names:
        return "FULL"
    if segment is None:
        return "PARTIAL"
    values = {v for i in config.interfaces if i.segment_id == segment.id for v in (i.name, i.zone) if v}
    return "FULL" if any((not any(fnmatchcase(v, n[1:]) for v in values)) if n.startswith("!")
                         else any(fnmatchcase(v, n) for v in values) for n in names) else "NONE"


def _match(config: CanonicalConfig, rule: NATRule, packet: Packet, ingress: Segment,
           egress: Segment | None) -> str:
    if rule.disabled or (rule.ip_version and packet.ip_version and rule.ip_version != packet.ip_version):
        return "NONE"
    protocol = {"6": "tcp", "17": "udp", "1": "icmp", "58": "icmpv6"}.get(rule.protocol.lower(), rule.protocol.lower())
    protocols = {protocol}
    if "tcp_udp" in protocols:
        protocols = {"tcp", "udp"}
    protocol_known = protocol in {"any", "all", "ip", "*", "tcp", "udp", "tcp_udp", "icmp", "icmpv6", "gre", "esp", "ah", "sctp"}
    if protocol_known and not protocols.intersection({"any", "all", "ip", "*", packet.protocol.lower()}):
        return "NONE"
    checks = [_coverage(config, rule.original_src, packet.source_addresses),
              _coverage(config, rule.original_dst, packet.destination_addresses),
              _interface_match(rule.in_interfaces, config, ingress),
              _interface_match(rule.out_interfaces, config, egress)]
    if not protocol_known:
        checks.append("PARTIAL")
    for ports, port in ((rule.source_ports, packet.source_port),
                        (rule.destination_ports or ([str(rule.original_port)] if rule.original_port is not None else []),
                         packet.destination_port)):
        ports = [part for value in ports for part in value.split(",")]
        if any(not re.fullmatch(r"(?:any|\*|\d+|\d+-\d+|(?:eq|lt|gt|neq) \d+|range \d+-\d+)", v) and v not in SERVICE_PORTS for v in ports):
            checks.append("PARTIAL")
            continue
        if ports and not set(ports).intersection({"any", "*"}):
            checks.append("PARTIAL" if port is None else "FULL" if port_matches(ports, port) else "NONE")
    if "NONE" in checks:
        return "NONE"
    return "PARTIAL" if "PARTIAL" in checks or rule.unsupported_matches else "FULL"


def _translate(config: CanonicalConfig, value: str, original: str, scope: tuple[str, ...],
               rule: NATRule, packet: Packet, egress: Segment | None) -> tuple[str, ...]:
    if value in {"interface-address", "masquerade"}:
        candidates = [str(ipaddress.ip_interface(a).ip) for i in config.interfaces
                      if egress and i.segment_id == egress.id for a in i.addresses
                      if ipaddress.ip_interface(a).version == packet.ip_version]
        if len(set(candidates)) != 1:
            raise ValueError("NAT外側interfaceのアドレスが一意に確定しません")
    else:
        candidates = _addresses(config, value)
    if len(candidates) != 1:
        raise ValueError("NAT pool/objectの変換先が複数あります")
    target = ipaddress.ip_network(candidates[0], strict=False)
    if packet.ip_version != target.version:
        raise ValueError("NATによるIP family変換は未対応です")
    if target.num_addresses == 1:
        return (str(target),)
    # Prefix shifting is deterministic only for static one-to-one maps.
    sources = _addresses(config, original)
    if rule.type != "static" or len(sources) != 1:
        raise ValueError("NAT poolの割り当て先は実セッション情報が必要です")
    source = ipaddress.ip_network(sources[0], strict=False)
    if source.version != target.version or source.prefixlen != target.prefixlen:
        raise ValueError("static NATのprefix長が一致しません")
    return tuple(str(ipaddress.ip_network((int(target.network_address) + int(ipaddress.ip_network(v).network_address)
                                           - int(source.network_address), ipaddress.ip_network(v).prefixlen))) for v in scope)


def apply_nat_stage(config: CanonicalConfig, packet: Packet, ingress: Segment,
                    egress: Segment | None, stage: str, policy_id: str | None = None) -> NatStage:
    legacy = any(r.trace and r.semantics_version < 1 for r in config.nat if not r.disabled)
    if stage == "destination" and (config.device.network_os not in ORDERS or legacy):
        active = [r for r in config.nat if not r.disabled]
        if active:
            rule = active[0]
            effect = NatEffect(name=rule.name, type=rule.type, stage=stage_of(rule),
                translated_src=rule.translated_src, translated_dst=rule.translated_dst,
                translated_port=rule.translated_port, before=packet, trace=rule.trace,
                confidence="PARTIAL", note="旧NATモデルです。configを再取り込みしてください" if legacy else "このNetwork OSのNAT処理順は未対応です")
            return NatStage(packet, [effect], blocked=True)
    rules = [r for r in config.nat if stage_of(r) == stage]
    if config.device.network_os == "srx" and stage == "source":
        for rule in config.nat:
            if rule.type == "static" and rule.translated_dst:
                reverse = rule.model_copy(deep=True, update={
                    "name": rule.name + " (reverse static)", "stage": "source",
                    "original_src": rule.translated_dst, "original_dst": "any",
                    "translated_src": rule.original_dst, "translated_dst": None,
                    "in_interfaces": rule.out_interfaces, "out_interfaces": rule.in_interfaces,
                })
                if rule.original_src not in {"any", "0.0.0.0/0", "::/0"} or rule.source_ports or rule.destination_ports or rule.translated_port is not None:
                    reverse.unsupported_matches.append("conditional reverse static NAT")
                    reverse.source_ports, reverse.destination_ports = [], []
                    reverse.original_port = None
                rules.append(reverse)
    if config.device.network_os == "srx":
        rules.sort(key=lambda r: (r.type != "static", r.sequence if r.sequence is not None else 2**31))
    else:
        rules.sort(key=lambda r: r.sequence if r.sequence is not None else 2**31)
    for rule in rules:
        if rule.policy_id and policy_id != rule.policy_id:
            continue
        match = _match(config, rule, packet, ingress, egress)
        if match == "NONE":
            continue
        effect = NatEffect(name=rule.name, type=rule.type, stage=stage,
                           translated_src=rule.translated_src, translated_dst=rule.translated_dst,
                           translated_port=rule.translated_port, before=packet, trace=rule.trace,
                           evaluation_order=ORDERS.get(config.device.network_os))
        try:
            if match != "FULL":
                raise ValueError("NAT条件が部分一致または未解決です: " + "; ".join(rule.unsupported_matches))
            if config.device.network_os not in ORDERS:
                raise ValueError("このNetwork OSのNAT処理順は未対応です")
            if packet.state != "new":
                raise ValueError("既存セッションのNAT対応表は未取得です")
            if rule.type == "exclude":
                effect.note = "NAT除外: 後続の同段階のルールは評価しません"
                effect.after = packet
                return NatStage(packet, [effect])
            if rule.type not in {"source", "destination", "static"}:
                raise ValueError("未対応のNAT actionです")
            if config.device.network_os == "fortios" and (stage != "source" or not rule.policy_id):
                raise ValueError("FortiOSはPolicyに関連付けられたSNATのみ対応しています")
            if (stage == "destination" and rule.translated_src) or (stage == "source" and rule.translated_dst):
                raise ValueError("単一ルールの双方向アドレス変換は処理順未対応です")
            updates = {}
            for field_name, value, original, scope in (
                ("source_addresses", rule.translated_src, rule.original_src, packet.source_addresses),
                ("destination_addresses", rule.translated_dst, rule.original_dst, packet.destination_addresses),
            ):
                if value:
                    updates[field_name] = _translate(config, value, original, scope, rule, packet, egress)
            if rule.translated_port is not None:
                if packet.protocol not in {"tcp", "udp"} or not 0 <= rule.translated_port <= 65535:
                    raise ValueError("NAT port変換のprotocolまたは値が不明です")
                updates["source_port" if stage == "source" else "destination_port"] = rule.translated_port
            elif rule.dynamic_port and packet.protocol in {"tcp", "udp"}:
                updates["source_port"] = None
                effect.note = "動的PATの送信元portは実セッション情報が必要です"
                effect.confidence = "PARTIAL"
            if not updates:
                raise ValueError("NAT変換値を解決できません")
            after = packet.model_copy(update=updates)
            effect.applied, effect.after = True, after
            return NatStage(after, [effect])
        except ValueError as exc:
            effect.confidence, effect.note = "PARTIAL", str(exc)
            return NatStage(packet, [effect], blocked=True)
    return NatStage(packet)
