from __future__ import annotations

import ipaddress

from .analyzer import policy_coverage
from .models import CanonicalConfig, Confidence, Policy, Segment
from .policy_utils import packet_matches, policy_chain_key, policy_order
from .reachability_models import ChainVerdict, HopResult, Packet


DEFINITION_ONLY_NETWORK_OSES = {
    "ios", "ios-xe", "nx-os", "aos-cx", "eos", "alliedware-plus",
    "rtx", "exos", "voss",
}
STATEFUL_NETWORK_OSES = {"srx", "fortios", "panos", "asa", "ftd"}


def resolve_policy(config: CanonicalConfig, policy: Policy) -> Policy:
    objects = {item.name: item.values for item in config.address_objects}

    def resolve(values: list[str], seen: set[str] | None = None) -> list[str]:
        seen = set() if seen is None else seen
        result: list[str] = []
        for value in values:
            if value in objects and value not in seen:
                result.extend(resolve(objects[value], seen | {value}))
            else:
                result.append(value)
        return list(dict.fromkeys(result))

    return policy.model_copy(update={"src": resolve(policy.src), "dst": resolve(policy.dst)})


def policy_applies(
    policy: Policy,
    config: CanonicalConfig,
    ingress: Segment,
    egress: Segment,
    ingress_interfaces: set[str],
    egress_interfaces: set[str],
) -> bool:
    if not policy.enabled:
        return False
    if policy.ip_version:
        def versions(segment: Segment) -> set[int]:
            result: set[int] = set()
            for raw in segment.networks:
                try:
                    result.add(ipaddress.ip_network(raw, strict=False).version)
                except ValueError:
                    continue
            return result
        ingress_versions, egress_versions = versions(ingress), versions(egress)
        if ((ingress_versions and policy.ip_version not in ingress_versions)
                or (egress_versions and policy.ip_version not in egress_versions)):
            return False
    if policy.direction == "unknown" and config.device.network_os in DEFINITION_ONLY_NETWORK_OSES:
        return False
    if (
        policy.direction == "in" and policy.interface
        and policy.interface not in ingress_interfaces
        and ingress.id not in policy.src_segments
    ):
        return False
    if (
        policy.direction == "out" and policy.interface
        and policy.interface not in egress_interfaces
        and egress.id not in policy.dst_segments
    ):
        return False
    if policy.direction == "zone":
        if policy.src_segments and ingress.id not in policy.src_segments:
            return False
        if policy.dst_segments and egress.id not in policy.dst_segments:
            return False
        if policy.from_zone and not policy.src_segments and policy.from_zone not in ingress_interfaces:
            return False
        if policy.to_zone and not policy.dst_segments and policy.to_zone not in egress_interfaces:
            return False
    if policy.in_interfaces and not ingress_interfaces.intersection(policy.in_interfaces):
        return False
    if policy.out_interfaces and not egress_interfaces.intersection(policy.out_interfaces):
        return False
    return True


def chain_default(config: CanonicalConfig, rules: list[Policy]) -> str:
    explicit = next((rule.default_action for rule in rules if rule.default_action), None)
    if explicit:
        if explicit == "permit":
            return "ALLOW"
        if explicit in {"deny", "reject"}:
            return "DENY"
        return "UNKNOWN"
    direction = rules[0].direction
    if direction in {"in", "out", "zone", "global"}:
        return "DENY"
    if direction == "forward" and config.device.network_os in {"routeros", "vyos"}:
        return "ALLOW"
    return "UNKNOWN"


def evaluate_chain(
    config: CanonicalConfig,
    rules: list[Policy],
    ingress: Segment,
    egress: Segment,
    protocol: str,
    port: int | None,
    state: str,
    all_chains: dict[tuple[str, ...], list[Policy]],
    visited: set[tuple[str, ...]] | None = None,
    source_port: int | None = None,
    packet: Packet | None = None,
) -> ChainVerdict:
    rules = sorted(rules, key=policy_order)
    key = policy_chain_key(rules[0])
    visited = set() if visited is None else visited
    if key in visited:
        return ChainVerdict(result="UNKNOWN", reason="Policy chain loop")
    visited.add(key)
    for policy in rules:
        if policy.states and not ({state.lower(), "any"} & {value.lower() for value in policy.states}):
            continue
        resolved = resolve_policy(config, policy)
        # Binding IDs and device ownership stay local; address matches use
        # the same end-to-end packet at every hop.
        coverage = policy_coverage(
            resolved,
            ingress.model_copy(update={"networks": list(packet.source_addresses)}) if packet else ingress,
            egress.model_copy(update={"networks": list(packet.destination_addresses)}) if packet else egress,
        )
        if coverage == "NONE" or not packet_matches(resolved, protocol, port, source_port):
            continue
        suffix = "（Segmentの一部に一致）" if coverage == "PARTIAL" else ""
        source_port_unknown = source_port is None and not any(
            value.lower() in {"any", "*"} for value in policy.src_ports
        )
        destination_port_unknown = port is None and not any(
            value.lower() in {"any", "*"} for value in policy.dst_ports
        )
        if (coverage == "PARTIAL" or policy.confidence != Confidence.EXACT
                or policy.unsupported_matches or source_port_unknown
                or destination_port_unknown):
            result = "PARTIAL"
        elif policy.action == "permit":
            result = "ALLOW"
        elif policy.action in {"deny", "reject", "restrict"}:
            result = "DENY"
        elif policy.action == "return":
            return ChainVerdict(
                result="RETURN", reason=f"{policy.name} / Rule {policy.sequence}",
                policy=policy.id, trace=policy.trace, chain=key[-1],
            )
        elif policy.action == "continue" or not policy.terminal:
            continue
        elif policy.action == "jump" and policy.jump_target:
            target = next((candidate for candidate in all_chains
                           if candidate[-1] == policy.jump_target
                           or candidate[-1].endswith(f":{policy.jump_target}")), None)
            if target:
                jumped = evaluate_chain(
                    config, all_chains[target], ingress, egress, protocol, port,
                    state, all_chains, visited.copy(), source_port, packet,
                )
                if jumped.result == "RETURN":
                    continue
                return jumped
            result = "UNKNOWN"
        else:
            result = "UNKNOWN"
        return ChainVerdict(
            result=result, reason=f"{policy.name} / Rule {policy.sequence}{suffix}",
            policy=policy.id, trace=policy.trace, chain=key[-1],
        )
    default_action = next((rule.default_action for rule in rules if rule.default_action), None)
    if default_action == "return":
        return ChainVerdict(result="RETURN", reason="custom chain default return", chain=key[-1])
    if default_action == "jump":
        target_name = next((rule.default_jump_target for rule in rules if rule.default_jump_target), None)
        target = next((candidate for candidate in all_chains
                       if target_name and (candidate[-1] == target_name
                                           or candidate[-1].endswith(f":{target_name}"))), None)
        if target:
            return evaluate_chain(
                config, all_chains[target], ingress, egress, protocol, port,
                state, all_chains, visited.copy(), source_port, packet,
            )
        return ChainVerdict(result="UNKNOWN", reason="default jump targetを解決できません", chain=key[-1])
    if config.device.network_os == "routeros" and not any(rule.entrypoint for rule in rules):
        return ChainVerdict(result="RETURN", reason="custom chain end", chain=key[-1])
    default = chain_default(config, rules)
    reason = (
        "適用Policyの暗黙deny" if default == "DENY" else
        "Policy chainの既定permit" if default == "ALLOW" else
        "一致するPolicyを確認できません"
    )
    return ChainVerdict(result=default, reason=reason, chain=key[-1])


def _asa_default(config: CanonicalConfig, ingress: Segment, egress: Segment) -> HopResult | None:
    source = next((item for item in config.interfaces if item.segment_id == ingress.id), None)
    target = next((item for item in config.interfaces if item.segment_id == egress.id), None)
    if not source or not target or source.security_level is None or target.security_level is None:
        return None
    same = source.security_level == target.security_level
    allowed = source.security_level > target.security_level or (
        same and config.device.features.get("same_security_inter_interface", False)
    )
    return HopResult(
        device=config.device.id, ingress=ingress.id, egress=egress.id,
        result="ALLOW" if allowed else "DENY", reason="ASA security-level既定動作",
    )


def evaluate_device(
    config: CanonicalConfig,
    ingress: Segment,
    egress: Segment,
    protocol: str,
    port: int | None,
    state: str = "new",
    assume_session: bool = False,
    source_port: int | None = None,
    ip_version: int | None = None,
    packet: Packet | None = None,
) -> HopResult:
    if packet is not None:
        protocol, port = packet.protocol, packet.destination_port
        state, source_port, ip_version = packet.state, packet.source_port, packet.ip_version
    if state in {"established", "related"} and config.device.network_os in STATEFUL_NETWORK_OSES:
        if assume_session:
            return HopResult(
                device=config.device.id, ingress=ingress.id, egress=egress.id,
                result="ALLOW", reason="既存stateful sessionを仮定",
            )
        return HopResult(
            device=config.device.id, ingress=ingress.id, egress=egress.id,
            result="UNKNOWN", reason="実セッションテーブル未取得（既存sessionの有無を判定不能）",
        )
    ingress_interfaces = {
        value for interface in config.interfaces if interface.segment_id == ingress.id
        for value in (interface.name, interface.zone) if value
    }
    egress_interfaces = {
        value for interface in config.interfaces if interface.segment_id == egress.id
        for value in (interface.name, interface.zone) if value
    }
    chains: dict[tuple[str, ...], list[Policy]] = {}
    for policy in config.policies:
        if ip_version and policy.ip_version and policy.ip_version != ip_version:
            continue
        if policy_applies(policy, config, ingress, egress, ingress_interfaces, egress_interfaces):
            chains.setdefault(policy_chain_key(policy), []).append(policy)
    entry_chains = {key: rules for key, rules in chains.items() if any(rule.entrypoint for rule in rules)}
    if not entry_chains:
        if config.device.network_os in {"asa", "ftd"}:
            asa_result = _asa_default(config, ingress, egress)
            if asa_result:
                return asa_result
        firewall_default_deny = config.device.network_os in {"srx", "fortios", "panos"}
        return HopResult(
            device=config.device.id, ingress=ingress.id, egress=egress.id,
            result="DENY" if firewall_default_deny else "UNKNOWN",
            reason="適用Policyの暗黙deny" if firewall_default_deny else "一致する適用Policyを確認できません",
        )
    verdicts = [evaluate_chain(config, rules, ingress, egress, protocol, port, state, chains,
                               source_port=source_port, packet=packet)
                for rules in entry_chains.values()]
    values = {item.result for item in verdicts}
    result = (
        "DENY" if "DENY" in values else
        "PARTIAL" if "PARTIAL" in values else
        "UNKNOWN" if "UNKNOWN" in values else
        "ALLOW"
    )
    decisive = next((item for item in verdicts if item.result == result), verdicts[0])
    return HopResult(
        device=config.device.id, ingress=ingress.id, egress=egress.id,
        result=result, reason=decisive.reason, policy=decisive.policy,
        trace=decisive.trace, chains=verdicts,
    )
