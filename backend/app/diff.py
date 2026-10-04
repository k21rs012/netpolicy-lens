from __future__ import annotations

from typing import Any, Callable
import ipaddress

from .analyzer import build_matrix
from .models import CanonicalConfig
from .matrix_query import build_query_matrix


POLICY_FIELDS = (
    "src", "dst", "src_segments", "dst_segments", "protocol", "src_ports", "dst_ports",
    "action", "direction", "interface", "from_zone", "to_zone", "src_negate", "dst_negate",
)
INTERFACE_FIELDS = ("description", "addresses", "vlan_id", "trunk_vlans", "zone", "segment_id", "acl_in", "acl_out")
VLAN_FIELDS = ("name", "subnets", "gateway")
ZONE_FIELDS = ("interfaces", "segment_id")


def _field_changes(before: Any, after: Any, fields: tuple[str, ...]) -> list[dict[str, Any]]:
    changes: list[dict[str, Any]] = []
    for field in fields:
        old, new = getattr(before, field), getattr(after, field)
        if old != new:
            changes.append({"field": field, "before": old, "after": new})
    return changes


def _object_diff(
    before_items: list[Any], after_items: list[Any], key: Callable[[Any], str],
    fields: tuple[str, ...], kind: str,
) -> list[dict[str, Any]]:
    before_map = {key(item): item for item in before_items}; after_map = {key(item): item for item in after_items}
    result: list[dict[str, Any]] = []
    for item_key in sorted(before_map.keys() - after_map.keys()):
        result.append({"change": "REMOVED", "kind": kind, "key": item_key, "before": before_map[item_key].model_dump(), "after": None, "fields": []})
    for item_key in sorted(after_map.keys() - before_map.keys()):
        result.append({"change": "ADDED", "kind": kind, "key": item_key, "before": None, "after": after_map[item_key].model_dump(), "fields": []})
    for item_key in sorted(before_map.keys() & after_map.keys()):
        changes = _field_changes(before_map[item_key], after_map[item_key], fields)
        if changes:
            result.append({"change": "CHANGED", "kind": kind, "key": item_key,
                "before": before_map[item_key].model_dump(), "after": after_map[item_key].model_dump(), "fields": changes})
    return result


def _range_signature(cell) -> tuple:
    # Ignore partition shape, path order and prose: compare address coverage
    # per protocol/verdict, including all ECMP outcomes for each address.
    groups = {}
    for item in cell.destination_ranges if cell else []:
        for value in item["addresses"]:
            network = ipaddress.ip_network(value)
            key = (item["protocol"], item["result"], network.version)
            groups.setdefault(key, []).append(network)
    return tuple((key, tuple(map(str, ipaddress.collapse_addresses(values))))
                 for key, values in sorted(groups.items()))


def compare_snapshots(before: list[CanonicalConfig], after: list[CanonicalConfig],
                      protocol: str | None = None, port: int | None = None) -> dict[str, Any]:
    conditioned = protocol is not None or port is not None
    def cells(configs):
        return build_query_matrix(configs, protocol, port) if conditioned else build_matrix(configs)
    before_segments = {segment.id: segment for config in before for segment in config.segments}
    after_segments = {segment.id: segment for config in after for segment in config.segments}
    all_segments = {**before_segments, **after_segments}
    before_cells = {(cell.source, cell.destination): cell for cell in cells(before)}
    after_cells = {(cell.source, cell.destination): cell for cell in cells(after)}
    communications: list[dict[str, Any]] = []
    for key in sorted(before_cells.keys() | after_cells.keys()):
        old, new = before_cells.get(key), after_cells.get(key)
        old_allowed, new_allowed = set(old.allowed if old else []), set(new.allowed if new else [])
        old_denied, new_denied = set(old.denied if old else []), set(new.denied if new else [])
        new_allow = sorted(new_allowed - old_allowed); new_deny = sorted(new_denied - old_denied)
        removed_allow = sorted(old_allowed - new_allowed); removed_deny = sorted(old_denied - new_denied)
        result_changed = (old.result if old else None) != (new.result if new else None)
        range_changed = conditioned and _range_signature(old) != _range_signature(new)
        if not (new_allow or new_deny or removed_allow or removed_deny or result_changed or range_changed):
            continue
        src, dst = all_segments.get(key[0]), all_segments.get(key[1])
        communications.append({
            "source": key[0], "destination": key[1],
            "source_label": src.name if src else key[0], "destination_label": dst.name if dst else key[1],
            "source_device": src.device if src else "unknown", "destination_device": dst.device if dst else "unknown",
            "before_result": old.result if old else None, "after_result": new.result if new else None,
            "new_allow": new_allow, "new_deny": new_deny,
            "removed_allow": removed_allow, "removed_deny": removed_deny,
            "after_traces": new.traces if new else [],
            "before_ranges": old.destination_ranges if old else [],
            "after_ranges": new.destination_ranges if new else [],
            "before_reason": old.reason if old else None, "after_reason": new.reason if new else None,
        })

    before_policies = [p for config in before for p in config.policies]
    after_policies = [p for config in after for p in config.policies]
    policies = _object_diff(before_policies, after_policies, lambda p: f"{p.device}:{p.name}:{p.sequence}", POLICY_FIELDS, "policy")
    interfaces = _object_diff(
        [x for c in before for x in c.interfaces], [x for c in after for x in c.interfaces],
        lambda x: f"{x.device}:{x.name}", INTERFACE_FIELDS, "interface",
    )
    vlans = _object_diff(
        [x for c in before for x in c.vlans], [x for c in after for x in c.vlans],
        lambda x: f"{x.device}:vlan-{x.id}", VLAN_FIELDS, "vlan",
    )
    zones = _object_diff(
        [x for c in before for x in c.zones], [x for c in after for x in c.zones],
        lambda x: f"{x.device}:{x.name}", ZONE_FIELDS, "zone",
    )
    network = interfaces + vlans + zones
    return {
        "evaluation": "path" if conditioned else "policy_summary",
        "protocol": protocol, "port": port,
        "summary": {
            "new_allow": sum(len(x["new_allow"]) for x in communications),
            "new_deny": sum(len(x["new_deny"]) for x in communications),
            "removed_allow": sum(len(x["removed_allow"]) for x in communications),
            "added_rules": sum(x["change"] == "ADDED" for x in policies),
            "removed_rules": sum(x["change"] == "REMOVED" for x in policies),
            "changed_rules": sum(x["change"] == "CHANGED" for x in policies),
            "network_changes": len(network),
        },
        "communications": communications,
        "policies": policies,
        "network": network,
    }

