"""Retain Junos NAT rule-set scope and conditions the basic parser cannot execute."""
from __future__ import annotations

import re
from collections import defaultdict

from ..models import NATRule


def scope_junos_nat(lines: list[str], rules: list[NATRule]) -> None:
    contexts = defaultdict(lambda: {"from": [], "to": []})
    unknown = defaultdict(list)
    rule_unknown = defaultdict(list)
    pool_unknown = defaultdict(list)
    pools = defaultdict(list)
    fields = defaultdict(list)
    translations = {}
    for raw in lines:
        line = raw.strip()
        if m := re.fullmatch(r"set security nat (source|destination|static) rule-set (\S+) (from|to) (zone|interface) (\S+)", line):
            contexts[(m[1], m[2])][m[3]].append(m[5])
        elif m := re.match(r"set security nat (source|destination|static) rule-set (\S+) rule (\S+) (.+)", line):
            key = m[1], f"{m[2]}/{m[3]}"
            rest = m[4]
            if field := re.fullmatch(r"match (source-address|destination-address|source-port|destination-port|protocol) (\S+)", rest):
                fields[(*key, field[1])].append(field[2])
            elif translation := re.fullmatch(r"then (?:source-nat|destination-nat|static-nat) (off|interface|pool \S+|prefix \S+|inet)", rest):
                translations[key] = translation[1]
            else:
                rule_unknown[key].append(rest)
        elif m := re.match(r"set security nat (source|destination|static) rule-set (\S+) (.+)", line):
            unknown[(m[1], m[2])].append(m[3])
        elif m := re.match(r"set security nat (source|destination) pool (\S+) (.+)", line):
            if re.fullmatch(r"address [\da-fA-F:.]+(?:/\d+)?", m[3]):
                pools[(m[1], m[2])].append(m[3].split()[1])
            elif not re.fullmatch(r"address port \d+", m[3]):
                pool_unknown[(m[1], m[2])].append(m[3])
    for rule in rules:
        kind = rule.type
        name = rule.name.split("/", 1)[0]
        rule.stage = "destination" if kind in {"destination", "static"} else "source"
        rule.in_interfaces = contexts[(kind, name)]["from"]
        rule.out_interfaces = contexts[(kind, name)]["to"]
        rule.unsupported_matches.extend([*unknown[(kind, name)], *rule_unknown[(kind, rule.name)]])
        for key, values in fields.items():
            if key[:2] == (kind, rule.name) and len(values) > 1:
                rule.unsupported_matches.append("multiple NAT match values: " + key[2])
                if key[2] == "source-address": rule.original_src = "any"
                elif key[2] == "destination-address": rule.original_dst = "any"
                elif key[2] == "source-port": rule.source_ports = []
                elif key[2] == "destination-port": rule.destination_ports, rule.original_port = [], None
                elif key[2] == "protocol": rule.protocol = "any"
        raw = "-nat " + translations.get((kind, rule.name), "")
        if "-nat off" in raw:
            rule.type = "exclude"
        if rule.translated_dst and rule.translated_dst.startswith("prefix "):
            rule.translated_dst = rule.translated_dst.removeprefix("prefix ")
        if kind == "source":
            rule.dynamic_port = True
        if m := re.search(r"-nat pool (\S+)", raw):
            key = kind, m[1]
            if len(pools[key]) != 1 or pool_unknown[key]:
                rule.unsupported_matches.append("NAT pool range/options or unresolved pool")
        # Different rule-set selectors have precedence rules; do not flatten
        # multiple sets into one globally ordered chain and guess a winner.
        same_stage_sets = {r.name.split("/", 1)[0] for r in rules if r.type == kind}
        if len(same_stage_sets) > 1:
            rule.unsupported_matches.append("multiple NAT rule-set precedence")
