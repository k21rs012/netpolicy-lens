"""FortiOS NAT normalization with explicit guards for unresolved mappings."""
import ipaddress
import re

from ..models import AddressObject, NATRule


def first(block, key, default=None):
    return (block.values.get(key) or [default])[0]


def single_host(value):
    try:
        network = ipaddress.ip_network(value)
        return str(network.network_address) if network.version == 4 and network.num_addresses == 1 else None
    except (ValueError, TypeError):
        return None


class FortiOSNAT:
    def __init__(self, parser, blocks, device, objects, resolve):
        self.parser, self.blocks, self.device = parser, blocks, device
        self.objects, self.resolve = objects, resolve
        settings = {key: value for b in blocks if b.section == 'system settings' for key, value in b.values.items()}
        self.central = settings.get('central-nat', ['disable'])[0] == 'enable'
        self.policy_based = settings.get('ngfw-mode', ['profile-based'])[0] == 'policy-based'
        self.pools = {b.name: b for b in blocks if b.section == 'firewall ippool'}
        self.vips = {b.name: b for b in blocks if b.section == 'firewall vip'}
        self.vip_groups = {b.name: b.values.get('member', []) for b in blocks if b.section == 'firewall vipgrp'}

    def policy_destinations(self, names, seen=frozenset()):
        vips, ordinary = [], []
        for name in names:
            if name in seen:
                ordinary.append('unknown')
            elif name in self.vips:
                vips.append(name)
            elif name in self.vip_groups:
                child, other = self.policy_destinations(self.vip_groups[name], seen | {name})
                vips.extend(child); ordinary.extend(other)
            else:
                ordinary.append(name)
        return list(dict.fromkeys(vips)), ordinary

    def pool(self, names):
        if len(names) != 1 or names[0] not in self.pools:
            return None, True, ['IP poolの参照先が未定義または複数です']
        block = self.pools[names[0]]
        start, end = single_host(first(block, 'startip')), single_host(first(block, 'endip'))
        kind = first(block, 'type', 'overload')
        supported = {'type', 'startip', 'endip', 'arp-reply', 'comments', 'associated-interface'}
        problems = []
        if not start or start != end or kind not in {'overload', 'one-to-one'}:
            problems.append('IP poolの範囲・割り当て方式を確定できません')
        if set(block.values) - supported:
            problems.append('IP poolに未対応条件があります')
        return start, kind == 'overload', problems

    def vip_rules(self):
        rules = []
        supported = {'uuid', 'comment', 'type', 'extip', 'mappedip', 'extintf', 'portforward', 'protocol',
                     'extport', 'mappedport', 'arp-reply', 'status', 'nat-source-vip'}
        for order, block in enumerate(self.vips.values(), 1):
            external = first(block, 'extip', 'unknown')
            interface = first(block, 'extintf', 'any')
            if external == '0.0.0.0':
                external = f'interface:{interface}'
            mapped = single_host(first(block, 'mappedip'))
            problems = []
            if not mapped or len(block.values.get('mappedip', [])) != 1:
                problems.append('VIPのmapped IPが単一IPv4ではありません')
            if not single_host(external) and not external.startswith('interface:'):
                problems.append('VIPのexternal IPが単一IPv4ではありません')
            if first(block, 'type', 'static-nat') != 'static-nat' or set(block.values) - supported:
                problems.append('VIPに未対応のtype・条件があります')
            forwarding = first(block, 'portforward', 'disable') == 'enable'
            external_port, mapped_port = None, None
            if forwarding:
                ports = [first(block, 'extport', ''), first(block, 'mappedport', '')]
                if all(v.isdigit() and 0 < int(v) <= 65535 for v in ports):
                    external_port, mapped_port = map(int, ports)
                else:
                    problems.append('VIPのport範囲・変換先portは未対応です')
                if first(block, 'protocol', 'tcp') not in {'tcp', 'udp'}:
                    problems.append('VIP port forwardingのprotocolは未対応です')
            rules.append(NATRule(device=self.device, name=block.name, type='destination', stage='destination',
                fortios_kind='vip', original_dst=external, translated_dst=mapped,
                protocol=first(block, 'protocol', 'tcp') if forwarding else 'any',
                original_port=external_port, translated_port=mapped_port, in_interfaces=[interface],
                sequence=order, ip_version=4, disabled=first(block, 'status', 'enable') == 'disable',
                unsupported_matches=problems, trace=self.parser._block_trace(block)))
        return rules

    def policy_snat(self, block, policy, order):
        target, dynamic, problems = 'interface-address', True, []
        if first(block, 'ippool', 'disable') == 'enable':
            target, dynamic, problems = self.pool(block.values.get('poolname', []))
        if first(block, 'fixedport', 'disable') == 'enable':
            dynamic = False
        return NATRule(device=self.device, name=f'policy-{block.name}-snat', type='source', stage='source',
            translated_src=target, policy_id=policy.id, sequence=order,
            dynamic_port=dynamic, unsupported_matches=problems,
            in_interfaces=block.values.get('srcintf', []), out_interfaces=block.values.get('dstintf', []),
            trace=self.parser._block_trace(block))

    def address_reference(self, block, key):
        name = f'__central_nat_{block.name}_{key}'
        self.objects.append(AddressObject(device=self.device, name=name, values=self.resolve(block.values.get(key, ['all']))))
        # NAT object resolver treats "any" as a literal only at top level.
        values = self.objects[-1].values
        return 'any' if 'any' in values else name

    def central_rules(self):
        if not self.central:
            return []
        blocks = [b for b in self.blocks if b.section == 'firewall central-snat-map']
        order = [b.name for b in blocks]
        section = ''
        for raw in self.parser.lines:
            line = raw.strip()
            if line.startswith('config '): section = line[7:]
            elif line == 'end': section = ''
            elif section == 'firewall central-snat-map' and (match := re.fullmatch(r'move (\S+) (before|after) (\S+)', line)):
                item, where, anchor = match.groups()
                if item in order and anchor in order and item != anchor:
                    order.remove(item); order.insert(order.index(anchor) + (where == 'after'), item)
        rules = []
        supported = {'uuid', 'comments', 'srcintf', 'dstintf', 'orig-addr', 'dst-addr', 'protocol', 'orig-port',
                     'dst-port', 'nat-port', 'nat-ippool', 'nat', 'status', 'type', 'port-preserve'}
        for index, name in enumerate(order, 1):
            block = next(b for b in blocks if b.name == name)
            target, dynamic, problems = 'interface-address', True, []
            if block.values.get('nat-ippool'):
                target, dynamic, problems = self.pool(block.values['nat-ippool'])
            if set(block.values) - supported or first(block, 'type', 'ipv4') != 'ipv4':
                problems.append('central SNATに未対応条件・IP familyがあります')
            port = first(block, 'nat-port', '0')
            translated_port = None
            if port != '0':
                if port.isdigit() and 0 < int(port) <= 65535:
                    translated_port = int(port)
                else:
                    problems.append('central SNATの変換port範囲は未対応です')
            protocol = first(block, 'protocol', '0')
            if translated_port is not None and protocol not in {'6', '17'}:
                problems.append('central SNATのport変換にはTCP/UDPの指定が必要です')
            rules.append(NATRule(device=self.device, name=f'central-snat-{name}',
                type='exclude' if first(block, 'nat', 'enable') == 'disable' else 'source', stage='source',
                fortios_kind='central-snat', sequence=index,
                ip_version=4 if first(block, 'type', 'ipv4') == 'ipv4' else None,
                original_src=self.address_reference(block, 'orig-addr'), original_dst=self.address_reference(block, 'dst-addr'),
                protocol='any' if protocol == '0' else protocol,
                source_ports=[] if first(block, 'orig-port', '0') == '0' else block.values['orig-port'],
                destination_ports=[] if first(block, 'dst-port', '0') == '0' else block.values['dst-port'],
                translated_src=target, translated_port=translated_port, dynamic_port=dynamic,
                in_interfaces=block.values.get('srcintf', []), out_interfaces=block.values.get('dstintf', []),
                disabled=first(block, 'status', 'enable') == 'disable', unsupported_matches=problems,
                trace=self.parser._block_trace(block)))
        return rules

    def finalize_vips(self, rules, policies):
        if self.policy_based:
            rules.insert(0, NATRule(device=self.device, name='NGFW policy-based NAT', type='destination',
                stage='destination', sequence=-2, unsupported_matches=['NGFW policy-basedモードのPolicy/NAT連携は未対応です']))
        active_refs = {name for policy in policies for name in policy.destination_vips}
        source_nat = any(r.stage == 'source' and r.type != 'exclude' for r in rules)
        for rule in list(rules):
            if rule.fortios_kind != 'vip' or rule.disabled:
                continue
            block = self.vips[rule.name]
            if not self.central and rule.name not in active_refs:
                rule.unsupported_matches.append('未参照VIPのlocal処理は未対応です')
            if rule.translated_dst and (first(block, 'nat-source-vip') == 'enable' or
                                      (source_nat and first(block, 'portforward', 'disable') != 'enable')):
                rules.append(NATRule(device=self.device, name=rule.name + ' reverse SNAT', type='source', stage='source',
                    fortios_kind='vip-reverse', original_src=rule.translated_dst, translated_src=rule.original_dst,
                    sequence=-1, unsupported_matches=['VIPによる逆方向SNATの優先順位は未対応です'], trace=rule.trace))
