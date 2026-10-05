"""Isolated native RouterOS probe. Ethernet frames travel over QEMU socket NICs."""
from pathlib import Path
import json
import hashlib
from datetime import datetime, timezone
import re
import select
import socket
import struct
import time
import pexpect
from scapy.all import ARP, Ether, IP, TCP

OUT = Path('/results')
OUT.mkdir(parents=True, exist_ok=True)
# A failed rerun must never leave an earlier successful report as its result.
(OUT / 'native.json').write_text(json.dumps({'status': 'incomplete'}) + '\n')
args = ['-accel', 'tcg', '-m', '512', '-drive', 'file=/opt/chr.img,format=raw,if=virtio,snapshot=on',
        '-display', 'none', '-serial', 'stdio', '-monitor', 'none']
for i in range(1, 4):
    args += ['-netdev', f'socket,id=n{i},listen=127.0.0.1:{17000+i}', '-device', f'virtio-net-pci,netdev=n{i},mac=52:54:00:12:34:0{i}']
vm = pexpect.spawn('qemu-system-x86_64', args, encoding='utf8', timeout=180, dimensions=(40, 240))
vm.logfile_read = (OUT / 'console.log').open('w')
try:
    vm.expect('Login:'); vm.sendline('admin+ct')
    vm.expect('Password:'); vm.sendline('')
    n = vm.expect(['Do you want to see the software license', 'new password>', r'\[admin@[^\]]+\] >'])
    if n == 0:
        vm.sendline('n'); n = vm.expect(['new password>', r'\[admin@[^\]]+\] >'])
        n = 1 if n == 0 else 2
    if n == 1:
        vm.sendline('Synthetic-Lab-Only-482!'); vm.expect('repeat new password>'); vm.sendline('Synthetic-Lab-Only-482!')
        vm.expect(r'\[admin@[^\]]+\] >')
    def command(value):
        vm.sendline(value); vm.expect(r'\[admin@[^\]]+\] >', timeout=30)
        result = re.sub(r'\x1b\[[0-9;?]*[A-Za-z]', '', vm.before).replace('\r', '')
        if re.search(r'(syntax error|bad command|failure:|expected end of command)', result, re.I):
            raise AssertionError(result)
        return result
    print('RouterOS booted', flush=True)
    version = command(':put [/system resource get version]').splitlines()[-1].strip()
    command('/ip dhcp-client remove [find]')
    prefix = ''
    fixture = Path('/lab/scenarios/routeros/before/routeros.rsc')
    for line in fixture.read_text().splitlines():
        if not line or line.startswith('#'): continue
        if line.startswith('/'): prefix = line
        else: command(prefix + ' ' + line)
    exported = command('/export terse')
    (OUT / 'export-terse.txt').write_text(exported)
    # Standard sectioned export is what users upload to NetPolicy Lens.
    exported = command('/export')
    def save_export(raw, name):
        # Remove only ephemeral VM identity/time comments, never config lines.
        lines = raw[raw.find('#'):].strip().splitlines()
        lines = [line for line in lines if not line.startswith('# system id =')]
        (OUT / name).write_text('\n'.join(lines) + '\n')
    save_export(exported, 'routeros-before.rsc')
    print('Fixture accepted by RouterOS', flush=True)
    sockets = []
    buffers = {}
    hosts = ['10.44.1.10', '10.44.9.20', '10.44.2.10']
    macs = ['02:00:00:00:00:01', '02:00:00:00:00:02', '02:00:00:00:00:03']
    for i in range(3):
        sock = socket.create_connection(('127.0.0.1', 17001+i)); sockets.append(sock); buffers[sock] = b''
    def send(i, frame):
        raw = bytes(frame); sockets[i].sendall(struct.pack('!I', len(raw)) + raw)
    def receive(duration):
        end = time.monotonic() + duration; packets = []
        while time.monotonic() < end:
            ready, _, _ = select.select(sockets, [], [], min(.1, max(0, end-time.monotonic())))
            for sock in ready:
                data = sock.recv(65536)
                if not data: raise RuntimeError('QEMU NIC closed')
                buffers[sock] += data
                while len(buffers[sock]) >= 4:
                    size = struct.unpack('!I', buffers[sock][:4])[0]
                    if len(buffers[sock]) < size + 4: break
                    packet = Ether(buffers[sock][4:4+size]); buffers[sock] = buffers[sock][4+size:]
                    i = sockets.index(sock)
                    if ARP in packet and packet[ARP].op == 1 and packet[ARP].pdst == hosts[i]:
                        send(i, Ether(src=macs[i], dst=packet.src)/ARP(op=2, hwsrc=macs[i], psrc=hosts[i], hwdst=packet[ARP].hwsrc, pdst=packet[ARP].psrc))
                    packets.append((i,packet))
        return packets
    receive(3)
    checks = []
    def probe(name, ingress, destination, port, sport, allowed, egress=1, translated=None):
        receive(.2)
        command('/ip firewall filter reset-counters-all')
        send(ingress, Ether(src=macs[ingress], dst=f'52:54:00:12:34:0{ingress+1}')/IP(src=hosts[ingress],dst=destination)/TCP(sport=sport,dport=port,flags='S',seq=12345))
        packets = receive(4)
        forwarded = [p for i,p in packets if i==egress and IP in p and TCP in p and p[TCP].sport==sport]
        if allowed:
            assert forwarded, (name, 'SYN not forwarded')
            p = forwarded[0]
            target, target_port = translated or (destination,port)
            assert p[IP].dst==target and p[TCP].dport==target_port, (name, p.summary())
            send(egress, Ether(src=macs[egress],dst=p.src)/IP(src=target,dst=hosts[ingress])/TCP(sport=target_port,dport=sport,flags='SA',seq=45678,ack=12346))
            returned = [p for i,p in receive(3) if i==ingress and TCP in p and p[TCP].dport==sport and int(p[TCP].flags)==18]
            assert returned and returned[0][IP].src==destination and returned[0][TCP].sport==port, (name,'SYN-ACK/reverse NAT missing')
            send(ingress,Ether(src=macs[ingress],dst=f'52:54:00:12:34:0{ingress+1}')/IP(src=hosts[ingress],dst=destination)/TCP(sport=sport,dport=port,flags='A',seq=12346,ack=45679))
            assert any(i==egress and TCP in p and p[TCP].sport==sport and int(p[TCP].flags)==16 for i,p in receive(1)), (name,'ACK missing')
            evidence = 'TCP three-way handshake; destination and reverse source verified'
        else:
            assert not forwarded, (name,'unexpected forwarded SYN')
            rule = 'office-https' if name.startswith('after-') else 'default-deny'
            assert '\ndrop\n' in command(f':put [/ip firewall filter get [find comment="{rule}"] action]')
            counters = command(f':put [/ip firewall filter get [find comment="{rule}"] packets]')
            values = re.findall(r'(?m)^\s*(\d+)\s*$', counters)
            assert any(int(v)>0 for v in values), (name,'no drop counter evidence', counters)
            evidence = 'No forwarded SYN; matching firewall counter incremented'
        checks.append({'case':name,'result':'ALLOW' if allowed else 'DENY','evidence':evidence})
        print(name, 'passed', flush=True)
    probe('office-https',0,'10.44.9.20',443,41001,True)
    probe('office-ssh',0,'10.44.9.20',22,41002,False)
    probe('guest-isolation',2,'10.44.1.10',443,41003,False,egress=0)
    probe('dnat',0,'10.44.1.100',8443,41004,True,translated=('10.44.9.20',443))
    command('/ip firewall filter set [find comment="office-https"] action=drop')
    save_export(command('/export'), 'routeros-after.rsc')
    probe('after-office-https',0,'10.44.9.20',443,42001,False)
    probe('after-dnat',0,'10.44.1.100',8443,42004,False)
    (OUT/'native.json').write_text(json.dumps({'status':'passed','created_at':datetime.now(timezone.utc).isoformat(),'version':version.strip(),'image_sha256':Path('/opt/chr.sha256').read_text().split()[0],
        'export_sha256':{v:hashlib.sha256((OUT/f'routeros-{v}.rsc').read_bytes()).hexdigest() for v in ('before','after')},
        'fixture_sha256':hashlib.sha256(fixture.read_bytes()).hexdigest(),'checks':checks},indent=2)+'\n')
finally:
    vm.close(force=True)
