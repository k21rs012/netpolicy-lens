SAMPLES = {
"cisco01.conf": """version 17.9
hostname cisco01
!
vlan 10
 name USER
vlan 20
 name SERVER
interface Vlan10
 description User Gateway
 ip address 192.168.10.1 255.255.255.0
 ip access-group USER-IN in
interface Vlan20
 description Server Gateway
 ip address 192.168.20.1 255.255.255.0
ip access-list extended USER-IN
 10 permit tcp 192.168.10.0 0.0.0.255 192.168.20.0 0.0.0.255 eq 443
 20 deny tcp 192.168.10.0 0.0.0.255 192.168.20.0 0.0.0.255 eq 22
 30 permit ip 192.168.10.0 0.0.0.255 any
""",
"srx01.conf": """set system host-name srx01
set interfaces ge-0/0/1 unit 0 family inet address 10.0.10.1/24
set interfaces ge-0/0/2 unit 0 family inet address 203.0.113.2/29
set security zones security-zone trust interfaces ge-0/0/1.0
set security zones security-zone untrust interfaces ge-0/0/2.0
set security zones security-zone trust address-book address LAN-NET 10.0.10.0/24
set security policies from-zone trust to-zone untrust policy WEB match source-address LAN-NET
set security policies from-zone trust to-zone untrust policy WEB match destination-address any
set security policies from-zone trust to-zone untrust policy WEB match application junos-https
set security policies from-zone trust to-zone untrust policy WEB then permit
""",
"rtx01.conf": """hostname rtx01
ip lan1 address 192.168.30.1/24
ip lan2 address 192.168.20.254/24
ip filter 100 pass 192.168.30.0/24 192.168.20.0/24 tcp * 22
ip filter 101 reject * 192.168.30.0/24 * * *
ip lan1 secure filter in 100
ip lan2 secure filter out 101
ip route default gateway 192.168.20.1
""",
"fortigate01.conf": """config system global
    set hostname fortigate01
end
config system interface
    edit "port1"
        set alias "Internet"
        set ip 203.0.113.1 255.255.255.248
    next
    edit "port2"
        set alias "DMZ"
        set ip 172.16.100.1 255.255.255.0
    next
end
config system zone
    edit "WAN"
        set interface "port1"
    next
    edit "DMZ"
        set interface "port2"
    next
end
config firewall address
    edit "WEB-SERVER"
        set subnet 172.16.100.10 255.255.255.255
    next
end
config firewall service custom
    edit "WEB-HTTPS"
        set tcp-portrange 443
    next
end
config firewall policy
    edit 10
        set name "Internet-to-Web"
        set srcintf "WAN"
        set dstintf "DMZ"
        set srcaddr "all"
        set dstaddr "WEB-SERVER"
        set action accept
        set service "WEB-HTTPS"
        set nat enable
    next
end
config router static
    edit 1
        set dst 0.0.0.0 0.0.0.0
        set gateway 203.0.113.6
        set device "port1"
    next
end
""",
"panos01.set": """set deviceconfig system hostname panos01
set network interface ethernet ethernet1/1 layer3 ip 198.51.100.2/29
set network interface ethernet ethernet1/2 layer3 ip 10.20.0.1/24
set zone untrust network layer3 ethernet1/1
set zone trust network layer3 ethernet1/2
set address APP-NET ip-netmask 10.20.0.0/24
set address ADMIN ip-netmask 10.20.0.10/32
set address-group INTERNAL static [ APP-NET ADMIN ]
set service service-https protocol tcp port 443
set rulebase security rules OUTBOUND from trust
set rulebase security rules OUTBOUND to untrust
set rulebase security rules OUTBOUND source INTERNAL
set rulebase security rules OUTBOUND destination any
set rulebase security rules OUTBOUND application ssl
set rulebase security rules OUTBOUND service application-default
set rulebase security rules OUTBOUND action allow
set rulebase nat rules DNAT-WEB from untrust
set rulebase nat rules DNAT-WEB to untrust
set rulebase nat rules DNAT-WEB source any
set rulebase nat rules DNAT-WEB destination any
set rulebase nat rules DNAT-WEB service service-https
set rulebase nat rules DNAT-WEB destination-translation translated-address 10.20.0.20 translated-port 443
set network virtual-router default routing-table ip static-route default destination 0.0.0.0/0
set network virtual-router default routing-table ip static-route default nexthop ip-address 198.51.100.1
""",
"aoscx01.conf": """!Version ArubaOS-CX FL.10.13
hostname aoscx01
vlan 100
 name SERVER-CX
interface 1/1/1
 description Server uplink
 vlan access 100
interface vlan 100
 ip address 10.100.0.1/24
 apply access-list ip SERVER-IN in
access-list ip SERVER-IN
 10 permit tcp 10.100.0.0/24 any eq 443
 20 deny tcp 10.100.0.0/24 any eq 22
ip route 0.0.0.0/0 10.100.0.254
""",
"eos01.conf": """hostname eos01
service routing protocols model multi-agent
vlan 110
 name APP-EOS
interface Ethernet1
 description Application host
 switchport access vlan 110
interface Vlan110
 ip address 10.110.0.1/24
 ip access-group APP-IN in
ip access-list APP-IN
 10 permit tcp 10.110.0.0/24 any eq 8443
 20 deny ip 10.110.0.0/24 any
ip route 0.0.0.0/0 10.110.0.254
""",
"allied01.conf": """! AlliedWare Plus 5.5
hostname allied01
vlan 120 name MGMT-AW
interface port1.0.1
 switchport access vlan 120
interface vlan120
 ip address 10.120.0.1/24
 access-group MGMT-IN
access-list MGMT-IN permit tcp 10.120.0.0/24 any eq 22
access-list MGMT-IN deny ip 10.120.0.0/24 any
ip route 0.0.0.0/0 10.120.0.254
""",
"vyos01.set": """set system host-name 'vyos01'
set interfaces ethernet eth0 address '192.0.2.2/29'
set interfaces ethernet eth0 description 'WAN'
set interfaces ethernet eth1 address '10.130.0.1/24'
set interfaces ethernet eth1 description 'LAN'
set interfaces ethernet eth1 vif 130 address '10.130.130.1/24'
set firewall zone WAN interface 'eth0'
set firewall zone LAN interface 'eth1'
set firewall zone WAN from LAN firewall name 'LAN-TO-WAN'
set firewall ipv4 name LAN-TO-WAN rule 10 action 'accept'
set firewall ipv4 name LAN-TO-WAN rule 10 protocol 'tcp'
set firewall ipv4 name LAN-TO-WAN rule 10 source address '10.130.0.0/24'
set firewall ipv4 name LAN-TO-WAN rule 10 destination address 'any'
set firewall ipv4 name LAN-TO-WAN rule 10 destination port '443'
set nat source rule 100 source address '10.130.0.0/24'
set nat source rule 100 outbound-interface name 'eth0'
set nat source rule 100 translation address 'masquerade'
set protocols static route 0.0.0.0/0 next-hop '192.0.2.1'
"""
}
