# 2026-10-05 07:07:53 by RouterOS 7.23.7
#
/interface ethernet
set [ find default-name=ether1 ] disable-running-check=no
set [ find default-name=ether2 ] disable-running-check=no
set [ find default-name=ether3 ] disable-running-check=no
/ip address
add address=10.44.1.1/24 interface=ether1 network=10.44.1.0
add address=10.44.9.1/24 interface=ether2 network=10.44.9.0
add address=10.44.2.1/24 interface=ether3 network=10.44.2.0
/ip firewall filter
add action=accept chain=forward comment=return connection-state=\
    established,related
add action=accept chain=forward comment=office-https dst-address=10.44.9.0/24 \
    dst-port=443 in-interface=ether1 out-interface=ether2 protocol=tcp
add action=drop chain=forward comment=default-deny
/ip firewall nat
add action=dst-nat chain=dstnat comment=web-vip dst-address=10.44.1.100 \
    dst-port=8443 in-interface=ether1 protocol=tcp to-addresses=10.44.9.20 \
    to-ports=443
/system identity
set name=routeros-lab
