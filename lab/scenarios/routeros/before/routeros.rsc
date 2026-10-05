# RouterOS 7 synthetic acceptance laboratory
/system identity
set name=routeros-lab
/ip address
add address=10.44.1.1/24 interface=ether1
add address=10.44.9.1/24 interface=ether2
add address=10.44.2.1/24 interface=ether3
/ip firewall filter
add chain=forward action=accept connection-state=established,related comment=return
add chain=forward action=accept in-interface=ether1 out-interface=ether2 protocol=tcp dst-address=10.44.9.0/24 dst-port=443 comment=office-https
add chain=forward action=drop comment=default-deny
/ip firewall nat
add chain=dstnat action=dst-nat in-interface=ether1 protocol=tcp dst-address=10.44.1.100 dst-port=8443 to-addresses=10.44.9.20 to-ports=443 comment=web-vip
