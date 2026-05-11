/system identity set name=core01

/ip dhcp-client remove [find]
/ip dhcp-client add interface=ether2 disabled=no add-default-route=yes

/ip address add address=10.10.10.1/24 interface=ether1
/ip address add address=192.168.99.1/24 interface=ether3

/ip route add dst-address=192.168.10.0/24 gateway=10.10.10.2
/ip route add dst-address=192.168.20.0/24 gateway=10.10.10.2

/ip firewall nat add chain=srcnat out-interface=ether2 action=masquerade
