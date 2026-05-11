/system identity set name=acc01

/ip dhcp-client remove [find]
/ip dhcp-client add interface=ether4 disabled=no add-default-route=no

/ip address add address=10.10.10.2/24 interface=ether1
/ip address add address=192.168.10.1/24 interface=ether2
/ip address add address=192.168.20.1/24 interface=ether3

/ip dhcp-relay add name=line-a interface=ether2 dhcp-server=192.168.99.2 local-address=192.168.10.1 add-relay-info=yes relay-info-remote-id="ether2" disabled=no
/ip dhcp-relay add name=line-b interface=ether3 dhcp-server=192.168.99.2 local-address=192.168.20.1 add-relay-info=yes relay-info-remote-id="ether3" disabled=no

/ip route add dst-address=0.0.0.0/0 gateway=10.10.10.1
/ip route add dst-address=192.168.99.0/24 gateway=10.10.10.1
