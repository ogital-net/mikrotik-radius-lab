/system identity set name=core01

/ip dhcp-client remove [find]
/ip dhcp-client add interface=ether2 disabled=no add-default-route=yes

/ip address add address=192.168.50.1/24 interface=ether1
/ip address add address=192.168.10.1/24 interface=ether1
/ip address add address=192.168.20.1/24 interface=ether1

/ip pool add name=lab-pool-50 ranges=192.168.50.100-192.168.50.200

/ip dhcp-server add name=dhcp-core interface=ether1 use-radius=yes lease-time=10m disabled=no
:do { /ip dhcp-server set [find name=dhcp-core] support-broadband-tr101=yes } on-error={ :put "WARN: support-broadband-tr101 not accepted on this RouterOS version" }

/ip dhcp-server network add address=192.168.50.0/24 gateway=192.168.50.1 dns-server=8.8.8.8,8.8.4.4
/ip dhcp-server network add address=192.168.10.0/24 gateway=192.168.10.1 dns-server=8.8.8.8,8.8.4.4
/ip dhcp-server network add address=192.168.20.0/24 gateway=192.168.20.1 dns-server=8.8.8.8,8.8.4.4

/radius add service=dhcp address=10.0.2.2 secret=secret authentication-port=1812 accounting-port=1813 timeout=3s

/ip firewall nat add chain=srcnat out-interface=ether2 action=masquerade
