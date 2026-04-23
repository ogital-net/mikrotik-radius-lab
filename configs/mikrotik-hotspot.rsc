# WAN - DHCP client (internet via QEMU NAT)
/ip dhcp-client add interface=ether1 disabled=no add-default-route=yes

# LAN - static IP for HotSpot
/ip address add address=192.168.88.1/24 interface=ether2

# DNS
/ip dns set allow-remote-requests=yes servers=8.8.8.8,8.8.4.4

# DHCP server for HotSpot clients
/ip pool add name=hotspot-pool ranges=192.168.88.10-192.168.88.254
/ip dhcp-server add name=dhcp-lan interface=ether2 address-pool=hotspot-pool disabled=no
/ip dhcp-server network add address=192.168.88.0/24 gateway=192.168.88.1 dns-server=192.168.88.1

# NAT masquerade
/ip firewall nat add chain=srcnat out-interface=ether1 action=masquerade

# RADIUS server (host machine via QEMU NAT gateway = 10.0.2.2)
/radius add service=hotspot address=10.0.2.2 secret=secret authentication-port=1812

# HotSpot profile + server
/ip hotspot profile add name=hsprof1 hotspot-address=192.168.88.1 dns-name=hotspot.lab login-by=http-pap use-radius=yes
/ip hotspot add name=hs1 interface=ether2 address-pool=hotspot-pool profile=hsprof1 disabled=no

# Walled garden: allow unauthenticated clients to reach the portal web server (host)
/ip hotspot walled-garden ip add dst-address=10.0.2.2 dst-port=8080 protocol=tcp action=accept
