/system identity set name=acc01

/ip dhcp-client remove [find]
/ip dhcp-client add interface=ether4 disabled=no add-default-route=yes

/interface bridge add name=bridge1 vlan-filtering=no dhcp-snooping=yes add-dhcp-option82=yes

/interface bridge port add bridge=bridge1 interface=ether2 trusted=no
/interface bridge port add bridge=bridge1 interface=ether3 trusted=no
/interface bridge port add bridge=bridge1 interface=ether1 trusted=yes

:do { /interface bridge port set [find interface=ether2] add-dhcp-option82=yes dhcp-snooping-circuit-id="acc01:eth2" } on-error={ :put "WARN: dhcp-snooping-circuit-id not accepted on ether2" }
:do { /interface bridge port set [find interface=ether3] add-dhcp-option82=yes dhcp-snooping-circuit-id="acc01:eth3" } on-error={ :put "WARN: dhcp-snooping-circuit-id not accepted on ether3" }

/ip address add address=10.10.10.2/24 interface=bridge1
