/ip traffic-flow target remove [find dst-address=10.0.2.2 port=4739]
/ip traffic-flow target add dst-address=10.0.2.2 port=4739 version=ipfix

/ip traffic-flow set enabled=yes interfaces=all active-flow-timeout=1m inactive-flow-timeout=15s packet-sampling=yes sampling-interval=100 sampling-space=10000
