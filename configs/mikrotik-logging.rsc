/system logging remove [find action=cefremote]
/system logging action remove [find name=cefremote]

/system logging remove [find action=syslogremote]
/system logging action remove [find name=syslogremote]
/system logging action add name=syslogremote target=remote remote=10.0.2.2 remote-port=5140 remote-log-format=syslog syslog-time-format=iso8601 syslog-facility=local0
/system logging add topics=firewall action=syslogremote

/ip firewall filter remove [find log-prefix="conn-new"]
/ip firewall filter add chain=forward connection-state=new action=log log-prefix="conn-new" place-before=0
