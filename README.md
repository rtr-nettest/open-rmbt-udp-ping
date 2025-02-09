# UDP Ping Client/Server System


*This code is not ready for production use*.

A Python implementation of a UDP-based ping client and server with systemd integration.
The default server UDP port is 444.

## Features
- Client with precise timing
- Server with validation and logging
- Systemd service integration

## Installation

1. Clone the repository:
```bash
mkdir /opt
cd /opt
git clone https://github.com/rtr-nettest/open-rmbt-udp-ping.git
cd /open-rmbt-udp-ping
```

2. Server deployment with systemd:

```bash
useradd udp_ping
cp systemd/open-rmbt-udp-ping.service /etc/systemd/system/
systemctl daemon-reload
systemctl enable open-rmbt-udp-ping 
systemctl start open-rmbt-udp-ping
```


## Client
```bash
python3 client/udp_ping_client.py <server_ip> <server_port>
```

## Monitoring
```bash
journalctl -f -u open-rmbt-udp-ping --lines=200
```
