# UDP Ping Client/Server System

A Python implementation of a UDP-based ping client and server with systemd integration.
The server uses port 8443.

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
# Note: The default server port is 8443
python3 client/udp_client.py <server_ip> <server_port>
```

## Monitoring
```bash
journalctl -f -u udp-ping-server
```
