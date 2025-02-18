# UDP Ping Client/Server System

A Rust implementation of a UDP-based Ping server with a Python demo client implementation.
The default server UDP port is 444.

## Server Features
- Batch processing
- Multi-Threaded
- Supports CPU-pinning
- Authentication using sha256 HMAC
- Linux only (not portable to osX or Windows)

## Client Features
- Client with precise timing
- Authentication using sha256 HMAC based token

## Installation

1. Clone the repository:
```bash
mkdir /opt
cd /opt
git clone https://github.com/rtr-nettest/open-rmbt-udp-ping.git
cd /open-rmbt-udp-ping
```

## Rust server

```
UDP Ping Server 1.0.0

USAGE:
    udp_server [OPTIONS]

FLAGS:
    -h, --help       Prints help information
    -V, --version    Prints version information

OPTIONS:
    -d, --debug      Enable debug logging
    -c, --cpus <CPUS>    CPU cores to use (e.g. 5-8 or 5,6,7,8)
    -s, --seed <SEED>    Sets the HMAC-SHA256 seed
    -
```

The debug logging can also be enabled or disabled during runtime using signal `SIGUSR1`.

```bash
cd rust-server

# get rust
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# get build-essential
apt -y install build-essential

cd rust-server
# build
cargo build --release
# install 
cp target/release/udp_server /usr/local/bin 
# manual start
udp_server -c 0-1 -s topsecret

```
Format:
- Request: as '!4sI4s8s4s' using: 'RP01', sequence, time_bytes, packet_hash, packet_ip_hash
- Response: as '!4sI' using: 'RR01', sequence
- IP error response: as '!4sI' using: 'RE01', sequence


```
### Sample debug output
[2025-02-12T08:18:59Z DEBUG udp_server] Received (len=24): 5250303149e8964b67ac5975c44138a21867e72c07f4136c
[2025-02-12T08:18:59Z DEBUG udp_server] HMAC packet: c44138a21867e72c
[2025-02-12T08:18:59Z DEBUG udp_server] HMAC packet matches
[2025-02-12T08:18:59Z DEBUG udp_server] Source address: ::ffff:62.1.2.3 in hex 00000000000000000000ffff3e010203
[2025-02-12T08:18:59Z DEBUG udp_server] HMAC IP: 07f4136c
[2025-02-12T08:18:59Z DEBUG udp_server] Own HMAC IP: 07f4136c
[2025-02-12T08:18:59Z DEBUG udp_server] HMAC IP matches
[2025-02-12T08:18:59Z DEBUG udp_server] Sending response: 5252303149e8964b
```

### Service for systemd

```bash
useradd udp_ping
cp systemd/open-rmbt-udp-ping.service /lib/systemd/system/
systemctl daemon-reload
systemctl start open-rmbt-udp-ping
# check status
systemctl status open-rmbt-udp-ping
# enable service  
systemctl enable open-rmbt-udp-ping
```

## Utility
```
makeToken.py --seed SEED --ip IP
```
This utility can be used to prepare a token (e.g. `Z7QxVTGtS3CGMZ2BzuEkag==`)

IP is the IP of the client (source address to the server)
SEED is the shared secret to authenticate against the UDP server. In normal operatioon, the shared secret is set 
in the RMBTControlServer and the same seed is configured on the UDP server.

## Client
```
udp-ping-token.py [-h] --host HOST [--port PORT] --token TOKEN  
udp-ping-token.py [-h] --host HOST [--port PORT] --seed SEED --ip IP
```
The client can use a prepared TOKEN (first variant of command line options) or generate the token itself, in that 
case SEED and IP must be provided.

Example:
```bash
python3 client/udp_ping_token.py --host udp.example.com --port 444 --seed topsecret  --ip 1.2.3.4
```

### Sample client output
```
[...]
Response from udp.example.com: seq=11 time=9.960 ms
Response from udp.example.com: seq=12 time=10.548 ms

--- ping statistics ---
12 packets transmitted, 12 received, 0.0% packet loss, time 11079ms
rtt min/avg/max/mdev = 8.074/10.919/16.419/2.133 ms
```





