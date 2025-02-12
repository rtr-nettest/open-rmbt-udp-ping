# UDP Ping Client/Server System


*This code is not ready for production use*.

A Rust implementation of a UDP-based Ping server with a Python client implementation.
The default server UDP port is 444.

## Server Features
- Batch processing
- Multi-Threaded
- Supports CPU-pinning
- Authentication using sha256 HMAC

## Client Features
- Client with precise timing
- Authentication using sha256 HMAC

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
UDP Ping Server 0.1.0

USAGE:
    udp_server [OPTIONS]

FLAGS:
    -h, --help       Prints help information
    -V, --version    Prints version information

OPTIONS:
    -c, --cpus <CPUS>    CPU cores to use (e.g. 5-8 or 5,6,7,8)
    -s, --seed <SEED>    Sets the HMAC-SHA256 seed
```

```bash
cd rust-server
cargo build 
# Note --release currently fails, to be debugged
target/release/udp_server -c 0-1 -s topsecret
```

## Client
```
udp-ping-token.py [-h] [--host HOST] [--port PORT] --seed SEED --ip IP
```
IP is the IP of the client (source address to the server)

Normally the SEED (shared secret) is set in the RMBTControlServer and the same seed is configured
on the UDP server. To make this client independent of the ecosystem, it also includes the token generation,
thus IP and SEED need to be specified. In normal operation, the client would just forward the token received
from the RMBTControlServer

```bash
python3 client/udp_ping_token.py --host udp.example.com --port 444 --seed topsecret  --ip 1.2.3.4
```

Sample output
```
[...]
Response from udp.example.com: seq=11 time=9.960 ms
Response from udp.example.com: seq=12 time=10.548 ms

--- ping statistics ---
12 packets transmitted, 12 received, 0.0% packet loss, time 11079ms
rtt min/avg/max/mdev = 8.074/10.919/16.419/2.133 ms
```





