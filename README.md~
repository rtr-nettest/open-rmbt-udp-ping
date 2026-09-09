# UDP Ping Client/Server System

A Rust implementation of a UDP-based Ping server with a Python demo client implementation.
The default server UDP port is 444.

## Server Features
- Batch processing
- Multi-Threaded
- Supports CPU-pinning
- Authentication using sha256 HMAC

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
UDP Ping Server 2.0.1

USAGE:
    udp_server [OPTIONS]

FLAGS:
    -h, --help       Prints help information
    -V, --version    Prints version information

OPTIONS:
  -s, --secret <SECRET>     HMAC-SHA256 shared secret (visible in process list — prefer --secret-file)
  -f, --secret-file <PATH>  File with HMAC-SHA256 shared secrets, one per line: '<secret>[ <label>]'
  -b, --bind <ADDR>         IP address to listen on; may be repeated (default: all interfaces)
  -t, --threads <N>         Total worker threads shared across all sockets (default: logical CPU count)
  -d, --debug               Enable debug logging at startup (also toggled at runtime via SIGUSR1 on Unix)
  -p, --port <PORT>         UDP port to listen on (default: 444)
      --syslog <TARGET>     Send structured RFC 5424 logs over UDP to TARGET (IP or IP:port; port default 514)
  -h, --help                Print help
  -V, --version             Print version

```

Shared secrets are configured with `--secret` and/or `--secret-file`. A secret file holds one
secret per line in the format `<secret>[ <label>]`; the secret is whitespace-trimmed, the label
is optional, blank lines and lines starting with `#` are ignored. Secrets without a label are
named `secret_1`, `secret_2`, … by position. When both options are given, the `--secret` value is
`secret_1` and the file's secrets follow. With no secret configured, packets are not authenticated.

### Logging

The server has two independent logging channels: human-readable lines on **stderr** (captured by
systemd/journald) and, optionally, **structured events** sent to a remote collector for ELK.

#### Local logging (stderr)

Each line has the format `<unix-seconds> [LEVEL] <message>`, for example:

```text
1739347139 [INFO] Listening on 127.0.0.1, port 444
1739347139 [INFO] 1 socket(s), one blocking thread per socket
```

`ERROR`, `WARN` and `INFO` are always shown. `DEBUG` and `TRACE` (per-packet timing and HMAC
details) are emitted only when debug logging is enabled — at startup with `-d`/`--debug`, or
toggled at runtime on Unix by sending `SIGUSR1` (see [Debug logging](#debug-logging)).

#### Structured event logging (ELK)

`--syslog <IP[:port]>` (off by default, port defaults to 514) ships structured events to a
collector as UDP **RFC 5424** datagrams with a JSON message body, which ingest directly into
ELK (Logstash syslog input + `json` filter). Logging is fire-and-forget and never blocks packet
handling. Events:

- `startup` — version, bound addresses, port, secret count.
- `error` — bind / `recv_from` / `send_to` failures.
- `good_ping` — a successful authenticated ping; rate-limited to the first per source IP per
  minute to bound volume.
- `auth_fail` — no configured secret matched the packet (rate-limited per second).
- `ip_mismatch` — the secret matched but the source-IP HMAC did not (typically the client's IP
  changed via NAT/roaming, not an attack; rate-limited per second).

Example datagram:

```text
<134>1 2026-06-21T06:32:38.974Z host udp_server 33444 auth - {"event":"good_ping","src":"127.0.0.1","secret":"secret_1"}
```

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


### Sample debug output

With debug logging enabled, each received packet produces a trace such as:

```text
1739347139 [DEBUG] Received (len=24): 5250303149e8964b67ac5975c44138a21867e72c07f4136c
1739347139 [DEBUG] Time difference: 0.123 s
1739347139 [DEBUG] Source address: ::ffff:62.1.2.3 (00000000000000000000ffff3e010203)
1739347139 [DEBUG] HMAC packet received=c44138a21867e72c expected=c44138a21867e72c
1739347139 [TRACE] Secret matched: secret_1
1739347139 [DEBUG] HMAC IP received=07f4136c expected=07f4136c
1739347139 [DEBUG] Sending response: 5252303149e8964b
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

### Debug logging

Enable or Disable debug logging:
```
pkill -SIGUSR1 udp_server
```
Follow log in systemd:
```
journalctl -fu open-rmbt-udp-ping
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





