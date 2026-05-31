#!/usr/bin/env python3
"""Minimal cross-platform UDP test server — responds to RP01 with RE01 (no seed validation)."""
import hashlib
import hmac
import socket
import struct
import sys


def process(data: bytes, seed: bytes | None) -> bytes | None:
    if len(data) != 24 or data[:4] != b'RP01':
        return None
    seq = data[4:8]
    if seed:
        packet_time = data[8:12]
        mac = hmac.new(seed, packet_time, hashlib.sha256)
        if mac.digest()[:8] != data[12:20]:
            print("  HMAC mismatch — dropping", flush=True)
            return None
        return b'RR01' + seq
    return b'RE01' + seq


def main() -> None:
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 44444
    seed_str = sys.argv[2] if len(sys.argv) > 2 else None
    seed = seed_str.encode() if seed_str else None

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(('127.0.0.1', port))
    print(f"Test server on 127.0.0.1:{port}  seed={'<none>' if seed is None else repr(seed_str)}", flush=True)

    while True:
        data, addr = sock.recvfrom(1024)
        resp = process(data, seed)
        if resp:
            seq_num = struct.unpack('>I', data[4:8])[0]
            print(f"  {data[:4].decode()} seq={seq_num} -> {resp[:4].decode()}", flush=True)
            sock.sendto(resp, addr)


if __name__ == '__main__':
    main()
