#!/usr/bin/python3
import base64
import ipaddress
import struct
import time

import hmac
import hashlib
import sys
from argparse import ArgumentParser
from datetime import datetime



def generate_token(seed, source_ip):
    try:
        ip_obj = ipaddress.ip_address(source_ip)
        if ip_obj.version == 6:
            source_ip_u128 = int(ip_obj)
        else:
            source_ip_u128 = int(ip_obj) + 0xffff00000000  # Convert IPv4 to IPv4-mapped IPv6
    except ValueError as e:
        print(f"Error: Invalid IP address - {e}")
        sys.exit(1)

    current_time = int(time.time()) & 0xFFFFFFFF
    time_obj = datetime.fromtimestamp(current_time)

    print("Current time:", time_obj.strftime("%Y-%m-%d %H:%M:%S"))
    time_bytes = struct.pack(">I", current_time)
    time_bytes_for_hash = current_time.to_bytes(8, byteorder='big')
    print(f"time hex {time_bytes.hex()}")

    # Generate HMAC with seed
    mac = hmac.new(seed.encode(), time_bytes_for_hash, hashlib.sha256)
    packet_hash = mac.digest()[:8]

    # Generate HMAC with source IP
    ip_key = source_ip_u128.to_bytes(16, byteorder='big')
    mac_ip = hmac.new(ip_key, time_bytes_for_hash, hashlib.sha256)
    packet_ip_hash = mac_ip.digest()[:4]

    # Construct the packet
    sequence = 1
    data = struct.pack('4s8s4s',time_bytes, packet_hash, packet_ip_hash)
    print(f"Original token (in hex): {data.hex()}")
    b64_token = base64.b64encode(data).decode('utf-8')
    print(f"Token (Base64): {b64_token}")
    return data

if __name__ == '__main__':
    parser = ArgumentParser(description="Token generator")
    parser.add_argument("--seed", required=True, help="Seed value for HMAC")
    parser.add_argument("--ip", required=True, help="Source IP address")
    args = parser.parse_args()

    generate_token(args.seed, args.ip)