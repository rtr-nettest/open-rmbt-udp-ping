import base64
import binascii
import hashlib
import hmac
import ipaddress
import struct
import time


def _ip_to_128bit(ip_str: str) -> int:
    ip_obj = ipaddress.ip_address(ip_str)
    if isinstance(ip_obj, ipaddress.IPv6Address):
        return int(ip_obj)
    return int(ip_obj) + 0xffff00000000  # IPv4-mapped: ::ffff:a.b.c.d


def build_seed_packet(sequence: int, seed: str, source_ip: str) -> bytes:
    current_time = int(time.time()) & 0xFFFFFFFF
    time_bytes = struct.pack(">I", current_time)

    mac = hmac.new(seed.encode(), time_bytes, hashlib.sha256)
    time_hash = mac.digest()[:8]

    ip_u128 = _ip_to_128bit(source_ip)
    mac_ip = hmac.new(seed.encode(), digestmod=hashlib.sha256)
    mac_ip.update(time_bytes)
    mac_ip.update(ip_u128.to_bytes(16, byteorder='big'))
    ip_hash = mac_ip.digest()[:4]

    return struct.pack('!4sI4s8s4s', b'RP01', sequence, time_bytes, time_hash, ip_hash)


def build_token_packet(sequence: int, token: bytes) -> bytes:
    return struct.pack('!4sI16s', b'RP01', sequence, token)


def decode_token(token_b64: str) -> bytes:
    try:
        token = base64.b64decode(token_b64)
    except (ValueError, binascii.Error) as e:
        raise ValueError(f"invalid base64 token: {e}") from e
    if len(token) != 16:
        raise ValueError("token must be exactly 16 bytes")
    return token


def parse_response(data: bytes) -> tuple[bytes, int] | None:
    if len(data) != 8:
        return None
    tag, seq = struct.unpack('!4sI', data)
    if tag not in (b'RR01', b'RE01'):
        return None
    return tag, seq
