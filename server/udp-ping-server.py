#!/usr/bin/python3

import socket
import struct
import sys


def run_server(port):
    host = '::'  # Dual-stack binding

    sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)

    # Attempt to allow dual-stack if the system supports it
    try:
        sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
    except (AttributeError, OSError):
        # If the platform does not support disabling IPV6_V6ONLY, continue
        pass

    sock.bind((host, port))

    print(f"Server listening on port {port}")

    while True:
        data, addr = sock.recvfrom(1024)
        if len(data) < 14:
            continue

        try:
            id_req, seq, fixed_str = struct.unpack('!4sI6s', data)
        except struct.error:
            continue

        if id_req == b'RP01' and fixed_str == b'testme':
            print(f"Debug: Received sequence number {seq}")
            response = struct.pack('!4sI', b'RR01', seq)
            sock.sendto(response, addr)


if __name__ == '__main__':
    if len(sys.argv) > 2:
        print(f"Usage: python {sys.argv[0]} port")
        sys.exit(1)

    server_port = 444
    if len(sys.argv) == 2:
        try:
            server_port = int(sys.argv[1])
            if not 1 <= server_port <= 65535:
                raise ValueError
        except ValueError:
            print("Invalid port number, using default 444")
            server_port = 444

    run_server(server_port)
