#!/usr/bin/python3

import socket
import struct

def run_server():
    host = ''
    port = 8443

    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
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
    run_server()
	
	