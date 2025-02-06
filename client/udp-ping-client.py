#!/usr/bin/python3

import socket
import struct
import time
import random
import threading

def run_client(server_host, server_port):
    sequence = random.getrandbits(32)
    sent_times = {}
    lock = threading.Lock()

    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.settimeout(0.1)

        def receiver():
            while True:
                try:
                    data, _ = sock.recvfrom(1024)
                    if len(data) == 8:
                        id_res, seq_res = struct.unpack('!4sI', data)
                        if id_res == b'RR01':
                            with lock:
                                send_time = sent_times.pop(seq_res, None)
                            if send_time:
                                rtt = (time.time() - send_time) * 1000
                                if rtt <= 5000:
                                    print(f"{rtt:.3f}")
                except (socket.timeout, BlockingIOError):
                    continue
                except Exception as e:
                    break

        threading.Thread(target=receiver, daemon=True).start()

        try:
            while True:
                with lock:
                    sent_times[sequence] = time.time()
                data = struct.pack('!4sI6s', b'RP01', sequence, b'testme')
                sock.sendto(data, (server_host, server_port))
                sequence = (sequence + 1) % (1 << 32)
                time.sleep(1)
        except KeyboardInterrupt:
            print("\nClient stopped")

if __name__ == '__main__':
    import sys
    if len(sys.argv) != 3:
        print("Usage: python udp_client.py <server_ip> <server_port>")
        sys.exit(1)
    run_client(sys.argv[1], int(sys.argv[2]))
    