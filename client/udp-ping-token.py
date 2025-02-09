#!/usr/bin/python3
import socket
import struct
import time
import random
import threading
import signal
import math
import sys
import hmac
import hashlib
from argparse import ArgumentParser


class PingClient:
    def __init__(self, server_host, server_port, seed, source_ip):
        self.server_host = server_host
        self.server_port = server_port
        self.seed = seed
        self.source_ip = source_ip
        self.initial_sequence = random.getrandbits(32)
        self.sent_count = 0
        self.received_count = 0
        self.rtt_list = []
        self.sent_times = {}
        self.lock = threading.Lock()
        self.start_time = time.perf_counter()
        self.running = True

        signal.signal(signal.SIGINT, self.signal_handler)

    def signal_handler(self, signum, frame):
        self.running = False
        self.print_statistics()
        sys.exit(0)

    def print_statistics(self):
        total_time = (time.perf_counter() - self.start_time) * 1000
        print("\n--- ping statistics ---")
        loss = 100 * (1 - self.received_count / self.sent_count) if self.sent_count else 0
        print(f"{self.sent_count} packets transmitted, {self.received_count} received, "
              f"{loss:.1f}% packet loss, time {total_time:.0f}ms")

        if self.received_count > 0:
            min_rtt = min(self.rtt_list)
            avg_rtt = sum(self.rtt_list) / len(self.rtt_list)
            max_rtt = max(self.rtt_list)
            stddev = math.sqrt(sum((x - avg_rtt) ** 2 for x in self.rtt_list) / len(self.rtt_list))
            print(f"rtt min/avg/max/mdev = {min_rtt:.3f}/{avg_rtt:.3f}/"
                  f"{max_rtt:.3f}/{stddev:.3f} ms")

    def receiver(self, sock):
        while self.running:
            try:
                data, _ = sock.recvfrom(1024)
                if len(data) == 8:
                    id_res, seq_res = struct.unpack('!4sI', data)
                    if id_res == b'RR01':
                        current_time = time.perf_counter()
                        with self.lock:
                            send_info = self.sent_times.pop(seq_res, None)

                        if send_info:
                            send_time, displayed_seq, _ = send_info
                            rtt = (current_time - send_time) * 1000
                            self.received_count += 1
                            self.rtt_list.append(rtt)

                            print(f"Response from {self.server_host}: seq={displayed_seq} time={rtt:.3f} ms")
            except (socket.timeout, BlockingIOError):
                continue
            except ConnectionResetError:
                continue
            except Exception:
                continue

    def cleanup(self):
        current_time = time.perf_counter()
        with self.lock:
            timed_out_seqs = [seq for seq, (_, displayed_seq, start_time) in self.sent_times.items()
                              if (current_time - start_time) * 1000 > 5000]
            for seq in timed_out_seqs:
                _, displayed_seq, _ = self.sent_times.pop(seq)
                print(f"No response from {self.server_host}: seq={displayed_seq}")

    def run(self):
        try:
            addr_info = socket.getaddrinfo(self.server_host, self.server_port, socket.AF_UNSPEC, socket.SOCK_DGRAM)
        except socket.gaierror:
            print(f"Error: Unable to resolve host {self.server_host}")
            sys.exit(1)

        family = None
        for res in addr_info:
            if res[1] == socket.SOCK_DGRAM:
                family = res[0]
                break

        with socket.socket(family, socket.SOCK_DGRAM) as sock:
            sock.settimeout(0.1)
            threading.Thread(target=self.receiver, args=(sock,), daemon=True).start()

            try:
                while self.running:
                    sequence = (self.initial_sequence + self.sent_count) % (1 << 32)
                    displayed_seq = self.sent_count + 1

                    with self.lock:
                        self.sent_times[sequence] = (time.perf_counter(), displayed_seq, time.perf_counter())

                    # Get current time (32-bit Unix time, big-endian)
                    current_time = int(time.time()) & 0xFFFFFFFF
                    time_bytes =  struct.pack(">I", current_time)
                    time_bytes_for_hash = current_time.to_bytes(8, byteorder='big')

                    # Generate HMAC-SHA256 hash and truncate to 128 bits (16 bytes)
                    mac = hmac.new(self.seed.encode(), digestmod=hashlib.sha256)
                    # debug - do not update, just use seed

                    # Convert the string to bytes
                    source_ip_bytes = self.source_ip.encode('utf-8')

                    # Convert bytes to hex representation and join them into a single string
                    source_ip_hex = ''.join(f'{byte:02x}' for byte in source_ip_bytes)


                    # print(f"source ip in hex {source_ip_hex}")
                    mac.update(self.source_ip.encode())
                    # print(f"time_bytes {time_bytes.hex()}")
                    mac.update(time_bytes_for_hash)
                    packet_hash = mac.digest()[:16]  # Truncate to 128 bits
                    # print(f"Packet hash (hex): {packet_hash.hex()}")
                    # print(f"Packet hash full (hex): {mac.digest().hex()}")

                    # Construct the packet
                    data = struct.pack('!4sI4s16s', b'RP01', sequence, time_bytes, packet_hash)
                    # print(f"Sending {len(data)}")

                    try:
                        sock.sendto(data, (self.server_host, self.server_port))
                    except OSError as e:
                        print(f"Error sending data: {e}")
                    self.sent_count += 1

                    self.cleanup()  # Check for timeouts
                    time.sleep(1)
            except KeyboardInterrupt:
                self.running = False
                self.print_statistics()


if __name__ == '__main__':
    parser = ArgumentParser(description="UDP Ping Client with HMAC-SHA256 validation")
    parser.add_argument("--host", help="Hostname of server")
    parser.add_argument("--port", type=int, default=444, help="Server port (default: 444)")
    parser.add_argument("--seed", required=True, help="Seed")
    parser.add_argument("--ip", required=True, help="Source IP for HMAC calculation")
    args = parser.parse_args()

    client = PingClient(args.host, args.port, args.seed, args.ip)
    client.run()