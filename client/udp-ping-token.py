#!/usr/bin/python3
import base64
import binascii
import ipaddress
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
                # print(f"data (len={len(data)}) {data} or hex {data.hex()}")
                if len(data) == 8:

                    # ! specifies network (big-endian) byte order.
                    # 4s specifies four bytes for the string.
                    # I specifies a 4-byte unsigned int for seq_res.
                    id_res, seq_res = struct.unpack('!4sI', data)
                    # print(f"parsed: id_res {id_res.hex()} seq {format(seq_res, 'x')}")
                    if id_res == b'RR01' or id_res == b'RE01':
                        current_time = time.perf_counter()
                        with self.lock:
                            send_info = self.sent_times.pop(seq_res, None)

                        if send_info:
                            send_time, displayed_seq, _ = send_info
                            rtt = (current_time - send_time) * 1000
                            self.received_count += 1
                            self.rtt_list.append(rtt)
                            if id_res == b'RR01':
                                print(f"Response from {self.server_host}: seq={displayed_seq} time={rtt:.3f} ms")
                            else:
                                print(f"Error response from {self.server_host}: seq={displayed_seq} time={rtt:.3f} ms")
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


                    if not args.token:

                        # Get current time (32-bit Unix time, big-endian)
                        current_time = int(time.time()) & 0xFFFFFFFF
                        time_bytes = struct.pack(">I", current_time)
                        time_bytes_for_hash = current_time.to_bytes(4, byteorder='big')

                        # Generate HMAC-SHA256 hash and truncate to 128 bits (16 bytes)
                        mac = hmac.new(self.seed.encode(), digestmod=hashlib.sha256)

                        # print(f"time_bytes {time_bytes.hex()}")
                        mac.update(time_bytes_for_hash)
                        packet_hash = mac.digest()[:8]  # Truncate to 64 bits
                        # print(f"Packet hash (hex): {packet_hash.hex()}")
                        # print(f"Packet hash full (hex): {mac.digest().hex()}")
                        try:
                            # Attempt to parse the input string as an IP address (either IPv4 or IPv6)
                            ip_obj = ipaddress.ip_address(self.source_ip)
                            if isinstance(ip_obj, ipaddress.IPv6Address):
                                source_ip_u128 = int(ipaddress.IPv6Address(ip_obj))
                            elif isinstance(ip_obj, ipaddress.IPv4Address):
                                source_ip_u128 = int(ipaddress.IPv4Address(ip_obj)) + 0xffff00000000
                            else:
                                source_ip_u128 = 0x0
                        except ValueError as e:
                            # Catch and report invalid IP address strings
                            print(f"Error: {e}")


                        # print(f"Source IP hex: {source_ip_u128:032x}")

                        mac_ip = hmac.new(self.seed.encode(), digestmod=hashlib.sha256)
                        mac_ip.update(time_bytes_for_hash)
                        mac_ip.update(source_ip_u128.to_bytes(16, byteorder='big'))
                        packet_ip_hash = mac_ip.digest()[:4]  # Truncate to 32 bits

                        # Construct the packet
                        # ! specifies network (big-endian) byte order.
                        # 4s specifies four bytes for the string.
                        # I specifies a 4-byte unsigned int for seq_res.
                        # B specifies a 1-byte unsigned char for status.
                        # 4s specifies four bytes for time_bytes (aka time)
                        # 8s specifies 8 bytes for packet_hash
                        # 4s specifies 4 bytes for packet_ip_hash
                        data = struct.pack('!4sI4s8s4s', b'RP01', sequence, time_bytes, packet_hash, packet_ip_hash)
                    else:
                        try:
                            mytoken = base64.b64decode(args.token)
                        except (ValueError, binascii.Error) as e:
                            print(f"Error decoding token: {e}")
                            exit(1)
                        if len(mytoken) != 16:
                            print("Token length invalid")
                            exit(1)
                        # print(f"Token (in hex): {mytoken.hex()}")
                        data = struct.pack('!4sI16s', b'RP01', sequence, mytoken)



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
    parser.add_argument("--host", required=True, help="Hostname of server")
    parser.add_argument("--port", type=int, default=444, help="Server port (default: 444)")
    parser.add_argument("--seed",  help="Seed")
    parser.add_argument("--ip", help="Source IP for HMAC calculation")
    parser.add_argument("--token", help="Base64 encoded token")
    args = parser.parse_args()

    # Check mutual exclusion
    if args.token and (args.seed or args.ip):
        parser.error("--token cannot be used with --seed or --ip")

    #  Ensure either token or both seed+ip are provided
    if not args.token and not (args.seed and args.ip):
        parser.error("either --token or both --seed and --ip are required")

    client = PingClient(args.host, args.port, args.seed, args.ip)
    client.run()
