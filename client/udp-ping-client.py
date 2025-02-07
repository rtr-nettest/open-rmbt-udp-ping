#!/usr/bin/python3
import socket
import struct
import time
import random
import threading
import signal
import math
import sys


class PingClient:
    def __init__(self, server_host, server_port):
        self.server_host = server_host
        self.server_port = server_port
        self.initial_sequence = random.getrandbits(32)
        self.sent_count = 0
        self.received_count = 0
        self.rtt_list = []
        self.sent_times = {}
        self.lock = threading.Lock()
        self.start_time = time.time()
        self.running = True

        signal.signal(signal.SIGINT, self.signal_handler)

    def signal_handler(self, signum, frame):
        self.running = False
        self.print_statistics()
        sys.exit(0)

    def print_statistics(self):
        total_time = (time.time() - self.start_time) * 1000
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
                        current_time = time.time()
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

    def cleanup(self):
        current_time = time.time()
        with self.lock:
            timed_out_seqs = [seq for seq, (_, displayed_seq, start_time) in self.sent_times.items()
                              if (current_time - start_time) * 1000 > 5000]
            for seq in timed_out_seqs:
                _, displayed_seq, _ = self.sent_times.pop(seq)
                print(f"No response from {self.server_host}: seq={displayed_seq}")

    def run(self):
        addr_info = socket.getaddrinfo(self.server_host, self.server_port, socket.AF_UNSPEC, socket.SOCK_DGRAM)
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
                        self.sent_times[sequence] = (time.time(), displayed_seq, time.time())

                    data = struct.pack('!4sI6s', b'RP01', sequence, b'testme')
                    sock.sendto(data, (self.server_host, self.server_port))
                    self.sent_count += 1

                    self.cleanup()  # Check for timeouts
                    time.sleep(1)
            except KeyboardInterrupt:
                self.running = False
                self.print_statistics()


if __name__ == '__main__':
    if len(sys.argv) < 2 or len(sys.argv) > 3:
        print(f"Usage: python {sys.argv[0]} <server_ip> [port]")
        sys.exit(1)

    server_port = 444
    if len(sys.argv) == 3:
        try:
            server_port = int(sys.argv[2])
            if not 1 <= server_port <= 65535:
                raise ValueError
        except ValueError:
            print("Invalid port number, using default 444")
            server_port = 444

    client = PingClient(sys.argv[1], server_port)
    client.run()