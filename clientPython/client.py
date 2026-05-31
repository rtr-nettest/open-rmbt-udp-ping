import random
import signal
import socket
import sys
import time

from .packet import build_seed_packet, build_token_packet, decode_token
from .receiver import Receiver
from .stats import RttStats


class PingClient:
    def __init__(
        self,
        host: str,
        port: int,
        *,
        seed: str | None = None,
        source_ip: str | None = None,
        token: str | None = None,
    ) -> None:
        self._host = host
        self._port = port
        self._seed = seed
        self._source_ip = source_ip
        self._token_bytes = decode_token(token) if token else None

        self._receiver = Receiver()
        self._stats = RttStats()
        self._sent_count = 0
        self._seq_base = random.getrandbits(32)
        self._start_time = time.perf_counter()

        signal.signal(signal.SIGINT, self._handle_sigint)

    def _handle_sigint(self, signum: int, frame: object) -> None:
        self._receiver.stop()
        self._stats.print_summary(self._sent_count, self._start_time, self._host)
        sys.exit(0)

    def _on_response(self, tag: bytes, displayed_seq: int, rtt_ms: float) -> None:
        self._stats.add(rtt_ms)
        label = "Response" if tag == b'RR01' else "Error response"
        print(f"{label} from {self._host}: seq={displayed_seq} time={rtt_ms:.3f} ms")

    def _build_packet(self, sequence: int) -> bytes:
        if self._token_bytes is not None:
            return build_token_packet(sequence, self._token_bytes)
        return build_seed_packet(sequence, self._seed, self._source_ip)  # type: ignore[arg-type]

    def run(self) -> None:
        try:
            addr_info = socket.getaddrinfo(
                self._host, self._port, socket.AF_UNSPEC, socket.SOCK_DGRAM
            )
        except socket.gaierror:
            print(f"Error: unable to resolve host {self._host}")
            sys.exit(1)

        family = next((r[0] for r in addr_info if r[1] == socket.SOCK_DGRAM), socket.AF_INET)

        with socket.socket(family, socket.SOCK_DGRAM) as sock:
            sock.settimeout(0.1)
            self._receiver.start(sock, self._on_response)

            try:
                while True:
                    sequence = (self._seq_base + self._sent_count) % (1 << 32)
                    displayed_seq = self._sent_count + 1
                    self._receiver.register_send(sequence, displayed_seq)

                    try:
                        sock.sendto(self._build_packet(sequence), (self._host, self._port))
                    except OSError as e:
                        print(f"Error sending data: {e}")

                    self._sent_count += 1

                    for displayed in self._receiver.drain_timed_out():
                        print(f"No response from {self._host}: seq={displayed}")

                    time.sleep(1)
            except KeyboardInterrupt:
                self._receiver.stop()
                self._stats.print_summary(self._sent_count, self._start_time, self._host)
