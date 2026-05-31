import socket
import threading
import time
from typing import Callable, Optional

from .packet import parse_response


class Receiver:
    def __init__(self) -> None:
        self._pending: dict[int, tuple[float, int]] = {}  # seq -> (send_time, displayed_seq)
        self._lock = threading.Lock()
        self.running = True

    def register_send(self, sequence: int, displayed_seq: int) -> None:
        with self._lock:
            self._pending[sequence] = (time.perf_counter(), displayed_seq)

    def drain_timed_out(self, timeout_ms: float = 5000.0) -> list[int]:
        now = time.perf_counter()
        timed_out: list[int] = []
        with self._lock:
            expired = [
                seq for seq, (t, _) in self._pending.items()
                if (now - t) * 1000 > timeout_ms
            ]
            for seq in expired:
                _, displayed = self._pending.pop(seq)
                timed_out.append(displayed)
        return timed_out

    def start(self, sock: socket.socket, on_response: Callable[[bytes, int, float], None]) -> None:
        thread = threading.Thread(target=self._loop, args=(sock, on_response), daemon=True)
        thread.start()

    def stop(self) -> None:
        self.running = False

    def _loop(self, sock: socket.socket, on_response: Callable[[bytes, int, float], None]) -> None:
        while self.running:
            try:
                data, _ = sock.recvfrom(1024)
                parsed = parse_response(data)
                if parsed is None:
                    continue
                tag, seq = parsed
                recv_time = time.perf_counter()
                with self._lock:
                    entry = self._pending.pop(seq, None)
                if entry:
                    send_time, displayed_seq = entry
                    rtt_ms = (recv_time - send_time) * 1000
                    on_response(tag, displayed_seq, rtt_ms)
            except (socket.timeout, BlockingIOError, ConnectionResetError):
                continue
            except Exception:
                continue
