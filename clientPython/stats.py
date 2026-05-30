import math
import time


class RttStats:
    def __init__(self) -> None:
        self._rtts: list[float] = []

    def add(self, rtt_ms: float) -> None:
        self._rtts.append(rtt_ms)

    @property
    def received(self) -> int:
        return len(self._rtts)

    def print_summary(self, sent: int, start_time: float, host: str) -> None:
        elapsed_ms = (time.perf_counter() - start_time) * 1000
        loss = 100.0 * (1.0 - self.received / sent) if sent else 0.0
        print(f"\n--- {host} ping statistics ---")
        print(
            f"{sent} packets transmitted, {self.received} received, "
            f"{loss:.1f}% packet loss, time {elapsed_ms:.0f}ms"
        )
        if self.received > 0:
            min_rtt = min(self._rtts)
            avg_rtt = sum(self._rtts) / self.received
            max_rtt = max(self._rtts)
            mdev = math.sqrt(sum((x - avg_rtt) ** 2 for x in self._rtts) / self.received)
            print(
                f"rtt min/avg/max/mdev = "
                f"{min_rtt:.3f}/{avg_rtt:.3f}/{max_rtt:.3f}/{mdev:.3f} ms"
            )
