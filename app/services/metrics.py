from collections import defaultdict


class MetricsStore:
    def __init__(self) -> None:
        self.counters = defaultdict(int)

    def inc(self, key: str, value: int = 1) -> None:
        self.counters[key] += value

    def snapshot(self) -> dict[str, int]:
        return dict(self.counters)


metrics_store = MetricsStore()
