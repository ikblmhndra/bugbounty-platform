from collections import defaultdict
from threading import Lock
from time import monotonic


_target_locks: dict[str, Lock] = defaultdict(Lock)
_target_tokens: dict[str, tuple[float, int]] = {}


def acquire_target_lock(target_id: str) -> Lock:
    return _target_locks[target_id]


def allow_request(target_id: str, max_rps: int) -> bool:
    now = monotonic()
    ts, count = _target_tokens.get(target_id, (now, 0))
    if now - ts >= 1.0:
        _target_tokens[target_id] = (now, 1)
        return True
    if count >= max_rps:
        return False
    _target_tokens[target_id] = (ts, count + 1)
    return True
