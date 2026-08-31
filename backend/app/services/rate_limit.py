"""In-process sliding-window rate limiting (Phase 12, F3).

Before this existed there was no throttle of any kind: 150 concurrent
requests from the lowest-privilege role were all served, and the endpoints
that cost real money -- `investigate` (4 Groq calls) and `enrichment` (4
threat-intel provider calls) -- were reachable in a loop by any analyst.

**Deliberate scope, stated plainly.** This keeps its counters in process
memory. That is genuinely effective here because the app runs as a single
uvicorn process, but it means limits reset on restart and would NOT be
shared across workers if this were ever deployed multi-process. The
correct fix at that point is a shared store (Redis) or a limiter at the
reverse proxy; this is not a substitute for either. See
docs/SECURITY-TESTING-NOTES.md, F3.

The window is a real sliding window (timestamps, not fixed buckets), so
the classic burst-across-a-bucket-boundary bypass -- N requests at the end
of one bucket plus N at the start of the next -- does not work here.
"""

from __future__ import annotations

import threading
import time
from collections import defaultdict, deque

from fastapi import HTTPException

# (max_requests, window_seconds), keyed by a caller-chosen bucket name.
# Set from what the endpoint actually costs, not a round number: the two
# LLM/provider endpoints are the ones with real per-call spend attached.
LIMITS: dict[str, tuple[int, int]] = {
    "investigate": (10, 3600),   # 4 Groq calls each
    "enrichment": (30, 3600),    # 4 threat-intel provider calls each
    "upload": (10, 3600),        # each triggers a full host_profiles rebuild
    "capture": (20, 3600),
    "global": (300, 60),
}

_hits: dict[tuple[str, str], deque[float]] = defaultdict(deque)
_lock = threading.Lock()


def _check(bucket: str, user_id: str) -> tuple[bool, int]:
    """Returns (allowed, retry_after_seconds)."""
    max_requests, window = LIMITS[bucket]
    now = time.monotonic()
    key = (bucket, user_id)
    with _lock:
        stamps = _hits[key]
        cutoff = now - window
        while stamps and stamps[0] <= cutoff:
            stamps.popleft()
        if len(stamps) >= max_requests:
            # Time until the oldest hit in the window falls out of it.
            return False, max(1, int(stamps[0] + window - now) + 1)
        stamps.append(now)
        return True, 0


def reset() -> None:
    """Clear all counters. For tests only."""
    with _lock:
        _hits.clear()


def enforce(bucket: str, user_id: str) -> None:
    """Charge one hit against a single named bucket, 429 if over.

    Charges ONLY the named bucket. The cross-endpoint `global` bucket is
    charged centrally in `app.services.auth.user_from_raw_token()`, which
    every authenticated request passes through -- so it is not repeated
    here (that would double-count the spend endpoints).

    Called imperatively from inside a handler rather than as a dependency
    because `investigate` and `enrichment` both take a `fetch` flag:
    fetch=false is a free cache peek, fetch=true is what spends Groq /
    threat-intel quota. A dependency runs before that flag can be
    inspected, so charging there would bill a read-only peek against the
    spend budget.
    """
    allowed, retry_after = _check(bucket, user_id)
    if not allowed:
        max_requests, window = LIMITS[bucket]
        raise HTTPException(
            status_code=429,
            detail=f"Rate limit exceeded ({max_requests} per {window}s). Retry in {retry_after}s.",
            headers={"Retry-After": str(retry_after)},
        )
