"""Per-target rate limiting for tool execution -- CLAUDE.md requires
"rate limiting and safe-mode throttling on scanners by default" since this
runs against infrastructure whose blast radius the operator may not fully
understand.

Enforces a minimum interval between calls against the *same* target;
different targets aren't limited against each other (that's what the
concurrency semaphore is for).
"""

from __future__ import annotations

import asyncio
import logging
import time

logger = logging.getLogger(__name__)


class RateLimiter:
    def __init__(self, requests_per_second: float | None):
        # None/0 disables limiting -- used as the default for callers that
        # don't care (tests, one-off scripts); a real run always passes the
        # scan profile's configured rate.
        self._min_interval = 1.0 / requests_per_second if requests_per_second else 0.0
        self._last_call: dict[str, float] = {}
        self._lock = asyncio.Lock()

    async def wait(self, target: str) -> None:
        if self._min_interval <= 0:
            return
        async with self._lock:
            last = self._last_call.get(target)
            if last is not None:
                delay = self._min_interval - (time.monotonic() - last)
                if delay > 0:
                    logger.debug("[%s] rate limit: sleeping %.2fs", target, delay)
                    await asyncio.sleep(delay)
            self._last_call[target] = time.monotonic()
