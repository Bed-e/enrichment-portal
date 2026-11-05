"""Outbound rate limiter (design.md section 2).

Throttles our own outgoing calls so we never exceed a provider's published limit. It stores no
responses, so it is not a cache (D5). The clock and the sleep function are parameters so tests
advance time instantly instead of waiting (D13).
"""

import asyncio
import time
from collections import deque
from collections.abc import Awaitable, Callable


class RateLimiter:
    """Sliding window: at most `max_calls` calls in any `period` seconds."""

    def __init__(
        self,
        max_calls: int,
        period: float,
        clock: Callable[[], float] = time.monotonic,
        sleep: Callable[[float], Awaitable[None]] = asyncio.sleep,
    ) -> None:
        self._max_calls = max_calls
        self._period = period
        self._clock = clock
        self._sleep = sleep
        self._calls: deque[float] = deque()
        self._lock = asyncio.Lock()

    async def acquire(self, max_wait: float) -> bool:
        """Take a slot, waiting if needed. False if the wait would exceed `max_wait` seconds.

        A False return means the caller should report `rate_limited` instead of hanging.
        """
        async with self._lock:
            while True:
                now = self._clock()
                while self._calls and now - self._calls[0] >= self._period:
                    self._calls.popleft()
                if len(self._calls) < self._max_calls:
                    self._calls.append(now)
                    return True
                wait = self._calls[0] + self._period - now
                if wait > max_wait:
                    return False
                await self._sleep(wait)
