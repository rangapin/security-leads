"""Token bucket rate limiter for polite scanning."""

import asyncio
import time


class RateLimiter:
    """
    Token bucket rate limiter for controlling request rate.

    Default: 10 requests per second.

    Usage:
        limiter = RateLimiter(rate=10, per=1.0)
        await limiter.acquire()  # Wait for token if needed
    """

    def __init__(self, rate: int = 10, per: float = 1.0):
        """
        Initialize rate limiter.

        Args:
            rate: Number of tokens (requests) allowed per time period.
            per: Time period in seconds.
        """
        self.rate = rate
        self.per = per
        self.tokens = float(rate)
        self.last_update = time.monotonic()
        self._lock = asyncio.Lock()

    async def acquire(self) -> float:
        """
        Acquire a token, waiting if necessary.

        Returns:
            Time waited in seconds (0 if no wait was needed).
        """
        async with self._lock:
            now = time.monotonic()
            elapsed = now - self.last_update

            # Replenish tokens based on elapsed time
            self.tokens = min(
                float(self.rate),
                self.tokens + elapsed * (self.rate / self.per)
            )
            self.last_update = now

            wait_time = 0.0
            if self.tokens < 1:
                # Calculate wait time needed for 1 token
                wait_time = (1 - self.tokens) * (self.per / self.rate)
                await asyncio.sleep(wait_time)
                self.tokens = 0
                self.last_update = time.monotonic()
            else:
                self.tokens -= 1

            return wait_time

    def reset(self) -> None:
        """Reset the rate limiter to full tokens."""
        self.tokens = float(self.rate)
        self.last_update = time.monotonic()

    @property
    def available_tokens(self) -> float:
        """Get current available tokens (approximate)."""
        now = time.monotonic()
        elapsed = now - self.last_update
        return min(
            float(self.rate),
            self.tokens + elapsed * (self.rate / self.per)
        )
