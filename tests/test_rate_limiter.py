"""Tests for rate limiter module."""

import asyncio
import time

import pytest

from security_lead_scorer.utils.rate_limiter import RateLimiter


class TestRateLimiter:
    """Tests for RateLimiter class."""

    @pytest.mark.asyncio
    async def test_init_defaults(self):
        """Test default initialization."""
        limiter = RateLimiter()
        assert limiter.rate == 10
        assert limiter.per == 1.0
        assert limiter.tokens == 10.0

    @pytest.mark.asyncio
    async def test_init_custom_values(self):
        """Test custom initialization."""
        limiter = RateLimiter(rate=5, per=2.0)
        assert limiter.rate == 5
        assert limiter.per == 2.0
        assert limiter.tokens == 5.0

    @pytest.mark.asyncio
    async def test_acquire_reduces_tokens(self):
        """Test that acquire reduces available tokens."""
        limiter = RateLimiter(rate=10, per=1.0)
        initial_tokens = limiter.tokens

        await limiter.acquire()

        # Token should be reduced (accounting for time-based replenishment)
        assert limiter.tokens < initial_tokens

    @pytest.mark.asyncio
    async def test_acquire_multiple_fast(self):
        """Test acquiring multiple tokens quickly."""
        limiter = RateLimiter(rate=5, per=1.0)

        # Acquire 5 tokens quickly (should not wait)
        start = time.monotonic()
        for _ in range(5):
            await limiter.acquire()
        elapsed = time.monotonic() - start

        # Should complete quickly (all tokens available)
        assert elapsed < 0.5

    @pytest.mark.asyncio
    async def test_acquire_waits_when_depleted(self):
        """Test that acquire waits when tokens are depleted."""
        limiter = RateLimiter(rate=2, per=1.0)

        # Deplete tokens
        await limiter.acquire()
        await limiter.acquire()

        # Next acquire should wait
        start = time.monotonic()
        await limiter.acquire()
        elapsed = time.monotonic() - start

        # Should have waited for token replenishment
        assert elapsed >= 0.4  # At least ~0.5 seconds for 1 token at rate 2/sec

    @pytest.mark.asyncio
    async def test_acquire_returns_wait_time(self):
        """Test that acquire returns the wait time."""
        limiter = RateLimiter(rate=10, per=1.0)

        # First acquire should not wait
        wait_time = await limiter.acquire()
        assert wait_time == 0.0

    @pytest.mark.asyncio
    async def test_reset(self):
        """Test reset restores full tokens."""
        limiter = RateLimiter(rate=10, per=1.0)

        # Deplete some tokens
        await limiter.acquire()
        await limiter.acquire()

        # Reset
        limiter.reset()

        assert limiter.tokens == 10.0

    @pytest.mark.asyncio
    async def test_available_tokens_property(self):
        """Test available_tokens property."""
        limiter = RateLimiter(rate=10, per=1.0)

        # Should start with full tokens
        assert limiter.available_tokens == pytest.approx(10.0, abs=0.1)

        # Acquire some
        await limiter.acquire()
        await limiter.acquire()

        # Should have less
        assert limiter.available_tokens < 10.0

    @pytest.mark.asyncio
    async def test_token_replenishment_over_time(self):
        """Test that tokens replenish over time."""
        limiter = RateLimiter(rate=10, per=1.0)

        # Deplete all tokens
        for _ in range(10):
            await limiter.acquire()

        # Wait a bit for replenishment
        await asyncio.sleep(0.5)

        # Should have some tokens back
        assert limiter.available_tokens > 0

    @pytest.mark.asyncio
    async def test_concurrent_acquire(self):
        """Test concurrent acquire calls."""
        limiter = RateLimiter(rate=5, per=1.0)

        async def acquire_token():
            await limiter.acquire()
            return True

        # Run multiple concurrent acquires
        tasks = [acquire_token() for _ in range(5)]
        results = await asyncio.gather(*tasks)

        # All should complete
        assert all(results)

    @pytest.mark.asyncio
    async def test_rate_limiting_accuracy(self):
        """Test that rate limiting is reasonably accurate."""
        limiter = RateLimiter(rate=10, per=1.0)

        # Time 15 acquires (should take ~0.5 seconds for the last 5)
        start = time.monotonic()
        for _ in range(15):
            await limiter.acquire()
        elapsed = time.monotonic() - start

        # First 10 are instant, next 5 should take ~0.5 seconds
        assert elapsed >= 0.4
        assert elapsed < 1.5  # But not too long
