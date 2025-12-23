"""Tests for async runner module."""

import asyncio
import time

import pytest

from security_lead_scorer.utils.async_runner import (
    run_bulk_scans,
    run_single_scan_async,
    AsyncScanner,
)
from security_lead_scorer.utils.cache import ScanCache


def mock_scan_func(domain: str) -> dict:
    """Mock scan function for testing."""
    time.sleep(0.05)  # Simulate some work
    return {
        "domain": domain,
        "total_score": len(domain) * 5,
        "grade": "C",
        "temperature": "hot",
        "checks": {},
        "issues": [],
        "talking_points": [],
    }


def mock_scan_func_with_error(domain: str) -> dict:
    """Mock scan function that raises errors for specific domains."""
    if "error" in domain:
        raise ValueError(f"Scan failed for {domain}")
    return mock_scan_func(domain)


class TestRunBulkScans:
    """Tests for run_bulk_scans function."""

    @pytest.mark.asyncio
    async def test_scans_all_domains(self):
        """Test that all domains are scanned."""
        domains = ["example1.com", "example2.com", "example3.com"]

        results = await run_bulk_scans(
            domains=domains,
            scan_func=mock_scan_func,
            concurrency=2,
            rate_limit=100,
        )

        assert len(results) == 3
        assert results[0]["domain"] == "example1.com"
        assert results[1]["domain"] == "example2.com"
        assert results[2]["domain"] == "example3.com"

    @pytest.mark.asyncio
    async def test_preserves_order(self):
        """Test that results are in same order as input."""
        domains = ["z.com", "a.com", "m.com", "b.com"]

        results = await run_bulk_scans(
            domains=domains,
            scan_func=mock_scan_func,
            concurrency=4,
            rate_limit=100,
        )

        result_domains = [r["domain"] for r in results]
        assert result_domains == domains

    @pytest.mark.asyncio
    async def test_respects_concurrency(self):
        """Test that concurrency limit is respected."""
        concurrent_count = 0
        max_concurrent = 0

        def tracking_scan(domain: str) -> dict:
            nonlocal concurrent_count, max_concurrent
            concurrent_count += 1
            max_concurrent = max(max_concurrent, concurrent_count)
            time.sleep(0.1)
            concurrent_count -= 1
            return mock_scan_func(domain)

        domains = ["d1.com", "d2.com", "d3.com", "d4.com", "d5.com"]

        await run_bulk_scans(
            domains=domains,
            scan_func=tracking_scan,
            concurrency=2,
            rate_limit=100,
        )

        assert max_concurrent <= 2

    @pytest.mark.asyncio
    async def test_handles_errors_gracefully(self):
        """Test that errors are handled and don't stop scanning."""
        domains = ["good1.com", "error.com", "good2.com"]

        results = await run_bulk_scans(
            domains=domains,
            scan_func=mock_scan_func_with_error,
            concurrency=1,
            rate_limit=100,
        )

        assert len(results) == 3
        assert results[0]["domain"] == "good1.com"
        assert "error" in results[1]
        assert results[2]["domain"] == "good2.com"

    @pytest.mark.asyncio
    async def test_calls_progress_callback(self):
        """Test that progress callback is called for each domain."""
        domains = ["d1.com", "d2.com", "d3.com"]
        progress_calls = []

        def on_progress(domain, result, error):
            progress_calls.append((domain, result is not None, error))

        await run_bulk_scans(
            domains=domains,
            scan_func=mock_scan_func,
            concurrency=1,
            rate_limit=100,
            on_progress=on_progress,
        )

        assert len(progress_calls) == 3
        domains_called = {call[0] for call in progress_calls}
        assert domains_called == {"d1.com", "d2.com", "d3.com"}

    @pytest.mark.asyncio
    async def test_uses_cache(self, tmp_path):
        """Test that cache is used when provided."""
        cache = ScanCache(str(tmp_path / "cache"), ttl_seconds=3600)

        # Pre-populate cache
        cache.set("cached.com", {"domain": "cached.com", "from_cache_test": True})

        domains = ["cached.com", "fresh.com"]
        scan_count = 0

        def counting_scan(domain: str) -> dict:
            nonlocal scan_count
            scan_count += 1
            return mock_scan_func(domain)

        results = await run_bulk_scans(
            domains=domains,
            scan_func=counting_scan,
            concurrency=1,
            rate_limit=100,
            cache=cache,
        )

        # Only fresh.com should have been scanned
        assert scan_count == 1
        assert results[0].get("from_cache") is True
        assert results[0].get("from_cache_test") is True

    @pytest.mark.asyncio
    async def test_caches_new_results(self, tmp_path):
        """Test that new results are cached."""
        cache = ScanCache(str(tmp_path / "cache"), ttl_seconds=3600)

        domains = ["new.com"]

        await run_bulk_scans(
            domains=domains,
            scan_func=mock_scan_func,
            concurrency=1,
            rate_limit=100,
            cache=cache,
        )

        # Should be in cache now
        cached = cache.get("new.com")
        assert cached is not None
        assert cached["domain"] == "new.com"

    @pytest.mark.asyncio
    async def test_empty_domains_list(self):
        """Test handling of empty domains list."""
        results = await run_bulk_scans(
            domains=[],
            scan_func=mock_scan_func,
            concurrency=1,
            rate_limit=100,
        )

        assert results == []


class TestRunSingleScanAsync:
    """Tests for run_single_scan_async function."""

    @pytest.mark.asyncio
    async def test_scans_domain(self):
        """Test single domain scanning."""
        result = await run_single_scan_async(
            domain="example.com",
            scan_func=mock_scan_func,
        )

        assert result["domain"] == "example.com"

    @pytest.mark.asyncio
    async def test_uses_cache(self, tmp_path):
        """Test that cache is used."""
        cache = ScanCache(str(tmp_path / "cache"), ttl_seconds=3600)
        cache.set("cached.com", {"domain": "cached.com", "cached": True})

        result = await run_single_scan_async(
            domain="cached.com",
            scan_func=mock_scan_func,
            cache=cache,
        )

        assert result.get("cached") is True
        assert result.get("from_cache") is True


class TestAsyncScanner:
    """Tests for AsyncScanner class."""

    @pytest.mark.asyncio
    async def test_scan_domains(self):
        """Test scanning multiple domains."""
        scanner = AsyncScanner(
            scan_func=mock_scan_func,
            concurrency=2,
            rate_limit=100,
        )

        domains = ["d1.com", "d2.com", "d3.com"]
        results = await scanner.scan_domains(domains)

        assert len(results) == 3

    @pytest.mark.asyncio
    async def test_scan_single(self):
        """Test scanning single domain."""
        scanner = AsyncScanner(
            scan_func=mock_scan_func,
            concurrency=2,
            rate_limit=100,
        )

        result = await scanner.scan_single("example.com")

        assert result["domain"] == "example.com"

    @pytest.mark.asyncio
    async def test_stats_tracking(self):
        """Test that stats are tracked correctly."""
        scanner = AsyncScanner(
            scan_func=mock_scan_func,
            concurrency=2,
            rate_limit=100,
        )

        domains = ["d1.com", "d2.com", "d3.com"]
        await scanner.scan_domains(domains)

        stats = scanner.stats
        assert stats["scanned"] == 3
        assert stats["total"] == 3
        assert stats["errors"] == 0

    @pytest.mark.asyncio
    async def test_stats_with_errors(self):
        """Test stats tracking with errors."""
        scanner = AsyncScanner(
            scan_func=mock_scan_func_with_error,
            concurrency=1,
            rate_limit=100,
        )

        domains = ["good.com", "error.com"]
        await scanner.scan_domains(domains)

        stats = scanner.stats
        assert stats["scanned"] == 1
        assert stats["errors"] == 1
        assert stats["total"] == 2

    @pytest.mark.asyncio
    async def test_with_caching(self, tmp_path):
        """Test scanner with caching enabled."""
        cache_dir = str(tmp_path / "cache")

        scanner = AsyncScanner(
            scan_func=mock_scan_func,
            concurrency=2,
            rate_limit=100,
            cache_dir=cache_dir,
            cache_ttl=3600,
        )

        # First scan
        domains = ["d1.com", "d2.com"]
        await scanner.scan_domains(domains)

        # Second scan should use cache
        await scanner.scan_domains(domains)

        stats = scanner.stats
        assert stats["from_cache"] == 2

    @pytest.mark.asyncio
    async def test_without_caching(self):
        """Test scanner without caching."""
        scanner = AsyncScanner(
            scan_func=mock_scan_func,
            concurrency=2,
            rate_limit=100,
            cache_dir=None,
        )

        assert scanner.cache is None

        # Should still work
        domains = ["d1.com"]
        results = await scanner.scan_domains(domains)
        assert len(results) == 1

    @pytest.mark.asyncio
    async def test_progress_callback(self):
        """Test progress callback in AsyncScanner."""
        scanner = AsyncScanner(
            scan_func=mock_scan_func,
            concurrency=2,
            rate_limit=100,
        )

        progress_calls = []

        def on_progress(domain, result, error):
            progress_calls.append(domain)

        domains = ["d1.com", "d2.com"]
        await scanner.scan_domains(domains, on_progress=on_progress)

        assert len(progress_calls) == 2

    @pytest.mark.asyncio
    async def test_concurrent_performance(self):
        """Test that concurrency improves performance."""
        # Sequential (concurrency=1)
        scanner_seq = AsyncScanner(
            scan_func=mock_scan_func,
            concurrency=1,
            rate_limit=100,
        )

        # Concurrent (concurrency=5)
        scanner_conc = AsyncScanner(
            scan_func=mock_scan_func,
            concurrency=5,
            rate_limit=100,
        )

        domains = ["d1.com", "d2.com", "d3.com", "d4.com", "d5.com"]

        start = time.monotonic()
        await scanner_seq.scan_domains(domains)
        seq_time = time.monotonic() - start

        start = time.monotonic()
        await scanner_conc.scan_domains(domains)
        conc_time = time.monotonic() - start

        # Concurrent should be faster
        assert conc_time < seq_time
