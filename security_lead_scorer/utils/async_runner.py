"""Async runner for concurrent domain scanning."""

import asyncio
from typing import Callable, Any

from .rate_limiter import RateLimiter
from .cache import ScanCache


async def run_bulk_scans(
    domains: list[str],
    scan_func: Callable[[str], dict],
    concurrency: int = 5,
    rate_limit: int = 10,
    cache: ScanCache | None = None,
    on_progress: Callable[[str, dict | None, Exception | None], None] | None = None,
) -> list[dict]:
    """
    Run scans concurrently with rate limiting and optional caching.

    Args:
        domains: List of domains to scan.
        scan_func: Synchronous function that takes a domain and returns scan results.
        concurrency: Maximum number of concurrent scans.
        rate_limit: Maximum requests per second.
        cache: Optional ScanCache instance for caching results.
        on_progress: Optional callback(domain, result, error) called after each scan.

    Returns:
        List of scan results in the same order as input domains.
    """
    rate_limiter = RateLimiter(rate=rate_limit, per=1.0)
    semaphore = asyncio.Semaphore(concurrency)

    async def scan_with_limits(domain: str, index: int) -> tuple[int, dict]:
        """Scan a single domain with rate limiting and concurrency control."""
        async with semaphore:
            # Check cache first
            if cache is not None:
                cached_result = cache.get(domain)
                if cached_result is not None:
                    cached_result["from_cache"] = True
                    if on_progress:
                        on_progress(domain, cached_result, None)
                    return (index, cached_result)

            # Wait for rate limiter
            await rate_limiter.acquire()

            try:
                # Run synchronous scan function in thread pool
                result = await asyncio.to_thread(scan_func, domain)

                # Store in cache
                if cache is not None:
                    cache.set(domain, result)

                if on_progress:
                    on_progress(domain, result, None)

                return (index, result)

            except Exception as e:
                error_result = {
                    "domain": domain,
                    "error": str(e),
                    "total_score": 0,
                    "grade": "?",
                    "temperature": "unknown",
                    "checks": {},
                    "issues": [f"Scan error: {e}"],
                    "talking_points": [],
                }

                if on_progress:
                    on_progress(domain, None, e)

                return (index, error_result)

    # Create tasks for all domains
    tasks = [
        scan_with_limits(domain, idx)
        for idx, domain in enumerate(domains)
    ]

    # Run all tasks concurrently
    completed = await asyncio.gather(*tasks)

    # Sort by original index and return results
    completed_sorted = sorted(completed, key=lambda x: x[0])
    return [result for _, result in completed_sorted]


async def run_single_scan_async(
    domain: str,
    scan_func: Callable[[str], dict],
    cache: ScanCache | None = None,
) -> dict:
    """
    Run a single scan asynchronously.

    Args:
        domain: Domain to scan.
        scan_func: Synchronous function that takes a domain and returns scan results.
        cache: Optional ScanCache instance.

    Returns:
        Scan result dict.
    """
    # Check cache first
    if cache is not None:
        cached_result = cache.get(domain)
        if cached_result is not None:
            cached_result["from_cache"] = True
            return cached_result

    # Run scan in thread pool
    result = await asyncio.to_thread(scan_func, domain)

    # Store in cache
    if cache is not None:
        cache.set(domain, result)

    return result


class AsyncScanner:
    """
    Async scanner with built-in rate limiting and caching.

    Usage:
        scanner = AsyncScanner(
            scan_func=my_scan_function,
            concurrency=5,
            rate_limit=10,
            cache_dir=".cache",
            cache_ttl=86400,
        )

        results = await scanner.scan_domains(["example.com", "test.com"])
    """

    def __init__(
        self,
        scan_func: Callable[[str], dict],
        concurrency: int = 5,
        rate_limit: int = 10,
        cache_dir: str | None = None,
        cache_ttl: int = 86400,
    ):
        """
        Initialize async scanner.

        Args:
            scan_func: Synchronous function that scans a domain.
            concurrency: Maximum concurrent scans.
            rate_limit: Maximum requests per second.
            cache_dir: Directory for cache files. None disables caching.
            cache_ttl: Cache TTL in seconds.
        """
        self.scan_func = scan_func
        self.concurrency = concurrency
        self.rate_limit = rate_limit
        self.cache = ScanCache(cache_dir, cache_ttl) if cache_dir else None

        # Stats
        self._scanned = 0
        self._cached = 0
        self._errors = 0

    async def scan_domains(
        self,
        domains: list[str],
        on_progress: Callable[[str, dict | None, Exception | None], None] | None = None,
    ) -> list[dict]:
        """
        Scan multiple domains concurrently.

        Args:
            domains: List of domains to scan.
            on_progress: Optional progress callback.

        Returns:
            List of scan results.
        """
        self._scanned = 0
        self._cached = 0
        self._errors = 0

        def track_progress(domain: str, result: dict | None, error: Exception | None):
            if error:
                self._errors += 1
            elif result and result.get("from_cache"):
                self._cached += 1
            else:
                self._scanned += 1

            if on_progress:
                on_progress(domain, result, error)

        results = await run_bulk_scans(
            domains=domains,
            scan_func=self.scan_func,
            concurrency=self.concurrency,
            rate_limit=self.rate_limit,
            cache=self.cache,
            on_progress=track_progress,
        )

        return results

    async def scan_single(self, domain: str) -> dict:
        """Scan a single domain."""
        return await run_single_scan_async(
            domain=domain,
            scan_func=self.scan_func,
            cache=self.cache,
        )

    @property
    def stats(self) -> dict[str, Any]:
        """Get scanning statistics."""
        return {
            "scanned": self._scanned,
            "from_cache": self._cached,
            "errors": self._errors,
            "total": self._scanned + self._cached + self._errors,
        }
