"""File-based cache for scan results."""

import json
from datetime import datetime, timedelta
from hashlib import md5
from pathlib import Path
from typing import Any


class ScanCache:
    """
    Simple file-based cache for scan results.

    Avoids re-scanning recently checked domains by storing results
    in JSON files with TTL-based expiration.

    Usage:
        cache = ScanCache(cache_dir=".cache", ttl_seconds=86400)

        # Check cache
        result = cache.get("example.com")
        if result is None:
            result = scan_domain("example.com")
            cache.set("example.com", result)
    """

    def __init__(self, cache_dir: str = ".cache", ttl_seconds: int = 86400):
        """
        Initialize cache.

        Args:
            cache_dir: Directory to store cache files.
            ttl_seconds: Time-to-live in seconds (default: 24 hours).
        """
        self.cache_dir = Path(cache_dir)
        self.ttl = timedelta(seconds=ttl_seconds)
        self._ensure_cache_dir()

    def _ensure_cache_dir(self) -> None:
        """Create cache directory if it doesn't exist."""
        self.cache_dir.mkdir(parents=True, exist_ok=True)

    def _cache_key(self, domain: str) -> str:
        """Generate cache key from domain."""
        return md5(domain.lower().encode()).hexdigest()

    def _cache_file(self, domain: str) -> Path:
        """Get cache file path for domain."""
        return self.cache_dir / f"{self._cache_key(domain)}.json"

    def get(self, domain: str) -> dict | None:
        """
        Get cached result for domain.

        Args:
            domain: Domain to look up.

        Returns:
            Cached scan result dict, or None if not found or expired.
        """
        cache_file = self._cache_file(domain)

        if not cache_file.exists():
            return None

        try:
            data = json.loads(cache_file.read_text(encoding="utf-8"))
            cached_at = datetime.fromisoformat(data["cached_at"])

            # Check if expired
            if datetime.now() - cached_at > self.ttl:
                cache_file.unlink(missing_ok=True)
                return None

            return data["result"]

        except (json.JSONDecodeError, KeyError, ValueError):
            # Invalid cache file, remove it
            cache_file.unlink(missing_ok=True)
            return None

    def set(self, domain: str, result: dict) -> None:
        """
        Store scan result in cache.

        Args:
            domain: Domain that was scanned.
            result: Scan result dict to cache.
        """
        self._ensure_cache_dir()
        cache_file = self._cache_file(domain)

        cache_data = {
            "cached_at": datetime.now().isoformat(),
            "domain": domain,
            "result": result,
        }

        cache_file.write_text(
            json.dumps(cache_data, indent=2, default=str),
            encoding="utf-8"
        )

    def delete(self, domain: str) -> bool:
        """
        Delete cached result for domain.

        Args:
            domain: Domain to delete from cache.

        Returns:
            True if deleted, False if not found.
        """
        cache_file = self._cache_file(domain)

        if cache_file.exists():
            cache_file.unlink()
            return True
        return False

    def clear(self) -> int:
        """
        Clear all cached results.

        Returns:
            Number of cache files deleted.
        """
        count = 0
        if self.cache_dir.exists():
            for cache_file in self.cache_dir.glob("*.json"):
                cache_file.unlink()
                count += 1
        return count

    def cleanup_expired(self) -> int:
        """
        Remove expired cache entries.

        Returns:
            Number of expired entries removed.
        """
        count = 0
        if not self.cache_dir.exists():
            return count

        for cache_file in self.cache_dir.glob("*.json"):
            try:
                data = json.loads(cache_file.read_text(encoding="utf-8"))
                cached_at = datetime.fromisoformat(data["cached_at"])

                if datetime.now() - cached_at > self.ttl:
                    cache_file.unlink()
                    count += 1

            except (json.JSONDecodeError, KeyError, ValueError):
                # Invalid file, remove it
                cache_file.unlink()
                count += 1

        return count

    def stats(self) -> dict[str, Any]:
        """
        Get cache statistics.

        Returns:
            Dict with cache stats (total entries, expired, size).
        """
        total = 0
        expired = 0
        total_size = 0

        if self.cache_dir.exists():
            for cache_file in self.cache_dir.glob("*.json"):
                total += 1
                total_size += cache_file.stat().st_size

                try:
                    data = json.loads(cache_file.read_text(encoding="utf-8"))
                    cached_at = datetime.fromisoformat(data["cached_at"])
                    if datetime.now() - cached_at > self.ttl:
                        expired += 1
                except (json.JSONDecodeError, KeyError, ValueError):
                    expired += 1

        return {
            "total_entries": total,
            "expired_entries": expired,
            "valid_entries": total - expired,
            "total_size_bytes": total_size,
            "cache_dir": str(self.cache_dir),
            "ttl_seconds": int(self.ttl.total_seconds()),
        }
