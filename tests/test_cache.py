"""Tests for cache module."""

import json
import time
from datetime import datetime, timedelta
from pathlib import Path

import pytest

from security_lead_scorer.utils.cache import ScanCache


@pytest.fixture
def cache_dir(tmp_path):
    """Create a temporary cache directory."""
    return tmp_path / "test_cache"


@pytest.fixture
def cache(cache_dir):
    """Create a ScanCache instance with temp directory."""
    return ScanCache(str(cache_dir), ttl_seconds=3600)


class TestScanCache:
    """Tests for ScanCache class."""

    def test_init_creates_directory(self, cache_dir):
        """Test that init creates the cache directory."""
        cache = ScanCache(str(cache_dir), ttl_seconds=3600)
        assert cache_dir.exists()
        assert cache_dir.is_dir()

    def test_init_with_existing_directory(self, cache_dir):
        """Test init with existing directory."""
        cache_dir.mkdir(parents=True)
        cache = ScanCache(str(cache_dir), ttl_seconds=3600)
        assert cache_dir.exists()

    def test_set_creates_cache_file(self, cache, cache_dir):
        """Test that set creates a cache file."""
        result = {"domain": "example.com", "score": 42}
        cache.set("example.com", result)

        # Check file was created
        cache_files = list(cache_dir.glob("*.json"))
        assert len(cache_files) == 1

    def test_get_returns_cached_result(self, cache):
        """Test get returns cached result."""
        result = {"domain": "example.com", "score": 42}
        cache.set("example.com", result)

        retrieved = cache.get("example.com")
        assert retrieved == result

    def test_get_returns_none_for_missing(self, cache):
        """Test get returns None for missing entry."""
        result = cache.get("nonexistent.com")
        assert result is None

    def test_get_returns_none_for_expired(self, cache_dir):
        """Test get returns None for expired entry."""
        # Create cache with very short TTL
        cache = ScanCache(str(cache_dir), ttl_seconds=1)

        result = {"domain": "example.com", "score": 42}
        cache.set("example.com", result)

        # Wait for expiry
        time.sleep(1.5)

        # Should return None
        assert cache.get("example.com") is None

    def test_cache_key_is_consistent(self, cache):
        """Test that cache key is consistent for same domain."""
        key1 = cache._cache_key("example.com")
        key2 = cache._cache_key("example.com")
        assert key1 == key2

    def test_cache_key_is_case_insensitive(self, cache):
        """Test that cache key is case insensitive."""
        key1 = cache._cache_key("Example.COM")
        key2 = cache._cache_key("example.com")
        assert key1 == key2

    def test_delete_removes_cache_file(self, cache, cache_dir):
        """Test delete removes the cache file."""
        result = {"domain": "example.com", "score": 42}
        cache.set("example.com", result)

        # Delete
        deleted = cache.delete("example.com")
        assert deleted is True

        # Verify file is gone
        assert cache.get("example.com") is None

    def test_delete_returns_false_for_missing(self, cache):
        """Test delete returns False for missing entry."""
        deleted = cache.delete("nonexistent.com")
        assert deleted is False

    def test_clear_removes_all_files(self, cache, cache_dir):
        """Test clear removes all cache files."""
        # Add multiple entries
        cache.set("example1.com", {"score": 1})
        cache.set("example2.com", {"score": 2})
        cache.set("example3.com", {"score": 3})

        # Clear
        count = cache.clear()
        assert count == 3

        # Verify all gone
        assert cache.get("example1.com") is None
        assert cache.get("example2.com") is None
        assert cache.get("example3.com") is None

    def test_cleanup_expired_removes_old_entries(self, cache_dir):
        """Test cleanup_expired removes old entries."""
        cache = ScanCache(str(cache_dir), ttl_seconds=1)

        # Add entries
        cache.set("old.com", {"score": 1})
        time.sleep(1.5)  # Let it expire

        # Add new entry
        cache.set("new.com", {"score": 2})

        # Cleanup
        count = cache.cleanup_expired()
        assert count == 1

        # Verify old is gone, new remains
        assert cache.get("old.com") is None
        assert cache.get("new.com") is not None

    def test_stats_returns_correct_counts(self, cache):
        """Test stats returns correct statistics."""
        # Add entries
        cache.set("example1.com", {"score": 1})
        cache.set("example2.com", {"score": 2})

        stats = cache.stats()

        assert stats["total_entries"] == 2
        assert stats["valid_entries"] == 2
        assert stats["expired_entries"] == 0
        assert stats["total_size_bytes"] > 0

    def test_stats_counts_expired(self, cache_dir):
        """Test stats correctly counts expired entries."""
        cache = ScanCache(str(cache_dir), ttl_seconds=1)

        cache.set("example.com", {"score": 1})
        time.sleep(1.5)

        stats = cache.stats()

        assert stats["total_entries"] == 1
        assert stats["expired_entries"] == 1
        assert stats["valid_entries"] == 0

    def test_handles_invalid_json(self, cache, cache_dir):
        """Test handles corrupted cache files gracefully."""
        # Create invalid cache file
        cache_key = cache._cache_key("example.com")
        invalid_file = cache_dir / f"{cache_key}.json"
        invalid_file.write_text("not valid json{{{")

        # Should return None and remove the file
        result = cache.get("example.com")
        assert result is None
        assert not invalid_file.exists()

    def test_handles_missing_cached_at(self, cache, cache_dir):
        """Test handles cache file missing cached_at field."""
        cache_key = cache._cache_key("example.com")
        cache_file = cache_dir / f"{cache_key}.json"
        cache_file.write_text(json.dumps({"result": {"score": 42}}))

        # Should return None and remove the file
        result = cache.get("example.com")
        assert result is None
        assert not cache_file.exists()

    def test_stores_complex_results(self, cache):
        """Test storing complex nested results."""
        result = {
            "domain": "example.com",
            "total_score": 67,
            "grade": "D",
            "temperature": "hot",
            "checks": {
                "ssl": {"has_ssl": True, "score": 15},
                "headers": {"headers_missing": ["CSP", "HSTS"], "score": 23},
            },
            "issues": ["SSL expiring", "Missing CSP"],
            "talking_points": ["Your SSL cert expires soon"],
        }

        cache.set("example.com", result)
        retrieved = cache.get("example.com")

        assert retrieved == result
        assert retrieved["checks"]["ssl"]["has_ssl"] is True

    def test_ttl_from_init(self, cache_dir):
        """Test TTL is correctly set from initialization."""
        cache = ScanCache(str(cache_dir), ttl_seconds=7200)
        assert cache.ttl == timedelta(seconds=7200)

    def test_multiple_domains_independent(self, cache):
        """Test multiple domains are stored independently."""
        cache.set("example1.com", {"score": 10})
        cache.set("example2.com", {"score": 20})
        cache.set("example3.com", {"score": 30})

        assert cache.get("example1.com")["score"] == 10
        assert cache.get("example2.com")["score"] == 20
        assert cache.get("example3.com")["score"] == 30

        # Delete one, others remain
        cache.delete("example2.com")
        assert cache.get("example1.com") is not None
        assert cache.get("example2.com") is None
        assert cache.get("example3.com") is not None
