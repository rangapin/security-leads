"""Pytest configuration and fixtures."""

import pytest


@pytest.fixture
def sample_domain():
    """Return a sample domain for testing."""
    return "example.com"
