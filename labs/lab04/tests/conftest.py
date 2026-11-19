"""Shared fixtures and network isolation for Lab 04 tests."""

import pytest
import requests


@pytest.fixture(autouse=True)
def isolated_environment(monkeypatch):
    """Prevent accidental Requests traffic and remove inherited API secrets."""
    monkeypatch.delenv("NVD_API_KEY", raising=False)
    monkeypatch.delattr(requests.sessions.Session, "request")
