import os
from pathlib import Path
import pytest
from src.safety.authorization import validate_api_key, AuthorizationError
from src.safety.rate_limiter import RateLimiter
from src.safety.policy_engine import load_policies

BASE = Path(__file__).resolve().parents[1]

def test_api_key_validation(monkeypatch):
    monkeypatch.setenv("HEXSTRIKE_API_KEY", "lab-secret")
    validate_api_key("lab-secret")
    with pytest.raises(AuthorizationError):
        validate_api_key("wrong")

def test_rate_limiter():
    limiter = RateLimiter(2, 60)
    assert limiter.allow("test")
    assert limiter.allow("test")
    assert not limiter.allow("test")

def test_policies():
    policies = load_policies(BASE)
    assert "safe" in policies
    assert policies["safe"].timeout_seconds == 120
