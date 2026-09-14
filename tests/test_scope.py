import pytest
from src.safety.scope_validator import ScopeError, validate_target

def test_accepts_runtime_targets_without_registration():
    assert validate_target('10.0.0.1', []) == '10.0.0.1'
    assert validate_target('192.168.56.101', ['127.0.0.1']) == '192.168.56.101'

def test_rejects_shell_metacharacters():
    with pytest.raises(ScopeError):
        validate_target('127.0.0.1;whoami', [])

def test_accepts_urls_and_normalizes_host():
    assert validate_target('https://10.0.0.25:8443/login', []) == '10.0.0.25'
