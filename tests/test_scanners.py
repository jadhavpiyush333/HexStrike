from src.scanners.registry import build_registry

def test_registry_contains_core_scanners():
    r = build_registry()
    for name in ["nmap","scanx","nikto","nuclei","whatweb","httpx","gobuster","ffuf","amass","subfinder"]:
        assert name in r

def test_missing_binary_is_safe():
    r = build_registry()
    result = r["nikto"].scan("127.0.0.1", "safe", timeout=1)
    assert result.status in {"unavailable", "completed", "failed"}
