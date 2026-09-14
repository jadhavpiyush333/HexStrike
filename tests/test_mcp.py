from src.mcp.tools.scan_tools import scanner_health, scan_status, get_scan_results

def test_health_contains_core_scanners():
    health = scanner_health()
    assert "nmap" in health
    assert "scanx" in health

def test_missing_scan_is_safe():
    assert scan_status("SCAN-0000000000")["error"] == "Scan not found"
    assert get_scan_results("SCAN-0000000000")["error"] == "Scan not found"
