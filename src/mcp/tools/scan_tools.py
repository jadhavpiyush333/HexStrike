from src.services.scan_service import SCANS, start_scan
from src.scanners.registry import build_registry
from src.mcp.schemas import ScanToolInput


def scanner_health() -> dict:
    return {name: scanner.health() for name, scanner in build_registry().items()}


def scanx_scan(target: str, profile: str = "safe") -> dict:
    return _run("scanx", target, profile)


def nmap_scan(target: str, profile: str = "safe") -> dict:
    return _run("nmap", target, profile)


def _run(scanner: str, target: str, profile: str) -> dict:
    from src.mcp.runtime import ALLOWLIST, BASE
    return start_scan(target, profile, ALLOWLIST, BASE, scanner)


def scan_status(scan_id: str) -> dict:
    return SCANS.get(scan_id) or {"error": "Scan not found", "scan_id": scan_id}


def get_scan_results(scan_id: str) -> dict:
    record = SCANS.get(scan_id)
    if not record:
        return {"error": "Scan not found", "scan_id": scan_id}
    return {"scan_id": scan_id, "status": record["status"], "findings": record["findings"], "metadata": record["metadata"]}
