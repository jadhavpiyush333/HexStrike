from src.services.scan_service import SCANS
from src.ai_analysis import analyze_findings

def analyze_scan(scan_id: str) -> dict:
    record = SCANS.get(scan_id)
    if not record:
        return {"error": "Scan not found", "scan_id": scan_id}
    result = analyze_findings(record.get("findings", []))
    return {"scan_id": scan_id, **result.__dict__}
