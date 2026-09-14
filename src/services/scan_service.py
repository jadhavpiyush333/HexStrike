import uuid
from datetime import datetime, timezone
from threading import Semaphore

from src.logging.audit import audit
from src.safety.policy_engine import load_policies
from src.scanners.registry import build_registry


SCANS = {}
_semaphores = {}


def start_scan(target, profile, allowlist, base_path, scanner_name="nmap"):
    policy = load_policies(base_path).get(profile)

    if policy is None:
        raise ValueError("Unsupported or unsafe scan profile")

    registry = build_registry()

    if scanner_name not in registry:
        raise ValueError("Unknown scanner")

    sem = _semaphores.setdefault(
        profile,
        Semaphore(policy.max_concurrent),
    )

    # Wait for an available scanner slot instead of
    # immediately rejecting the scan.
    sem.acquire()

    scan_id = f"SCAN-{uuid.uuid4().hex[:10].upper()}"

    audit(
        "scan_requested",
        scan_id=scan_id,
        target=target,
        profile=profile,
        scanner=scanner_name,
    )

    try:
        result = registry[scanner_name].scan(
            target,
            profile,
            timeout=policy.timeout_seconds,
        )

        record = {
            "scan_id": scan_id,
            "target": target,
            "profile": profile,
            "scanner": result.scanner,
            "status": result.status,
            "findings": result.findings,
            "error": result.error,
            "metadata": result.metadata,
            "created_at": datetime.now(timezone.utc).isoformat(),
        }

        SCANS[scan_id] = record

        audit(
            "scan_completed",
            scan_id=scan_id,
            scanner=scanner_name,
            status=result.status,
            finding_count=len(result.findings),
        )

        return record

    finally:
        sem.release()
