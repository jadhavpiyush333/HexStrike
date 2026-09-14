import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from threading import Lock

logger = logging.getLogger("security.audit")
_lock = Lock()

def audit(event: str, **details) -> None:
    record = {"timestamp": datetime.now(timezone.utc).isoformat(), "event": event, **details}
    logger.info(json.dumps(record, sort_keys=True))
    path = Path(__file__).resolve().parents[2] / "data" / "security_audit.jsonl"
    path.parent.mkdir(parents=True, exist_ok=True)
    with _lock:
        with path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(record, sort_keys=True) + "\n")
