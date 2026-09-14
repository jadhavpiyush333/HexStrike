from pathlib import Path
import yaml

BASE = Path(__file__).resolve().parents[2]
ALLOWLIST = yaml.safe_load((BASE / "config" / "targets.yaml").read_text(encoding="utf-8"))["targets"]
