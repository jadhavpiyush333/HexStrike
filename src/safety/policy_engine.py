from dataclasses import dataclass
from pathlib import Path
import yaml

@dataclass(frozen=True)
class ScanPolicy:
    name: str
    timeout_seconds: int = 120
    max_concurrent: int = 2

    def validate(self) -> None:
        if not self.name:
            raise ValueError("Unsupported or unsafe scan profile")
        if not 1 <= self.timeout_seconds <= 600:
            raise ValueError("Invalid scan timeout policy")
        if not 1 <= self.max_concurrent <= 10:
            raise ValueError("Invalid concurrency policy")

def load_policies(base: Path) -> dict[str, ScanPolicy]:
    path = base / "config" / "security.yaml"
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    result = {}
    for name, cfg in data.get("profiles", {}).items():
        policy = ScanPolicy(name, int(cfg.get("timeout_seconds", 120)), int(cfg.get("max_concurrent", 2)))
        policy.validate()
        result[name] = policy
    return result
