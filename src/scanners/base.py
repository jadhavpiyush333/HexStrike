from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any

@dataclass
class ScanResult:
    scanner: str
    target: str
    status: str
    findings: list[dict[str, Any]] = field(default_factory=list)
    raw: str = ""
    error: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)

class Scanner(ABC):
    name: str

    @abstractmethod
    def health(self) -> bool: ...

    @abstractmethod
    def scan(self, target: str, profile: str, timeout: int = 120) -> ScanResult: ...
