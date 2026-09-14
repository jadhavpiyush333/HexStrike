from __future__ import annotations
from dataclasses import dataclass
from urllib.parse import urlparse
import ipaddress
import re

_HOST_RE = re.compile(r"^[A-Za-z0-9.-]+$")

@dataclass(frozen=True)
class Target:
    raw: str
    host: str
    scheme: str | None = None
    port: int | None = None

    @property
    def is_url(self) -> bool:
        return self.scheme is not None

    @property
    def is_ip(self) -> bool:
        try:
            ipaddress.ip_address(self.host)
            return True
        except ValueError:
            return False

    @property
    def authority(self) -> str:
        host = f"[{self.host}]" if ":" in self.host else self.host
        if self.port and not ((self.scheme == 'http' and self.port == 80) or (self.scheme == 'https' and self.port == 443)):
            return f"{host}:{self.port}"
        return host

    @property
    def url(self) -> str | None:
        return f"{self.scheme}://{self.authority}" if self.scheme else None


def normalize_target(value: str) -> Target:
    value = str(value or '').strip()
    if not value or len(value) > 255 or any(c in value for c in ';|&`$<>{}\n\r\x00'):
        raise ValueError('Invalid target')
    candidate = value if '://' in value else f'//{value}'
    try:
        parsed = urlparse(candidate)
        host = parsed.hostname
        port = parsed.port
    except ValueError as exc:
        raise ValueError('Invalid target') from exc
    if not host:
        raise ValueError('Target host is missing')
    try:
        ipaddress.ip_address(host)
    except ValueError:
        if not _HOST_RE.fullmatch(host) or '..' in host or host.startswith('.') or host.endswith('.'):
            raise ValueError('Invalid hostname')
        labels = host.split('.')
        if any(not label or label.startswith('-') or label.endswith('-') for label in labels):
            raise ValueError('Invalid hostname')
    scheme = parsed.scheme.lower() if parsed.scheme else None
    if scheme and scheme not in {'http', 'https'}:
        raise ValueError('Only HTTP and HTTPS targets are supported')
    if port is not None and not 1 <= port <= 65535:
        raise ValueError('Invalid target port')
    return Target(raw=value, host=host, scheme=scheme, port=port)
