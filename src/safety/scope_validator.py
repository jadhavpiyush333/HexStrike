from src.core.target import normalize_target

class ScopeError(ValueError):
    pass

def validate_target(target: str, allowlist=None) -> str:
    """Validate target syntax without requiring pre-registration in a target file."""
    try:
        return normalize_target(target).host
    except ValueError as exc:
        raise ScopeError(str(exc)) from exc
