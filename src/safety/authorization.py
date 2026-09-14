import hashlib
import hmac
import os

class AuthorizationError(PermissionError):
    pass

def validate_api_key(provided: str | None, required: bool = True) -> None:
    expected = os.getenv("HEXSTRIKE_API_KEY")
    if not required:
        return
    if not expected or not provided:
        raise AuthorizationError("API authorization is required")
    if not hmac.compare_digest(hashlib.sha256(provided.encode()).digest(), hashlib.sha256(expected.encode()).digest()):
        raise AuthorizationError("Invalid API authorization")
