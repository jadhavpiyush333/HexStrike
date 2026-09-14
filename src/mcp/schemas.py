from pydantic import BaseModel, Field

class ScanToolInput(BaseModel):
    target: str = Field(min_length=1, max_length=255)
    profile: str = Field(default="safe", pattern=r"^[a-z0-9_-]{1,32}$")
    scanner: str = Field(default="nmap", pattern=r"^[a-z0-9_-]{1,32}$")

class ScanStatusInput(BaseModel):
    scan_id: str = Field(pattern=r"^SCAN-[A-F0-9]{10}$")
