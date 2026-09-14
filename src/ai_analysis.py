from __future__ import annotations
from collections import Counter
from dataclasses import dataclass
from typing import Any

SEVERITY_ORDER = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}

@dataclass
class Analysis:
    summary: str
    risk_level: str
    finding_count: int
    severity_counts: dict[str, int]
    recommendations: list[str]
    correlated_groups: list[dict[str, Any]]


def analyze_findings(findings: list[dict[str, Any]]) -> Analysis:
    counts = Counter(str(f.get("severity", "INFO")).upper() for f in findings)
    highest = max((SEVERITY_ORDER.get(s, 0) for s in counts), default=0)
    risk = next((s for s, n in SEVERITY_ORDER.items() if n == highest), "INFO")

    groups: dict[str, list[dict[str, Any]]] = {}
    for f in findings:
        key = f"{f.get('host','unknown')}:{f.get('port','')}:{f.get('protocol','')}"
        groups.setdefault(key, []).append(f)

    recommendations = []
    if counts.get("CRITICAL", 0) or counts.get("HIGH", 0):
        recommendations.append("Prioritize validation and remediation of high-impact findings before lower-risk observations.")
    if counts.get("MEDIUM", 0):
        recommendations.append("Review medium-risk configuration and service findings and verify exposure manually.")
    if counts.get("LOW", 0) or counts.get("INFO", 0):
        recommendations.append("Use informational observations to improve hardening and asset inventory accuracy.")
    if not recommendations:
        recommendations.append("No actionable findings were returned; retain the scan evidence for audit purposes.")

    return Analysis(
        summary=f"Analyzed {len(findings)} normalized finding(s); highest observed severity is {risk}.",
        risk_level=risk,
        finding_count=len(findings),
        severity_counts=dict(sorted(counts.items())),
        recommendations=recommendations,
        correlated_groups=[{"asset": k, "finding_count": len(v), "finding_ids": [x.get("finding_id") for x in v]} for k, v in groups.items()],
    )
