from __future__ import annotations
import json
from pathlib import Path
from typing import Any

def render_markdown(record: dict[str, Any]) -> str:
    a=record.get('analysis') or {}; fs=record.get('findings') or []
    lines=[f"# HexStrike Security Assessment — {record.get('target','unknown')}","",f"- Assessment ID: `{record.get('assessment_id',record.get('scan_id',''))}`",f"- Status: **{record.get('status','unknown')}**",f"- Risk: **{a.get('risk_level','INFO')}**","", "## Summary", a.get('summary','No analysis available.'), "", "## Severity"]
    lines += [f"- {k}: {v}" for k,v in (a.get('severity_counts') or {}).items()]
    lines += ["", "## Findings"]
    if not fs: lines.append("No findings were returned.")
    for i,f in enumerate(fs,1):
        lines += [f"### {i}. {f.get('title') or f.get('name') or 'Observation'}",f"- Severity: `{f.get('severity','INFO')}`",f"- Host: `{f.get('host','')}`",f"- Port: `{f.get('port','')}`",f"- Evidence: {f.get('evidence','')}",f"- Recommendation: {f.get('recommendation','')}",""]
    lines += ["## Recommendations"] + [f"- {x}" for x in (a.get('recommendations') or [])]
    if record.get('skipped'): lines += ["", "## Skipped Scanners"] + [f"- **{x.get('scanner')}** — {x.get('reason')}" for x in record['skipped']]
    return "\n".join(lines)+"\n"

def write_report(record: dict[str, Any], base_path: Path, fmt: str) -> Path:
    out=Path(base_path)/'data'/'reports'; out.mkdir(parents=True,exist_ok=True)
    rid=record.get('assessment_id') or record.get('scan_id') or 'report'
    p=out/f"{rid}.{'json' if fmt=='json' else 'md'}"
    p.write_text(json.dumps(record,indent=2,default=str) if fmt=='json' else render_markdown(record),encoding='utf-8')
    return p
