from __future__ import annotations
import json, html
from pathlib import Path

def export_json(record, path):
    p=Path(path); p.parent.mkdir(parents=True,exist_ok=True); p.write_text(json.dumps(record,indent=2,default=str),encoding='utf-8'); return p

def export_html(record, path):
    p=Path(path); p.parent.mkdir(parents=True,exist_ok=True)
    findings=record.get('findings',[])
    rows=''.join(f"<tr><td>{html.escape(str(f.get('severity')))}</td><td>{html.escape(str(f.get('title')))}</td><td>{html.escape(str(f.get('host')))}</td><td>{html.escape(str(f.get('port') or ''))}</td><td>{html.escape(str(f.get('evidence') or ''))}</td></tr>" for f in findings)
    body=f'''<!doctype html><html><head><meta charset="utf-8"><title>HexStrike Assessment</title><style>body{{font-family:Arial;margin:32px}}table{{border-collapse:collapse;width:100%}}td,th{{border:1px solid #ccc;padding:8px;text-align:left}}code{{white-space:pre-wrap}}</style></head><body><h1>HexStrike Security Assessment</h1><p><b>Target:</b> {html.escape(str(record.get('target')))}</p><p><b>Status:</b> {html.escape(str(record.get('status')))}</p><h2>Findings</h2><table><tr><th>Severity</th><th>Title</th><th>Host</th><th>Port</th><th>Evidence</th></tr>{rows}</table></body></html>'''
    p.write_text(body,encoding='utf-8'); return p
