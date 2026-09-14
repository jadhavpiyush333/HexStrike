from __future__ import annotations
import json
from pathlib import Path
from typing import Any
class ResultStore:
    def __init__(self, base_path: Path): self.root=Path(base_path)/'data'/'results'; self.root.mkdir(parents=True,exist_ok=True)
    def _path(self,rid): return self.root/("".join(c for c in rid if c.isalnum() or c in '-_')+'.json')
    def save(self,record:dict[str,Any]):
        rid=record.get('scan_id') or record.get('assessment_id')
        if not rid: raise ValueError('record requires scan_id or assessment_id')
        self._path(rid).write_text(json.dumps(record,indent=2,default=str),encoding='utf-8')
    def get(self,rid):
        p=self._path(rid); return json.loads(p.read_text(encoding='utf-8')) if p.exists() else None
    def list(self):
        out=[]
        for p in sorted(self.root.glob('*.json'),key=lambda x:x.stat().st_mtime,reverse=True):
            try: out.append(json.loads(p.read_text(encoding='utf-8')))
            except Exception: pass
        return out
