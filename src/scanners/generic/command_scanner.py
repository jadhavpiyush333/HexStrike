from __future__ import annotations
import json
import shutil
import subprocess
from typing import Sequence
from ..base import ScanResult, Scanner

class CommandScanner(Scanner):
    executable: str

    def health(self) -> bool:
        return shutil.which(self.executable) is not None

    def build_args(self, target: str, profile: str) -> Sequence[str]:
        raise NotImplementedError(f'{self.name} must implement build_args()')

    def parse(self, target: str, stdout: str) -> list[dict]:
        out=[]
        for line in stdout.splitlines():
            line=line.strip()
            if not line: continue
            try:
                obj=json.loads(line)
            except json.JSONDecodeError:
                obj=None
            if isinstance(obj,dict):
                info=obj.get('info',{}) if isinstance(obj.get('info'),dict) else {}
                matched=obj.get('matched-at') or obj.get('matched_at')
                out.append({
                    'title': info.get('name') or obj.get('template-id') or obj.get('template_id') or obj.get('name') or 'Scanner finding',
                    'severity': info.get('severity') or obj.get('severity') or 'INFO',
                    'description': info.get('description') or obj.get('description') or '',
                    'evidence': obj.get('extracted-results') or obj.get('extracted_results') or obj.get('matcher-name') or matched or line,
                    'url': matched or obj.get('url') or target,
                    'host': obj.get('host') or target,
                    'port': obj.get('port'),
                    'service': obj.get('service'),
                    'template_id': obj.get('template-id') or obj.get('template_id'),
                })
            else:
                out.append({'target':target,'observation':line,'severity':'INFO'})
        return out[:1000]

    def scan(self, target: str, profile: str, timeout: int = 120) -> ScanResult:
        if not self.health():
            return ScanResult(self.name,target,'unavailable',error=f'{self.executable} executable not found')
        try:
            args=list(self.build_args(target,profile))
            proc=subprocess.run([self.executable,*args],capture_output=True,text=True,timeout=timeout,check=False)
        except subprocess.TimeoutExpired as exc:
            return ScanResult(self.name,target,'timeout',raw=(exc.stdout or ''),error='scan timed out')
        except (OSError,ValueError) as exc:
            return ScanResult(self.name,target,'failed',error=str(exc))
        findings=self.parse(target,proc.stdout or '')
        status='completed' if proc.returncode==0 else 'failed'
        return ScanResult(self.name,target,status,findings,proc.stdout or '',proc.stderr or None,{'returncode':proc.returncode,'argv':[self.executable,*args]})
