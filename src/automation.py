from __future__ import annotations
from dataclasses import dataclass, field
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any, Callable
import os, uuid
from src.services.scan_service import start_scan
from src.scanners.registry import build_registry
from src.ai_analysis import analyze_findings
from src.core.target import normalize_target
from src.core.findings import merge_scanner_findings
from src.core.recommendations import recommend
from src.core.target import Target
from src.intelligence.asset import build_asset_inventory, attack_surface_summary
from src.intelligence.risk import score_findings
from src.ui.terminal import banner, stage, findings_detail, summary, risk, recommendations, skipped

WEB_PORTS={80,81,443,3000,5000,8000,8008,8080,8081,8443,8888,9000,9001}
WEB_SCANNERS=('httpx','whatweb','nikto','nuclei','gobuster','ffuf')
DOMAIN_SCANNERS=('amass','subfinder')

@dataclass
class AssessmentResult:
    assessment_id:str; target:str; status:str
    scans:list[dict[str,Any]]=field(default_factory=list)
    findings:list[dict[str,Any]]=field(default_factory=list)
    analysis:dict[str,Any]|None=None
    skipped:list[dict[str,str]]=field(default_factory=list)
    assets:list[dict[str,Any]]=field(default_factory=list)
    attack_surface:dict[str,Any]=field(default_factory=dict)
    risk:dict[str,Any]=field(default_factory=dict)

class AssessmentEngine:
    def __init__(self, allowlist, base_path, scan_runner:Callable=start_scan, live=True):
        self.allowlist=allowlist; self.base_path=base_path; self.scan_runner=scan_runner; self.live=live

    def assess(self,target,profile='aggressive'):
        t=normalize_target(target); aid=f'ASSESS-{uuid.uuid4().hex[:10].upper()}'
        r=AssessmentResult(aid,t.raw,'running'); registry=build_registry()
        if self.live: banner(t.raw)
        nmap=self._run(r,'nmap',t.host,profile,registry)
        nmap_findings=nmap.get('findings',[]) if nmap else []
        web_urls=self._discover_urls(t,nmap_findings)
        if web_urls:
            scanners=['httpx','whatweb','nikto','nuclei']
            if os.getenv('HEXSTRIKE_WEB_WORDLIST'): scanners += ['gobuster','ffuf']
            else:
                for s in ('gobuster','ffuf'): r.skipped.append({'scanner':s,'reason':'HEXSTRIKE_WEB_WORDLIST is not configured'})
            with ThreadPoolExecutor(max_workers=min(6,max(1,len(scanners)*len(web_urls)))) as pool:
                fs=[pool.submit(self._run,r,s,u,profile,registry) for s in scanners for u in web_urls]
                for f in as_completed(fs): f.result()
        else:
            for s in WEB_SCANNERS: r.skipped.append({'scanner':s,'reason':'No HTTP(S) service discovered'})
        self._run(r,'scanx',t.host,profile,registry)
        if self._is_domain(t.host):
            with ThreadPoolExecutor(max_workers=2) as pool:
                fs=[pool.submit(self._run,r,s,t.host,profile,registry) for s in DOMAIN_SCANNERS]
                for f in fs: f.result()
        else:
            for s in DOMAIN_SCANNERS:r.skipped.append({'scanner':s,'reason':'Domain enumeration is not applicable to an IP target'})
        r.findings=merge_scanner_findings(r.scans,t.raw)
        r.analysis=analyze_findings(r.findings).__dict__
        r.assets=build_asset_inventory(r.findings); r.attack_surface=attack_surface_summary(r.findings); r.risk=score_findings(r.findings)
        r.status='completed_with_warnings' if any(x.get('status') in {'unavailable','failed','timeout'} for x in r.scans) or r.skipped else 'completed'
        if self.live:
            findings_detail(r.findings); summary(r.findings); risk(r.risk); skipped(r.skipped); recommendations(r.findings,recommend)
            print(f'\nAssessment {r.status}. Results were displayed in this terminal; no report was generated.')
        return r

    def _run(self,r,scanner,target,profile,registry):
        if scanner not in registry:
            r.skipped.append({'scanner':scanner,'reason':'Scanner adapter not registered'}); return None
        if self.live: stage(scanner,'running',target)
        try:
            rec=self.scan_runner(target,profile,self.allowlist,self.base_path,scanner); r.scans.append(rec)
            if self.live: stage(scanner,rec.get('status','unknown'),f"findings={len(rec.get('findings',[]))}")
            return rec
        except (ValueError,RuntimeError) as exc:
            r.skipped.append({'scanner':scanner,'reason':str(exc)})
            if self.live: stage(scanner,'skipped',str(exc))
            return None

    @staticmethod
    def _discover_urls(target:Target, findings):
        urls=[]
        for f in findings:
            try:p=int(f.get('port'))
            except (TypeError,ValueError):continue
            if p in WEB_PORTS:
                scheme='https' if p in {443,8443} else 'http'; suffix='' if p in {80,443} else f':{p}'
                urls.append(f'{scheme}://{target.host}{suffix}')
        return list(dict.fromkeys(urls))

    @staticmethod
    def _is_domain(host):
        import ipaddress
        try: ipaddress.ip_address(host); return False
        except ValueError: return '.' in host
