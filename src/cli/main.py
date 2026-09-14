from __future__ import annotations
import argparse, json, sys
from pathlib import Path
import yaml
from src.scanners.registry import build_registry
from src.services.scan_service import start_scan
from src.ai_analysis import analyze_findings
from src.automation import AssessmentEngine
from src.results.store import ResultStore
from src.config.runtime import RuntimeConfig
from src.export.exports import export_json, export_html
from src.ai_agent import local_ollama_analysis

BASE=Path(__file__).resolve().parents[2]; STORE=ResultStore(BASE); CFG=RuntimeConfig(BASE)
PROFILES=('aggressive','safe','soc_evidence')

def allow():
    p=BASE/'config'/'targets.yaml'; return (yaml.safe_load(p.read_text()) or {}).get('targets',[]) if p.exists() else []
def dump(x,j=False):
    if j: print(json.dumps(x,indent=2,default=str)); return
    if isinstance(x,dict): print('\n'.join(f'{k}: {v}' for k,v in x.items()))
    elif isinstance(x,list): print('\n'.join(map(str,x)))
    else: print(x)
def parser():
    p=argparse.ArgumentParser(prog='hexstrike',description='HexStrike + ScanX CLI-first security automation')
    p.add_argument('--version',action='version',version='HexStrike-ScanX 1.0.0')
    s=p.add_subparsers(dest='command')
    s.add_parser('health'); s.add_parser('doctor'); s.add_parser('self-test')
    c=s.add_parser('config'); cs=c.add_subparsers(dest='subcommand'); cs.add_parser('validate'); cs.add_parser('profiles'); q=cs.add_parser('show'); q.add_argument('profile',choices=PROFILES)
    t=s.add_parser('target'); ts=t.add_subparsers(dest='subcommand'); ts.add_parser('list'); a=ts.add_parser('add'); a.add_argument('target'); r=ts.add_parser('remove'); r.add_argument('target')
    sc=s.add_parser('scanner'); ss=sc.add_subparsers(dest='subcommand'); ss.add_parser('list'); ss.add_parser('health')
    x=s.add_parser('scan'); xs=x.add_subparsers(dest='subcommand')
    q=xs.add_parser('run'); q.add_argument('scanner'); q.add_argument('target'); q.add_argument('--profile',choices=PROFILES,default='aggressive'); q.add_argument('--json',action='store_true')
    for n in build_registry():
        q=xs.add_parser(n); q.add_argument('target'); q.add_argument('--profile',choices=PROFILES,default='aggressive'); q.add_argument('--json',action='store_true')
    for n in ('status','results'):
        q=xs.add_parser(n); q.add_argument('scan_id'); q.add_argument('--json',action='store_true')
    f=s.add_parser('findings'); fs=f.add_subparsers(dest='subcommand'); q=fs.add_parser('list'); q.add_argument('record_id',nargs='?'); q.add_argument('--json',action='store_true'); q=fs.add_parser('show'); q.add_argument('finding_id')
    q=s.add_parser('analyze'); q.add_argument('record_id'); q.add_argument('--json',action='store_true')
    q=s.add_parser('assess'); q.add_argument('target'); q.add_argument('--profile',choices=PROFILES,default='aggressive'); q.add_argument('--json',action='store_true'); q.add_argument('--ai',action='store_true')
    h=s.add_parser('history'); h.add_argument('--limit',type=int,default=20); h.add_argument('--json',action='store_true')
    e=s.add_parser('export'); e.add_argument('record_id'); e.add_argument('--format',choices=('json','html'),default='json'); e.add_argument('--output',required=True)
    m=s.add_parser('mcp'); ms=m.add_subparsers(dest='subcommand'); ms.add_parser('start'); ms.add_parser('tools')
    return p

def rec(rid): return STORE.get(rid)

def main(argv=None):
    a=parser().parse_args(argv); reg=build_registry()
    if a.command=='health':
        print('HexStrike CLI: OK'); [print(f'  {n:<10} {"READY" if s.health() else "UNAVAILABLE"}') for n,s in reg.items()]; return 0
    if a.command=='self-test':
        # Internal deterministic checks; does not execute external scanners.
        from src.core.target import normalize_target
        from src.core.findings import correlate
        from src.intelligence.risk import score_findings
        checks=[]
        try:
            assert normalize_target('https://example.com:8443').authority == 'example.com:8443'
            checks.append('target normalization')
            fs=[{'finding_id':'F-A','severity':'HIGH','title':'Test','host':'example.com','port':443,'service':'https','source_scanners':['a'],'evidence':'x'}, {'finding_id':'F-B','severity':'INFO','title':'Test','host':'example.com','port':443,'service':'https','source_scanners':['b'],'evidence':'longer'}]
            merged=correlate(fs); assert len(merged)==1 and merged[0]['severity']=='HIGH' and merged[0]['confidence']=='HIGH'; checks.append('finding correlation')
            assert score_findings(merged)['level']=='HIGH'; checks.append('risk scoring')
            print('Self-test: PASS'); [print('  ✓ '+c) for c in checks]; return 0
        except Exception as exc:
            print(f'Self-test: FAIL — {exc}', file=sys.stderr); return 1
    if a.command=='doctor':
        errs=CFG.validate(); print('Configuration: '+('OK' if not errs else 'ERRORS'))
        for e in errs: print('  - '+e)
        print('Scanners:'); [print(f'  {n:<10} {"READY" if s.health() else "UNAVAILABLE"}') for n,s in reg.items()]
        print('Optional: HEXSTRIKE_WEB_WORDLIST='+('configured' if __import__('os').getenv('HEXSTRIKE_WEB_WORDLIST') else 'not configured'))
        return 1 if errs else 0
    if a.command=='config':
        if a.subcommand=='validate':
            errs=CFG.validate(); print('Configuration valid' if not errs else '\n'.join(errs)); return 0 if not errs else 1
        if a.subcommand=='profiles': dump(CFG.security().get('profiles',{})); return 0
        dump(CFG.security().get('profiles',{}).get(a.profile,{})); return 0
    if a.command=='scanner':
        if a.subcommand=='list': [print(n) for n in reg]; return 0
        dump({n:s.health() for n,s in reg.items()},True); return 0
    if a.command=='target':
        targets=allow(); p=BASE/'config'/'targets.yaml'
        if a.subcommand=='list': [print(t) for t in targets]; return 0
        if a.subcommand=='add':
            if a.target not in targets: targets.append(a.target); p.write_text(yaml.safe_dump({'targets':targets},sort_keys=False))
            print(f'Added: {a.target}'); return 0
        if a.subcommand=='remove':
            if a.target not in targets: print('Target not found',file=sys.stderr); return 1
            targets.remove(a.target); p.write_text(yaml.safe_dump({'targets':targets},sort_keys=False)); print(f'Removed: {a.target}'); return 0
    if a.command=='scan':
        if a.subcommand in reg or a.subcommand=='run':
            scanner=a.subcommand if a.subcommand!='run' else a.scanner
            try: z=start_scan(a.target,a.profile,allow(),BASE,scanner); STORE.save(z); dump(z,a.json); return 0
            except Exception as e: print(f'Scan failed: {e}',file=sys.stderr); return 2
        if a.subcommand in ('status','results'):
            z=rec(a.scan_id)
            if not z: print('Scan not found',file=sys.stderr); return 1
            dump(z,a.json); return 0
    if a.command=='assess':
        try:
            r=AssessmentEngine(allow(),BASE,live=not a.json).assess(a.target,a.profile)
            z={'assessment_id':r.assessment_id,'target':r.target,'status':r.status,'profile':a.profile,'scans':r.scans,'findings':r.findings,'skipped':r.skipped,'analysis':r.analysis,'assets':r.assets,'attack_surface':r.attack_surface,'risk':r.risk,'created_at':__import__('datetime').datetime.now(__import__('datetime').timezone.utc).isoformat()}
            if a.ai: z['ai_analysis']=local_ollama_analysis(r.findings,r.analysis)
            STORE.save(z)
            if a.json: dump(z,True)
            else:
                print(f'\nAssessment ID: {r.assessment_id}\nFindings: {len(r.findings)}\nRisk: {r.risk.get("level")} ({r.risk.get("score")}/100)')
            return 0
        except Exception as e: print(f'Assessment failed: {e}',file=sys.stderr); return 2
    if a.command=='history':
        rows=STORE.list()[:a.limit]
        out=[{'id':r.get('assessment_id') or r.get('scan_id'),'type':'assessment' if r.get('assessment_id') else 'scan','target':r.get('target'),'status':r.get('status'),'findings':len(r.get('findings',[])),'created_at':r.get('created_at')} for r in rows]
        dump(out,a.json); return 0
    if a.command=='export':
        z=rec(a.record_id)
        if not z: print('Record not found',file=sys.stderr); return 1
        p=export_json(z,a.output) if a.format=='json' else export_html(z,a.output); print(f'Exported: {p}'); return 0
    if a.command=='findings':
        if a.subcommand=='list':
            z=rec(a.record_id) if a.record_id else None; fs=z.get('findings',[]) if z else [f for r in STORE.list() for f in r.get('findings',[])]; dump(fs,a.json); return 0
        for r in STORE.list():
            for f in r.get('findings',[]):
                if f.get('finding_id')==a.finding_id: dump(f,True); return 0
        print('Finding not found',file=sys.stderr); return 1
    if a.command=='analyze':
        z=rec(a.record_id)
        if not z: print('Record not found',file=sys.stderr); return 1
        dump(analyze_findings(z.get('findings',[])).__dict__,a.json); return 0
    if a.command=='mcp':
        if a.subcommand=='start': from src.mcp.server import mcp; mcp.run(transport='stdio'); return 0
        print('MCP server exposes scanner, status, result, and analysis tools. Run `hexstrike mcp start`.'); return 0
    parser().print_help(); return 0
if __name__=='__main__': raise SystemExit(main())
