from __future__ import annotations

def banner(target):
    print('\n'+'='*72); print(' HEXSTRIKE — AUTOMATED SECURITY ASSESSMENT'); print('='*72); print(f'Target: {target}'); print('Mode:   Full automated multi-scanner assessment\n')

def stage(scanner,status,detail=''):
    icon='✓' if status=='completed' else '→' if status=='running' else '!' if status in {'failed','timeout','unavailable'} else '-'
    print(f'[{icon}] {scanner:<12} {status:<12} {detail}')

def finding(f):
    print(f"[{f.get('severity','INFO')}] {f.get('finding_id')} — {f.get('title')}")
    print(f"  Host: {f.get('host')}  Port: {f.get('port') or '-'}  Service: {f.get('service') or '-'}")
    print(f"  Confidence: {f.get('confidence','-')}  Sources: {', '.join(f.get('source_scanners',[])) or '-'}")
    if f.get('description'): print(f"  What it means: {f.get('description')}")
    if f.get('evidence'): print(f"  Evidence: {f.get('evidence')}")

def findings_detail(findings):
    print('\n'+'-'*72); print(' FINDINGS'); print('-'*72)
    if not findings: print('  No normalized findings returned by the available scanners.'); return
    order={'CRITICAL':0,'HIGH':1,'MEDIUM':2,'LOW':3,'INFO':4}
    for f in sorted(findings,key=lambda x:(order.get(x.get('severity'),4),str(x.get('host')),str(x.get('port')))):
        finding(f); print()

def summary(findings):
    print('\n'+'-'*72); print(' FINDINGS SUMMARY'); print('-'*72)
    for s in ('CRITICAL','HIGH','MEDIUM','LOW','INFO'): print(f'  {s:<9}: {sum(1 for f in findings if f.get("severity")==s)}')

def risk(risk):
    print(f"\n Overall Risk: {risk.get('level','INFO')} ({risk.get('score',0)}/100)")

def skipped(items):
    if not items: return
    print('\n'+'-'*72); print(' SKIPPED / UNAVAILABLE STAGES'); print('-'*72)
    for item in items: print(f"  - {item.get('scanner')}: {item.get('reason')}")

def recommendations(findings, fn):
    print('\n' + '-' * 72)
    print(' WHAT TO DO NEXT')
    print('-' * 72)

    if not findings:
        print('  No remediation recommendations generated.')
        return

    for i, finding_data in enumerate(findings[:10], 1):
        rec = fn(finding_data)

        severity = finding_data.get('severity', 'INFO')
        title = finding_data.get('title', 'Scanner observation')
        priority = rec.get('priority', 'REVIEW')
        actions = rec.get('actions', [])
        verification = rec.get(
            'verification',
            'Re-run the relevant scanner and confirm the evidence is no longer present.'
        )

        print(f"{i}. [{severity}] {title} ({priority})")

        for action in actions:
            print(f"   • {action}")

        print(f"   Verify: {verification}")
        print()
