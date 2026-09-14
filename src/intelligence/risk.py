from __future__ import annotations
SEV={'CRITICAL':10,'HIGH':7,'MEDIUM':4,'LOW':2,'INFO':0}

def score_findings(findings):
    raw=sum(SEV.get(str(f.get('severity','INFO')).upper(),0) for f in findings)
    critical=sum(1 for f in findings if str(f.get('severity')).upper()=='CRITICAL')
    high=sum(1 for f in findings if str(f.get('severity')).upper()=='HIGH')
    # Cap to a stable 0-100 risk score while retaining severity dominance.
    score=min(100, raw + critical*10 + high*4)
    if critical: level='CRITICAL'
    elif high or score>=30: level='HIGH'
    elif score>=12: level='MEDIUM'
    elif findings: level='LOW'
    else: level='INFO'
    return {'score':score,'level':level,'finding_count':len(findings)}
