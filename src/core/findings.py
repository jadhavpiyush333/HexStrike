from __future__ import annotations
from hashlib import sha256

SEVERITIES=('CRITICAL','HIGH','MEDIUM','LOW','INFO')
_RANK={s:len(SEVERITIES)-i for i,s in enumerate(SEVERITIES)}

def _severity(text):
    s=str(text or '').upper()
    for level in SEVERITIES:
        if level in s: return level
    return 'INFO'

def normalize_findings(records:list[dict],scanner:str,target:str)->list[dict]:
    out=[]
    for raw in records or []:
        if not isinstance(raw,dict): continue
        title=raw.get('title') or raw.get('name') or raw.get('finding') or raw.get('observation') or raw.get('service') or 'Scanner observation'
        evidence=raw.get('evidence') or raw.get('observation') or raw.get('output') or raw.get('description') or ''
        severity=_severity(raw.get('severity'))
        host=raw.get('host') or target
        port=raw.get('port')
        service=raw.get('service') or raw.get('product')
        protocol=raw.get('protocol')
        url=raw.get('url')
        key=f'{host}|{port}|{service}|{url}|{title}'.lower()
        fid='F-'+sha256(key.encode()).hexdigest()[:12].upper()
        out.append({'finding_id':fid,'severity':severity,'title':str(title),'target':target,'host':host,'port':port,'protocol':protocol,'service':service,'url':url,'description':raw.get('description') or str(title),'evidence':str(evidence),'source_scanners':[scanner],'confidence':'MEDIUM'})
    return out

def correlate(findings:list[dict])->list[dict]:
    grouped={}
    for f in findings:
        key=(str(f.get('host')),str(f.get('port')),str(f.get('service')),f.get('title','').strip().lower())
        if key not in grouped: grouped[key]=dict(f)
        else:
            g=grouped[key]
            g['source_scanners']=sorted(set(g.get('source_scanners',[]))|set(f.get('source_scanners',[])))
            g['confidence']='HIGH' if len(g['source_scanners'])>=2 else g.get('confidence','MEDIUM')
            if len(f.get('evidence',''))>len(g.get('evidence','')): g['evidence']=f['evidence']
            if _RANK.get(f.get('severity'),0)>_RANK.get(g.get('severity'),0): g['severity']=f['severity']
    return list(grouped.values())

def merge_scanner_findings(scans:list[dict],target:str)->list[dict]:
    raw=[]
    for scan in scans: raw.extend(normalize_findings(scan.get('findings',[]),scan.get('scanner','unknown'),target))
    return correlate(raw)
