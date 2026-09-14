from __future__ import annotations
import json, os, urllib.request

def local_ollama_analysis(findings, analysis, model=None):
    """Optional local Ollama enrichment. Falls back cleanly when Ollama is unavailable."""
    model=model or os.getenv('HEXSTRIKE_OLLAMA_MODEL','gemma3:4b')
    prompt=('You are a defensive security analyst. Summarize the supplied findings, prioritize remediation, '
            'and avoid suggesting destructive actions. Return concise JSON with keys summary, priorities, caveats.\n\n'
            + json.dumps({'findings':findings[:40],'analysis':analysis},default=str))
    payload=json.dumps({'model':model,'prompt':prompt,'stream':False}).encode()
    req=urllib.request.Request(os.getenv('OLLAMA_URL','http://127.0.0.1:11434/api/generate'),data=payload,headers={'Content-Type':'application/json'})
    try:
        with urllib.request.urlopen(req,timeout=30) as r: data=json.loads(r.read().decode())
        text=data.get('response','').strip()
        return {'enabled':True,'model':model,'response':text}
    except Exception as exc:
        return {'enabled':False,'model':model,'error':str(exc)}
