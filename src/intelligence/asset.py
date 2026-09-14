from __future__ import annotations
from collections import Counter
import re

WEB_PORTS={80,81,443,3000,5000,8000,8008,8080,8081,8443,8888,9000,9001}
DB_PORTS={1433,1521,3306,5432,6379,9200,27017}
REMOTE_PORTS={22,23,3389,5900,5985,5986}

def build_asset_inventory(findings):
    hosts={}
    for f in findings:
        host=f.get('host') or f.get('target')
        if not host: continue
        h=hosts.setdefault(host, {'host':host,'open_ports':[],'web_endpoints':[],'services':[],'tags':set()})
        port=f.get('port')
        if port is not None and port not in h['open_ports']: h['open_ports'].append(port)
        svc=f.get('service') or f.get('title')
        if svc and svc not in h['services']: h['services'].append(svc)
        try:p=int(port)
        except (TypeError,ValueError):p=None
        if p in WEB_PORTS:
            h['tags'].add('web')
            if f.get('url') and f['url'] not in h['web_endpoints']: h['web_endpoints'].append(f['url'])
        if p in DB_PORTS: h['tags'].add('database')
        if p in REMOTE_PORTS: h['tags'].add('remote-access')
    out=[]
    for h in hosts.values():
        h['open_ports']=sorted(h['open_ports']); h['tags']=sorted(h['tags']); out.append(h)
    return sorted(out,key=lambda x:x['host'])

def attack_surface_summary(findings):
    ports=[]
    for f in findings:
        if f.get('port') is not None: ports.append(f.get('port'))
    c=Counter(ports)
    return {'unique_open_ports':len(c),'most_common_ports':[{'port':p,'count':n} for p,n in c.most_common(10)]}
