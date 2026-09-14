from __future__ import annotations
SEV_WEIGHT={'CRITICAL':0,'HIGH':1,'MEDIUM':2,'LOW':3,'INFO':4}

def recommend(f):
    title=(f.get('title') or '').lower(); service=(f.get('service') or '').lower(); port=f.get('port')
    actions=[]
    if 'ssh' in service or port == 22:
        actions=['Review SSH configuration and authentication policy','Disable unnecessary authentication methods','Restrict administrative access to trusted networks','Update the SSH service when an outdated version is confirmed']
    elif any(x in service or x in title for x in ('http','web','apache','nginx','iis')) or f.get('url'):
        actions=['Review the affected endpoint and server configuration','Remove unnecessary information exposure','Apply the vendor/application security fix when a vulnerability is confirmed','Re-run the web assessment to verify remediation']
    elif any(x in service or x in title for x in ('mysql','mariadb','postgres','mongodb','redis')):
        actions=['Confirm whether the database must be remotely reachable','Restrict database access to trusted hosts or networks','Review authentication and service configuration','Update the database software when a supported security fix exists']
    elif 'tls' in title or 'ssl' in title or 'certificate' in title:
        actions=['Review TLS protocol and cipher configuration','Remove deprecated protocols and weak cryptography','Verify certificate validity and hostname coverage','Re-run TLS/web checks after remediation']
    elif 'version' in title or 'outdated' in title or 'vulnerab' in title:
        actions=['Confirm the detected version with service evidence','Check the vendor security advisory or supported release','Patch or upgrade after change review','Re-scan to verify the finding is resolved']
    else:
        actions=['Review the evidence and confirm the finding manually','Determine whether the exposed service or behavior is required','Apply the least-privilege or hardening control appropriate to the service','Re-run the assessment after remediation']
    priority='IMMEDIATE' if f.get('severity') in ('CRITICAL','HIGH') else ('PLANNED' if f.get('severity')=='MEDIUM' else 'REVIEW')
    return {'priority':priority,'actions':actions,'verification':'Re-run the relevant scanner and confirm the evidence is no longer present.'}
