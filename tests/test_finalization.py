from pathlib import Path
from src.config.runtime import RuntimeConfig
from src.core.findings import correlate
from src.intelligence.asset import build_asset_inventory, attack_surface_summary
from src.intelligence.risk import score_findings
from src.results.store import ResultStore

def test_config_valid():
    assert RuntimeConfig(Path('.')).validate()==[]

def test_correlation_sets_confidence():
    fs=[{'finding_id':'1','severity':'LOW','title':'x','host':'a','port':80,'service':'http','source_scanners':['nmap'],'evidence':'a'}, {'finding_id':'2','severity':'MEDIUM','title':'x','host':'a','port':80,'service':'http','source_scanners':['nikto'],'evidence':'long evidence'}]
    out=correlate(fs); assert len(out)==1; assert out[0]['confidence']=='HIGH'; assert out[0]['severity']=='MEDIUM'

def test_asset_inventory_and_attack_surface():
    fs=[{'host':'10.0.0.1','port':80,'service':'http','url':'http://10.0.0.1'}, {'host':'10.0.0.1','port':22,'service':'ssh'}]
    a=build_asset_inventory(fs); assert a[0]['tags']==['remote-access','web']; assert attack_surface_summary(fs)['unique_open_ports']==2

def test_risk_score():
    r=score_findings([{'severity':'HIGH','title':'x'}]); assert r['level']=='HIGH'; assert r['score']>0

def test_store_roundtrip(tmp_path):
    s=ResultStore(tmp_path); rec={'scan_id':'SCAN-TEST','status':'completed','findings':[]}; s.save(rec); assert s.get('SCAN-TEST')['status']=='completed'
