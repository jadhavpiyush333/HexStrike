import os
from pathlib import Path
from src.core.target import normalize_target
from src.core.findings import correlate
from src.config.runtime import RuntimeConfig
from src.scanners.scanx.adapter import ScanXScanner


def test_ipv6_authority_and_invalid_target():
    assert normalize_target('https://[2001:db8::1]:8443').authority == '[2001:db8::1]:8443'
    try: normalize_target('bad..host')
    except ValueError: pass
    else: raise AssertionError('invalid hostname accepted')


def test_correlation_keeps_highest_severity():
    fs=[
        {'finding_id':'1','severity':'HIGH','title':'same','host':'h','port':443,'service':'https','source_scanners':['nmap'],'evidence':'a'},
        {'finding_id':'2','severity':'INFO','title':'same','host':'h','port':443,'service':'https','source_scanners':['nuclei'],'evidence':'long evidence'},
    ]
    r=correlate(fs)[0]
    assert r['severity']=='HIGH' and r['confidence']=='HIGH'


def test_scanx_command_template(monkeypatch):
    monkeypatch.setenv('SCANX_ARGS','scan --profile aggressive {target}')
    assert list(ScanXScanner().build_args('example.com','aggressive')) == ['scan','--profile','aggressive','example.com']


def test_runtime_config_is_valid():
    root=Path(__file__).resolve().parents[1]
    assert RuntimeConfig(root).validate()==[]
