from pathlib import Path
from src.services.scan_service import start_scan

def test_runtime_target_is_not_required_in_targets_file():
    base=Path(__file__).resolve().parents[1]
    result=start_scan('10.0.0.25','aggressive',[],base,'nmap')
    assert result['target']=='10.0.0.25'
    assert result['profile']=='aggressive'
    assert result['status'] in {'unavailable','completed','failed','timeout'}

def test_url_target_is_accepted_at_runtime():
    base=Path(__file__).resolve().parents[1]
    result=start_scan('http://10.0.0.25:8080','aggressive',[],base,'httpx')
    assert result['target']=='http://10.0.0.25:8080'
