from src.ai_analysis import analyze_findings

def test_analysis_counts_and_risk():
    a = analyze_findings([
        {"finding_id":"F1","severity":"LOW","host":"127.0.0.1","port":80,"protocol":"tcp"},
        {"finding_id":"F2","severity":"HIGH","host":"127.0.0.1","port":80,"protocol":"tcp"},
    ])
    assert a.risk_level == "HIGH"
    assert a.severity_counts["HIGH"] == 1
    assert a.correlated_groups[0]["finding_count"] == 2
