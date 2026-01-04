from src.llm_recommender import build_incident_summary

def test_build_incident_summary():
    findings = [
        {
            "category": "Brute Force",
            "severity": "high",
            "mitre_id": "T1110",
            "user": "admin",
            "ip": "1.2.3.4"
        },
        {
            "category": "Process Creation",
            "severity": "medium",
            "mitre_id": "T1059",
            "user": "admin",
            "ip": "1.2.3.4"
        }
    ]

    summary = build_incident_summary(findings)

    assert summary["max_severity"] == "high"
    assert "Brute Force" in summary["categories"]
    assert "T1110" in summary["mitre_techniques"]
    assert summary["event_count"] == 2
