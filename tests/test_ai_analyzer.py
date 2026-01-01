from src.ai_analyzer import AIAnalyzer

def test_ai_analyzer_detects_bruteforce():
    analyzer = AIAnalyzer()

    logs = [
        {"process": "sshd", "message": "Failed password for admin from 1.2.3.4"},
        {"process": "sshd", "message": "Failed password for admin from 1.2.3.4"},
        {"process": "sshd", "message": "Failed password for admin from 1.2.3.4"},
    ]

    results = analyzer.analyze(logs)

    assert len(results) == 1
    result = results[0]

    assert result["category"] == "Brute Force"
    assert result["severity"] == "medium"
    assert result["ip"] == "1.2.3.4"
    assert result["user"] == "admin"
