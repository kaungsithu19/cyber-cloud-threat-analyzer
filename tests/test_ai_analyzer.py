from src.ai_analyzer import AIAnalyzer

def test_ai_analyzer_detects_bruteforce():
    analyzer = AIAnalyzer()

    logs = [
        {"message": "Failed password for admin from 1.2.3.4"},
        {"message": "Failed password for admin from 1.2.3.4"},
        {"message": "Failed password for admin from 1.2.3.4"},
    ]

    results = analyzer.analyze(logs)

    assert results[-1]["severity"] == "medium"
    assert results[-1]["category"] == "Brute Force"