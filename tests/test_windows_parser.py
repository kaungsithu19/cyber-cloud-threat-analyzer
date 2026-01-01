from src.parser.windows_parser import WindowsEventParser
import json
import os

def test_windows_parser_reads_and_normalizes_jsonl():
    event = {
        "EventID": 4625,
        "Message": "An account failed to log on.",
        "TargetUserName": "admin",
        "IpAddress": "192.168.1.50"
    }

    test_file = "test_win.jsonl"

    with open(test_file, "w", encoding="utf-8") as f:
        f.write(json.dumps(event) + "\n")

    parser = WindowsEventParser()
    logs = parser.parse(test_file)

    # ---------- Assertions ----------
    assert len(logs) == 1

    log = logs[0]

    # Normalized fields
    assert log["source"] == "windows"
    assert log["event_id"] == 4625
    assert log["message"] == "An account failed to log on."
    assert log["user"] == "admin"
    assert log["ip"] == "192.168.1.50"

    # Raw event preserved
    assert log["raw"]["EventID"] == 4625

    os.remove(test_file)
