from src.parser.windows_parser import WindowsEventParser
import json

def test_windows_parser_reads_jsonl():
    event = {
        "EventID" : 4625,
        "Message": "An account failed to log on."

    }

    with open("test_win.jsonl", "w") as f:
        f.write(json.dumps(event) + "\n")
    
    parser = WindowsEventParser()
    logs = parser.parse("test_win.jsonl")

    assert len(logs) == 1
    assert logs[0]["EventID"] == 4625