from src.parser.cloudtrail_parser import CloudTrailParser
import json

def test_cloudtrail_parser_reads_records():
    data = {
        "Records" : [
            {"eventName": "ConsoleLogin", "userAgent":"test-agent"}
        ]
    }

    with open("test_cloudtrail.json", "w") as f:
        f.write(json.dumps(data))

    parser = CloudTrailParser()
    logs = parser.parse("test_cloudtrail.json")

    assert len(logs) == 1
    assert logs[0]["eventName"] == "ConsoleLogin"
    