from src.parser.linux_parser import LinuxAuthParser

def test_linux_parser_extract_fields():
    text = """
    Jan 10 12:45:22 ubuntu sshd[1234]: Failed password for admin from 10.0.0.5 port 22 ssh2
    """
    parser = LinuxAuthParser()

    with open("test_auth.log","w") as f:
        f.write(text)

    logs = parser.parse("test_auth.log")

    assert len(logs) == 1
    entry = logs[0]

    assert entry["host"] == "ubuntu"
    assert entry["process"] == "sshd"
    assert "Failed password" in entry["message"]