from typing import List, Dict
from .base_parser import BaseParser
import re

class LinuxAuthParser(BaseParser):
    PATTERN = re.compile(
        r"(?P<timestamp>\w{3}\s+\d+\s[\d:]+)\s"
        r"(?P<host>[\w\-.]+)\s"
        r"(?P<process>[\w\-/]+)(?:\[\d+\])?:\s"
        r"(?P<message>.+)"
    )

    def parse(self, file_path: str) -> List[Dict]:
        logs = []

        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                match = self.PATTERN.search(line)
                if not match:
                    continue

                logs.append({
                    "timestamp": match.group("timestamp"),
                    "host": match.group("host"),
                    "process": match.group("process"),
                    "message": match.group("message"),
                    "raw": line.strip()
                })

        return logs