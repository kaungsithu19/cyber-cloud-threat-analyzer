from typing import Dict, List

class LogParser:

    def parse(self, raw_data:str) -> List[Dict]:
        return [{"raw": line} for line in raw_data.splitlines() if line.strip()]
    