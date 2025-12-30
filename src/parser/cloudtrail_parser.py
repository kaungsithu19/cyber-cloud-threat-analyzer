from typing import List, Dict
from .base_parser import BaseParser
import json
import gzip
import os

class CloudTrailParser(BaseParser):
    def parse(self, file_path:str) -> List[Dict]:
        if file_path.endswith(".gz"):
            open_fn = gzip.open
            mode = "rt"
        else:
            open_fn = open
            mode = "r"

        with open_fn(file_path, mode, encoding = "utf-8") as f:
            data = json.load(f)

        return data.get("Records", [])
    
def parse_from_string_json(self, content: str):
    import json
    data = json.loads(content)
    return data.get("Records", [])
