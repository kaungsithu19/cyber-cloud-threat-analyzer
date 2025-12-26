from typing import List, Dict
from .base_parser import BaseParser
import json

class WindowsEventParser(BaseParser):
    def parse(self, file_path: str) -> List[Dict]:
        logs=[]

        with open(file_path, "r", encoding="utf-8") as f:
            for line in f:
                try:
                    event = json.loads(line) #loads converts JSON to Python DICT
                    logs.append(event)
                except json.JSONDecodeError:
                    continue
        return logs