from typing import List, Dict
from abc import ABC, abstractmethod

class BaseParser(ABC):

    @abstractmethod
    def parse(self, file_path:str) -> List[Dict]:
        pass