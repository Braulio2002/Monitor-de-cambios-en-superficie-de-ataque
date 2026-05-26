from dataclasses import dataclass
from typing import Dict


@dataclass
class HeaderSnapshot:
    url: str
    headers: Dict[str, str]
