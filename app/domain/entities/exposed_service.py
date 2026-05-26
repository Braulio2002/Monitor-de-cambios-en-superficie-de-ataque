from dataclasses import dataclass
from typing import Optional


@dataclass
class ExposedService:
    host: str
    ip: str
    port: int
    service: str
    version: Optional[str] = None
    category: Optional[str] = None
