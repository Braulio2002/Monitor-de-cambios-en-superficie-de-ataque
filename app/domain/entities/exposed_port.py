from dataclasses import dataclass
from typing import Optional


@dataclass
class ExposedPort:
    target: str
    ip: str
    port: int
    protocol: str
    status: str
    service: str
    version: Optional[str] = None
    banner: Optional[str] = None
