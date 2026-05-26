from dataclasses import dataclass
from typing import Optional


@dataclass
class SubdomainAsset:
    domain: str
    subdomain: str
    ip: str
    status: str
    http_status: Optional[int] = None
    technology: Optional[str] = None
