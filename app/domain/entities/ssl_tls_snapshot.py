from dataclasses import dataclass
from typing import Optional


@dataclass
class SslTlsSnapshot:
    domain: str
    https_available: bool
    certificate_valid: bool
    days_to_expire: int
    issuer: Optional[str] = None
    tls_1_0: bool = False
    tls_1_1: bool = False
    tls_1_2: bool = True
    tls_1_3: bool = True
