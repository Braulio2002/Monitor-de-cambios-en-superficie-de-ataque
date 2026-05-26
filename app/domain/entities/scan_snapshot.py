from dataclasses import dataclass, field
from typing import List

from app.domain.entities.exposed_endpoint import ExposedEndpoint
from app.domain.entities.exposed_port import ExposedPort
from app.domain.entities.exposed_service import ExposedService
from app.domain.entities.header_snapshot import HeaderSnapshot
from app.domain.entities.ssl_tls_snapshot import SslTlsSnapshot
from app.domain.entities.subdomain_asset import SubdomainAsset


@dataclass
class ScanSnapshot:
    nombre_snapshot: str
    fecha_carga: str
    puertos: List[ExposedPort] = field(default_factory=list)
    subdominios: List[SubdomainAsset] = field(default_factory=list)
    servicios: List[ExposedService] = field(default_factory=list)
    headers: List[HeaderSnapshot] = field(default_factory=list)
    ssl_tls: List[SslTlsSnapshot] = field(default_factory=list)
    endpoints: List[ExposedEndpoint] = field(default_factory=list)
