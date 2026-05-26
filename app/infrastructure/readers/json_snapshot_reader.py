import json
from pathlib import Path
from typing import Any, Dict, List

from app.application.interfaces.snapshot_reader_interface import SnapshotReaderInterface
from app.domain.entities.exposed_endpoint import ExposedEndpoint
from app.domain.entities.exposed_port import ExposedPort
from app.domain.entities.exposed_service import ExposedService
from app.domain.entities.header_snapshot import HeaderSnapshot
from app.domain.entities.scan_snapshot import ScanSnapshot
from app.domain.entities.ssl_tls_snapshot import SslTlsSnapshot
from app.domain.entities.subdomain_asset import SubdomainAsset
from app.shared.date_utils import get_date_for_reports
from app.shared.logger import logger


class JsonSnapshotReader(SnapshotReaderInterface):
    def __init__(self):
        self.errors: List[Dict[str, str]] = []

    def read_snapshot(self, snapshot_dir: Path, name: str) -> ScanSnapshot:
        """
        Lee los archivos JSON del directorio indicado.
        Si algún archivo falta o está corrupto, registra el error y continúa.
        """
        self.errors.clear()

        puertos = self._read_file(snapshot_dir / "ports.json", "ports", self._parse_port)
        subdomains = self._read_file(
            snapshot_dir / "subdomains.json", "subdomains", self._parse_subdomain
        )
        services = self._read_file(snapshot_dir / "services.json", "services", self._parse_service)
        headers = self._read_file(snapshot_dir / "headers.json", "headers", self._parse_header)
        ssl_tls = self._read_file(snapshot_dir / "ssl_tls.json", "ssl_tls", self._parse_ssl_tls)
        endpoints = self._read_file(
            snapshot_dir / "endpoints.json", "endpoints", self._parse_endpoint, optional=True
        )

        return ScanSnapshot(
            nombre_snapshot=name,
            fecha_carga=get_date_for_reports(),
            puertos=puertos,
            subdominios=subdomains,
            servicios=services,
            headers=headers,
            ssl_tls=ssl_tls,
            endpoints=endpoints,
        )

    def _read_file(
        self, path: Path, file_key: str, parser_func, optional: bool = False
    ) -> List[Any]:
        """Lectura tolerante a fallos de archivos individuales."""
        if not path.exists():
            if not optional:
                msg = f"El archivo requerido no existe: {path.name}"
                logger.warning(msg)
                self.errors.append(
                    {
                        "archivo": path.name,
                        "tipo_error": "Archivo Faltante",
                        "mensaje_error": msg,
                        "fecha": get_date_for_reports(),
                    }
                )
            return []

        try:
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)

            if not isinstance(data, list):
                raise ValueError("El formato raíz del JSON debe ser una lista.")

            parsed_items = []
            for idx, item in enumerate(data):
                try:
                    parsed_items.append(parser_func(item))
                except Exception as pe:
                    msg = f"Fallo al parsear objeto en índice {idx}: {str(pe)}"
                    logger.error(f"[{path.name}] {msg}")
                    self.errors.append(
                        {
                            "archivo": path.name,
                            "tipo_error": "Objeto Inválido",
                            "mensaje_error": msg,
                            "fecha": get_date_for_reports(),
                        }
                    )
            return parsed_items

        except json.JSONDecodeError as jde:
            msg = f"JSON corrupto o mal formado: {str(jde)}"
            logger.error(f"[{path.name}] {msg}")
            self.errors.append(
                {
                    "archivo": path.name,
                    "tipo_error": "JSON Corrupto",
                    "mensaje_error": msg,
                    "fecha": get_date_for_reports(),
                }
            )
        except Exception as e:
            msg = f"Error inesperado al leer archivo: {str(e)}"
            logger.error(f"[{path.name}] {msg}")
            self.errors.append(
                {
                    "archivo": path.name,
                    "tipo_error": "Error de Lectura",
                    "mensaje_error": msg,
                    "fecha": get_date_for_reports(),
                }
            )

        return []

    # --- Parsers Auxiliares ---
    def _parse_port(self, d: dict) -> ExposedPort:
        return ExposedPort(
            target=d["target"],
            ip=d["ip"],
            port=int(d["port"]),
            protocol=d.get("protocol", "tcp"),
            status=d.get("status", "open"),
            service=d.get("service", "unknown"),
            version=d.get("version"),
            banner=d.get("banner"),
        )

    def _parse_subdomain(self, d: dict) -> SubdomainAsset:
        return SubdomainAsset(
            domain=d["domain"],
            subdomain=d["subdomain"],
            ip=d["ip"],
            status=d.get("status", "active"),
            http_status=int(d["http_status"]) if d.get("http_status") is not None else None,
            technology=d.get("technology"),
        )

    def _parse_service(self, d: dict) -> ExposedService:
        return ExposedService(
            host=d["host"],
            ip=d["ip"],
            port=int(d["port"]),
            service=d["service"],
            version=d.get("version"),
            category=d.get("category"),
        )

    def _parse_header(self, d: dict) -> HeaderSnapshot:
        return HeaderSnapshot(url=d["url"], headers=d.get("headers", {}))

    def _parse_ssl_tls(self, d: dict) -> SslTlsSnapshot:
        return SslTlsSnapshot(
            domain=d["domain"],
            https_available=bool(d.get("https_available", True)),
            certificate_valid=bool(d.get("certificate_valid", True)),
            days_to_expire=int(d.get("days_to_expire", 0)),
            issuer=d.get("issuer"),
            tls_1_0=bool(d.get("tls_1_0", False)),
            tls_1_1=bool(d.get("tls_1_1", False)),
            tls_1_2=bool(d.get("tls_1_2", True)),
            tls_1_3=bool(d.get("tls_1_3", True)),
        )

    def _parse_endpoint(self, d: dict) -> ExposedEndpoint:
        return ExposedEndpoint(
            name=d["name"],
            url=d["url"],
            method=d.get("method", "GET"),
            requires_auth=bool(d.get("requires_auth", True)),
            status_code=int(d.get("status_code", 200)),
        )
