import json
from pathlib import Path
from typing import Any

from app.shared.logger import logger


class DirectoryManager:
    def __init__(self, base_dir: Path):
        self.base_dir = base_dir
        self.input_dir = base_dir / "datos_entrada"
        self.output_dir = base_dir / "datos_salida"
        self.prev_dir = self.input_dir / "escaneo_anterior"
        self.curr_dir = self.input_dir / "escaneo_actual"

    def setup_directories(self) -> None:
        """
        Crea las carpetas datos_entrada/ y datos_salida/ si no existen.
        Crea las subcarpetas escaneo_anterior/ y escaneo_actual/ y genera datos de ejemplo si están vacías.
        """
        logger.info("Creando carpeta datos_entrada si no existe...")
        self.input_dir.mkdir(parents=True, exist_ok=True)

        logger.info("Creando carpeta datos_salida si no existe...")
        self.output_dir.mkdir(parents=True, exist_ok=True)
        (self.output_dir / ".gitkeep").touch(exist_ok=True)

        self.prev_dir.mkdir(parents=True, exist_ok=True)
        self.curr_dir.mkdir(parents=True, exist_ok=True)
        (self.input_dir / ".gitkeep").touch(exist_ok=True)

        # Generar semillas de prueba realistas si están vacías
        self._generate_seed_data()

    def _generate_seed_data(self) -> None:
        """Genera archivos JSON con datos estructurados y realistas si no existen."""
        # 1. PORTS.JSON
        prev_ports = [
            {
                "target": "api.empresa.com",
                "ip": "192.168.1.10",
                "port": 443,
                "protocol": "tcp",
                "status": "open",
                "service": "https",
                "version": "nginx 1.24",
                "banner": "nginx/1.24.0",
            },
            {
                "target": "web.empresa.com",
                "ip": "192.168.1.11",
                "port": 80,
                "protocol": "tcp",
                "status": "open",
                "service": "http",
                "version": "Apache 2.4",
                "banner": "Apache/2.4.41 (Ubuntu)",
            },
        ]

        # Actual escaneo expone SSH (22) y MySQL (3306) e inactiva el puerto 80 (Apache cerrado)
        curr_ports = [
            {
                "target": "api.empresa.com",
                "ip": "192.168.1.10",
                "port": 443,
                "protocol": "tcp",
                "status": "open",
                "service": "https",
                "version": "nginx 1.24",
                "banner": "nginx/1.24.0",
            },
            {
                "target": "api.empresa.com",
                "ip": "192.168.1.10",
                "port": 22,
                "protocol": "tcp",
                "status": "open",
                "service": "ssh",
                "version": "OpenSSH 8.9p1",
                "banner": "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.3",
            },
            {
                "target": "db.empresa.com",
                "ip": "192.168.1.20",
                "port": 3306,
                "protocol": "tcp",
                "status": "open",
                "service": "mysql",
                "version": "8.0.32",
                "banner": "8.0.32-0ubuntu0.22.04.1",
            },
        ]

        # 2. SUBDOMAINS.JSON
        prev_subs = [
            {
                "domain": "empresa.com",
                "subdomain": "api.empresa.com",
                "ip": "192.168.1.10",
                "status": "active",
                "http_status": 200,
                "technology": "nginx",
            },
            {
                "domain": "empresa.com",
                "subdomain": "web.empresa.com",
                "ip": "192.168.1.11",
                "status": "active",
                "http_status": 200,
                "technology": "apache",
            },
        ]

        # Agrega subdominio sensible 'db.empresa.com' e 'intranet.empresa.com' y remueve 'web.empresa.com'
        curr_subs = [
            {
                "domain": "empresa.com",
                "subdomain": "api.empresa.com",
                "ip": "192.168.1.10",
                "status": "active",
                "http_status": 200,
                "technology": "nginx",
            },
            {
                "domain": "empresa.com",
                "subdomain": "db.empresa.com",
                "ip": "192.168.1.20",
                "status": "active",
                "http_status": 403,
                "technology": "mysql",
            },
            {
                "domain": "empresa.com",
                "subdomain": "intranet.empresa.com",
                "ip": "192.168.1.30",
                "status": "active",
                "http_status": 200,
                "technology": "iis",
            },
        ]

        # 3. SERVICES.JSON
        prev_svcs = [
            {
                "host": "api.empresa.com",
                "ip": "192.168.1.10",
                "port": 443,
                "service": "https",
                "version": "nginx 1.24",
                "category": "web",
            }
        ]

        curr_svcs = [
            {
                "host": "api.empresa.com",
                "ip": "192.168.1.10",
                "port": 443,
                "service": "https",
                "version": "nginx 1.24",
                "category": "web",
            },
            {
                "host": "api.empresa.com",
                "ip": "192.168.1.10",
                "port": 22,
                "service": "ssh",
                "version": "OpenSSH 8.9p1",
                "category": "remote-access",
            },
            {
                "host": "db.empresa.com",
                "ip": "192.168.1.20",
                "port": 3306,
                "service": "mysql",
                "version": "mysql 8.0",
                "category": "database",
            },
        ]

        # 4. HEADERS.JSON
        prev_hdrs = [
            {
                "url": "https://api.empresa.com",
                "headers": {
                    "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
                    "X-Content-Type-Options": "nosniff",
                    "X-Frame-Options": "SAMEORIGIN",
                    "Content-Security-Policy": "default-src 'self'",
                },
            }
        ]

        # Debilita CSP (añade unsafe-inline), remueve HSTS (Strict-Transport-Security) y añade Referrer-Policy
        curr_hdrs = [
            {
                "url": "https://api.empresa.com",
                "headers": {
                    "X-Content-Type-Options": "nosniff",
                    "X-Frame-Options": "SAMEORIGIN",
                    "Content-Security-Policy": "default-src 'self' 'unsafe-inline'",
                    "Referrer-Policy": "strict-origin-when-cross-origin",
                },
            }
        ]

        # 5. SSL_TLS.JSON
        prev_ssl = [
            {
                "domain": "api.empresa.com",
                "https_available": True,
                "certificate_valid": True,
                "days_to_expire": 80,
                "issuer": "Let's Encrypt",
                "tls_1_0": False,
                "tls_1_1": False,
                "tls_1_2": True,
                "tls_1_3": True,
            }
        ]

        # Certificado próximo a vencer (20 días restante) y TLS 1.0 habilitado
        curr_ssl = [
            {
                "domain": "api.empresa.com",
                "https_available": True,
                "certificate_valid": True,
                "days_to_expire": 20,
                "issuer": "Let's Encrypt",
                "tls_1_0": True,
                "tls_1_1": False,
                "tls_1_2": True,
                "tls_1_3": True,
            }
        ]

        # 6. ENDPOINTS.JSON (OPCIONAL)
        prev_eps = [
            {
                "name": "List users",
                "url": "https://api.empresa.com/users",
                "method": "GET",
                "requires_auth": True,
                "status_code": 200,
            }
        ]

        # endpoint /users pierde autenticación (requires_auth -> False) y responde 200
        curr_eps = [
            {
                "name": "List users",
                "url": "https://api.empresa.com/users",
                "method": "GET",
                "requires_auth": False,
                "status_code": 200,
            },
            {
                "name": "Create User",
                "url": "https://api.empresa.com/users",
                "method": "POST",
                "requires_auth": True,
                "status_code": 201,
            },
        ]

        # Escritura segura si no existen
        self._write_if_not_exists(self.prev_dir / "ports.json", prev_ports)
        self._write_if_not_exists(self.curr_dir / "ports.json", curr_ports)

        self._write_if_not_exists(self.prev_dir / "subdomains.json", prev_subs)
        self._write_if_not_exists(self.curr_dir / "subdomains.json", curr_subs)

        self._write_if_not_exists(self.prev_dir / "services.json", prev_svcs)
        self._write_if_not_exists(self.curr_dir / "services.json", curr_svcs)

        self._write_if_not_exists(self.prev_dir / "headers.json", prev_hdrs)
        self._write_if_not_exists(self.curr_dir / "headers.json", curr_hdrs)

        self._write_if_not_exists(self.prev_dir / "ssl_tls.json", prev_ssl)
        self._write_if_not_exists(self.curr_dir / "ssl_tls.json", curr_ssl)

        self._write_if_not_exists(self.prev_dir / "endpoints.json", prev_eps)
        self._write_if_not_exists(self.curr_dir / "endpoints.json", curr_eps)

    def _write_if_not_exists(self, filepath: Path, data: Any) -> None:
        if not filepath.exists():
            with open(filepath, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2, ensure_ascii=False)
            logger.info(f"Semilla de ejemplo creada: {filepath.name}")
