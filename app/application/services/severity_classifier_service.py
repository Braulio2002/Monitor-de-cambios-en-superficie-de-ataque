from app.domain.value_objects.asset_type import AssetType
from app.domain.value_objects.change_type import ChangeType
from app.domain.value_objects.severity_level import SeverityLevel
from app.shared.constants import SENSITIVE_PORTS, SENSITIVE_SERVICES, SENSITIVE_SUBDOMAINS


class SeverityClassifierService:
    def classify(self, change_dict: dict) -> SeverityLevel:
        """
        Clasifica un cambio detectado en base al tipo de activo, el cambio
        y el contexto (palabras clave sensibles, números de puerto, etc.)
        """
        asset_type = change_dict.get("asset_type")
        change_type = change_dict.get("change_type")
        details = change_dict.get("details", {})

        # Mejoras directas son INFO
        if change_type == ChangeType.IMPROVED:
            return SeverityLevel.INFO

        # PUERTOS (PORT)
        if asset_type == AssetType.PORT:
            if change_type == ChangeType.REMOVED:
                return SeverityLevel.INFO  # Puerto cerrado es positivo / informativo

            if change_type == ChangeType.ADDED:
                port = details.get("port")
                service = str(details.get("current_service", "")).lower()

                # Bases de datos y APIs críticas expuestas -> CRITICAL
                db_ports = [3306, 5432, 6379, 9200, 27017]
                db_services = ["mysql", "postgresql", "redis", "mongodb", "elasticsearch"]
                if port in db_ports or any(db_svc in service for db_svc in db_services):
                    return SeverityLevel.CRITICAL

                if port == 2375 or service == "docker api":
                    return SeverityLevel.CRITICAL

                # Consolas de administración, SSH o RDP expuestos -> HIGH
                admin_ports = [22, 3389, 21, 23, 445]
                admin_services = ["ssh", "rdp", "ftp", "telnet", "smb"]
                if port in admin_ports or any(adm in service for adm in admin_services):
                    return SeverityLevel.HIGH

                # Puertos web estándar -> MEDIUM
                if port in [80, 443, 8080]:
                    return SeverityLevel.MEDIUM

                return SeverityLevel.MEDIUM

            if change_type == ChangeType.MODIFIED:
                # Si cambió la versión de un puerto crítico -> MEDIUM
                port = details.get("port")
                if port in SENSITIVE_PORTS:
                    return SeverityLevel.MEDIUM
                return SeverityLevel.LOW

        # SUBDOMINIOS (SUBDOMAIN)
        elif asset_type == AssetType.SUBDOMAIN:
            if change_type == ChangeType.REMOVED:
                return SeverityLevel.INFO

            subdomain = str(details.get("subdomain", "")).lower()

            if change_type == ChangeType.ADDED:
                # Comprobar palabras clave sensibles
                is_sensitive = any(keyword in subdomain for keyword in SENSITIVE_SUBDOMAINS)
                if is_sensitive:
                    return SeverityLevel.HIGH
                return SeverityLevel.MEDIUM

            if change_type == ChangeType.MODIFIED:
                # Cambio de IP de subdominio es riesgo de hijack o takeover -> HIGH
                if details.get("previous_ip") != details.get("current_ip"):
                    return SeverityLevel.HIGH
                return SeverityLevel.MEDIUM

        # SERVICIOS (SERVICE)
        elif asset_type == AssetType.SERVICE:
            if change_type == ChangeType.REMOVED:
                return SeverityLevel.INFO

            service_name = str(details.get("current_service", "")).lower()

            if change_type == ChangeType.ADDED:
                is_sensitive = any(s in service_name for s in SENSITIVE_SERVICES)
                if is_sensitive:
                    return SeverityLevel.HIGH
                return SeverityLevel.MEDIUM

            if change_type == ChangeType.MODIFIED:
                # Cambio de versión de servicio sensible -> MEDIUM
                is_sensitive = any(s in service_name for s in SENSITIVE_SERVICES)
                if is_sensitive:
                    return SeverityLevel.MEDIUM
                return SeverityLevel.LOW

        # CABECERAS (HEADER)
        elif asset_type == AssetType.HEADER:
            header = str(details.get("header", ""))

            if change_type == ChangeType.ADDED:
                return SeverityLevel.INFO  # Cabecera agregada es una mejora / info

            if change_type == ChangeType.REMOVED:
                # HSTS o CSP eliminada es HIGH, las demás MEDIUM
                if header.lower() in ["strict-transport-security", "content-security-policy"]:
                    return SeverityLevel.HIGH
                return SeverityLevel.MEDIUM

            if change_type == ChangeType.WEAKENED:
                if header.lower() in ["strict-transport-security", "content-security-policy"]:
                    return SeverityLevel.HIGH
                return SeverityLevel.MEDIUM

            if change_type == ChangeType.MODIFIED:
                return SeverityLevel.LOW

        # SSL_TLS
        elif asset_type == AssetType.SSL_TLS:
            check_name = details.get("check_name")

            if change_type == ChangeType.ADDED:
                return SeverityLevel.INFO

            if check_name == "CERTIFICATE_EXPIRED":
                return SeverityLevel.CRITICAL

            if check_name == "CERTIFICATE_EXPIRING_SOON":
                return SeverityLevel.HIGH

            if check_name == "TLS_1_0_ENABLED":
                return SeverityLevel.CRITICAL

            if check_name == "TLS_1_1_ENABLED":
                return SeverityLevel.MEDIUM

            if check_name == "TLS_1_3_DISABLED":
                return SeverityLevel.MEDIUM

            return SeverityLevel.LOW

        # ENDPOINTS
        elif asset_type == AssetType.ENDPOINT:
            if change_type == ChangeType.REMOVED:
                return SeverityLevel.LOW

            if change_type == ChangeType.ADDED:
                # Nuevo endpoint público -> HIGH, privado -> MEDIUM
                if not details.get("current_auth"):
                    return SeverityLevel.HIGH
                return SeverityLevel.MEDIUM

            if change_type == ChangeType.WEAKENED:
                # Endpoint privado ahora responde sin auth -> CRITICAL
                return SeverityLevel.CRITICAL

            return SeverityLevel.LOW

        return SeverityLevel.INFO
