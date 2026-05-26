from typing import List

from app.config.settings import RISK_WEIGHTS
from app.domain.value_objects.asset_type import AssetType
from app.domain.value_objects.change_type import ChangeType
from app.domain.value_objects.risk_level import RiskLevel


class RiskScoreCalculatorService:
    def calculate_score(self, change_dict: dict) -> float:
        """
        Calcula un score cuantitativo de riesgo entre 0 y 100 para un cambio específico,
        basándose en pesos parametrizados.
        """
        asset_type = change_dict.get("asset_type")
        change_type = change_dict.get("change_type")
        details = change_dict.get("details", {})

        # Cierre de activos o mejoras representan riesgo 0 o insignificante
        if change_type in [ChangeType.REMOVED, ChangeType.IMPROVED]:
            # El requerimiento dice: "Puerto cerrado: 0"
            return 0.0

        # 1. PUERTOS
        if asset_type == AssetType.PORT:
            port = details.get("port")
            service = str(details.get("current_service", "")).lower()

            db_ports = [3306, 5432, 6379, 9200, 27017]
            db_services = ["mysql", "postgresql", "redis", "mongodb", "elasticsearch"]

            if port in db_ports or any(db in service for db in db_services):
                # "Nueva base de datos expuesta: 95"
                return float(RISK_WEIGHTS.get("PORT_OPEN_CRITICAL_DB", 95))

            if port == 2375 or service == "docker api":
                # "Docker API expuesto: 100"
                return float(RISK_WEIGHTS.get("PORT_OPEN_DOCKER_API", 100))

            if port == 3389 or service == "rdp":
                # "RDP expuesto: 85"
                return float(RISK_WEIGHTS.get("PORT_OPEN_RDP", 85))

            if port == 22 or service == "ssh":
                # "SSH expuesto: 70"
                return float(RISK_WEIGHTS.get("PORT_OPEN_SSH", 70))

            if port in [80, 443, 8080]:
                # "Nuevo puerto web: 40"
                return float(RISK_WEIGHTS.get("PORT_OPEN_WEB", 40))

            return float(RISK_WEIGHTS.get("PORT_OPEN_GENERIC", 30))

        # 2. SUBDOMINIOS
        elif asset_type == AssetType.SUBDOMAIN:
            subdomain = str(details.get("subdomain", "")).lower()

            if change_type == ChangeType.ADDED:
                from app.shared.constants import SENSITIVE_SUBDOMAINS

                is_sensitive = any(kw in subdomain for kw in SENSITIVE_SUBDOMAINS)
                if is_sensitive:
                    # "Nuevo subdominio sensible: 65"
                    return float(RISK_WEIGHTS.get("SUBDOMAIN_NEW_SENSITIVE", 65))
                return float(RISK_WEIGHTS.get("SUBDOMAIN_NEW_GENERIC", 35))

            if change_type == ChangeType.MODIFIED:
                # Si cambió la IP
                if details.get("previous_ip") != details.get("current_ip"):
                    return float(RISK_WEIGHTS.get("SUBDOMAIN_IP_CHANGED", 50))
                return 25.0

        # 3. SERVICIOS
        elif asset_type == AssetType.SERVICE:
            service_name = str(details.get("current_service", "")).lower()
            from app.shared.constants import SENSITIVE_SERVICES

            is_sensitive = any(s in service_name for s in SENSITIVE_SERVICES)

            if change_type == ChangeType.ADDED:
                if is_sensitive:
                    return float(RISK_WEIGHTS.get("SERVICE_NEW_SENSITIVE", 80))
                return 30.0

            if change_type == ChangeType.MODIFIED:
                if is_sensitive:
                    return float(RISK_WEIGHTS.get("SERVICE_VERSION_CHANGED_SENSITIVE", 55))
                return float(RISK_WEIGHTS.get("SERVICE_VERSION_CHANGED_GENERIC", 20))

        # 4. CABECERAS
        elif asset_type == AssetType.HEADER:
            header = str(details.get("header", "")).lower()

            if change_type == ChangeType.ADDED:
                # "Header agregado: 5"
                return float(RISK_WEIGHTS.get("HEADER_ADDED", 5))

            if change_type == ChangeType.REMOVED:
                if header == "strict-transport-security":
                    # "HSTS eliminado: 70"
                    return float(RISK_WEIGHTS.get("HEADER_REMOVED", 70))
                return 50.0

            if change_type == ChangeType.WEAKENED:
                if header == "content-security-policy":
                    # "CSP debilitada: 60"
                    return float(RISK_WEIGHTS.get("HEADER_WEAKENED", 60))
                return 40.0

        # 5. SSL_TLS
        elif asset_type == AssetType.SSL_TLS:
            check_name = details.get("check_name")

            if check_name == "CERTIFICATE_EXPIRED":
                return float(RISK_WEIGHTS.get("SSL_TLS_EXPIRED", 95))
            if check_name == "CERTIFICATE_EXPIRING_SOON":
                return float(RISK_WEIGHTS.get("SSL_TLS_EXPIRE_SOON", 60))
            if check_name == "TLS_1_0_ENABLED":
                return float(RISK_WEIGHTS.get("SSL_TLS_WEAK_PROTOCOL", 75))
            if check_name == "TLS_1_1_ENABLED":
                return 45.0
            if check_name == "TLS_1_3_DISABLED":
                return 35.0

        # 6. ENDPOINTS
        elif asset_type == AssetType.ENDPOINT:
            if change_type == ChangeType.WEAKENED:
                # "Endpoint privado que ahora responde sin auth: 95"
                return float(RISK_WEIGHTS.get("ENDPOINT_NEW_UNAUTH", 95))
            if change_type == ChangeType.ADDED:
                if not details.get("current_auth"):
                    return 75.0
                return float(RISK_WEIGHTS.get("ENDPOINT_NEW", 20))

        return float(RISK_WEIGHTS.get("DEFAULT", 10))

    def map_score_to_level(self, score: float) -> RiskLevel:
        """
        Mapea el score cuantitativo a niveles cualitativos de riesgo.
        - 0 a 20: Bajo
        - 21 a 50: Medio
        - 51 a 75: Alto
        - 76 a 100: Crítico
        """
        if score <= 20.0:
            return RiskLevel.LOW
        elif score <= 50.0:
            return RiskLevel.MEDIUM
        elif score <= 75.0:
            return RiskLevel.HIGH
        else:
            return RiskLevel.CRITICAL

    def calculate_overall_risk(self, scores: List[float]) -> float:
        """
        Calcula el score de riesgo general del reporte consolidado.
        Utiliza una aproximación conservadora (el máximo score si hay riesgos altos/críticos,
        o el promedio ponderado). Retorna un valor entre 0 y 100.
        """
        if not scores:
            return 0.0

        # Si existe al menos un riesgo crítico (>= 76), la superficie global tiene alta criticidad
        max_score = max(scores)
        if max_score >= 76.0:
            # Retorna el máximo score como el indicador general de riesgo
            return max_score

        # De lo contrario, retorna un promedio ponderado enfocado en los puntajes más altos
        return sum(scores) / len(scores)
