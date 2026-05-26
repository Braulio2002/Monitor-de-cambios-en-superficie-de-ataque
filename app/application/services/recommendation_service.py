from app.domain.value_objects.asset_type import AssetType
from app.domain.value_objects.change_type import ChangeType
from app.shared.constants import DEFAULT_RECOMMENDATIONS, SENSITIVE_PORTS


class RecommendationService:
    def get_recommendation(self, change_dict: dict) -> str:
        """
        Genera una recomendación de mitigación específica y contextualizada
        para el tipo de cambio y activo detectados.
        """
        asset_type = change_dict.get("asset_type")
        change_type = change_dict.get("change_type")
        details = change_dict.get("details", {})

        # Mejoras o eliminaciones de riesgos
        if change_type == ChangeType.REMOVED:
            if asset_type == AssetType.PORT:
                return "No se requieren acciones correctivas. El puerto ha sido cerrado, lo cual reduce la superficie de exposición."
            if asset_type == AssetType.SUBDOMAIN:
                return (
                    "Verifique que la eliminación del subdominio sea parte de una limpieza autorizada "
                    "y que no existan dependencias internas huérfanas."
                )
            if asset_type == AssetType.ENDPOINT:
                return "Asegúrese de que el endpoint deshabilitado no interrumpa integraciones legítimas."
            return "No se requieren acciones. El activo ha sido removido del alcance expuesto."

        if change_type == ChangeType.IMPROVED:
            return (
                "Buen trabajo. Se ha incrementado la postura de seguridad. "
                "Monitoree periódicamente para confirmar la estabilidad de la configuración."
            )

        # PUERTOS
        if asset_type == AssetType.PORT:
            port = details.get("port")
            if port in SENSITIVE_PORTS:
                return DEFAULT_RECOMMENDATIONS.get("PORT_OPEN_SENSITIVE")
            if port in [80, 443, 8080]:
                return DEFAULT_RECOMMENDATIONS.get("PORT_OPEN_WEB")
            return DEFAULT_RECOMMENDATIONS.get("PORT_OPEN_GENERIC")

        # SUBDOMINIOS
        elif asset_type == AssetType.SUBDOMAIN:
            subdomain = str(details.get("subdomain", "")).lower()
            from app.shared.constants import SENSITIVE_SUBDOMAINS

            is_sensitive = any(kw in subdomain for kw in SENSITIVE_SUBDOMAINS)

            if is_sensitive:
                return DEFAULT_RECOMMENDATIONS.get("SUBDOMAIN_SENSITIVE_NEW")
            if change_type == ChangeType.MODIFIED and details.get("previous_ip") != details.get(
                "current_ip"
            ):
                return DEFAULT_RECOMMENDATIONS.get("SUBDOMAIN_IP_CHANGE")
            return "Añada el nuevo subdominio al inventario oficial y configure políticas de HTTPS obligatorio con cabeceras de seguridad."

        # SERVICIOS
        elif asset_type == AssetType.SERVICE:
            service = str(details.get("current_service", "")).lower()
            from app.shared.constants import SENSITIVE_SERVICES

            if any(s in service for s in SENSITIVE_SERVICES):
                return DEFAULT_RECOMMENDATIONS.get("SERVICE_SENSITIVE_NEW")
            return "Asegúrese de que el servicio expuesto mantenga una política de hardening activa, desactivando banners detallados y depuración."

        # CABECERAS
        elif asset_type == AssetType.HEADER:
            str(details.get("header", ""))
            if change_type == ChangeType.REMOVED:
                return DEFAULT_RECOMMENDATIONS.get("HEADER_REMOVED")
            if change_type == ChangeType.WEAKENED:
                return DEFAULT_RECOMMENDATIONS.get("HEADER_WEAKENED")
            return "Monitoree la cabecera agregada para garantizar que sus valores no afecten la usabilidad legítima de la plataforma."

        # SSL_TLS
        elif asset_type == AssetType.SSL_TLS:
            check_name = details.get("check_name")
            if check_name == "CERTIFICATE_EXPIRED":
                return DEFAULT_RECOMMENDATIONS.get("SSL_TLS_EXPIRED")
            if check_name == "CERTIFICATE_EXPIRING_SOON":
                return DEFAULT_RECOMMENDATIONS.get("SSL_TLS_EXPIRE_SOON")
            if check_name in ["TLS_1_0_ENABLED", "TLS_1_1_ENABLED"]:
                return DEFAULT_RECOMMENDATIONS.get("SSL_TLS_WEAK_PROTOCOL")
            return "Configure el servidor web para deshabilitar suites de cifrado débiles y forzar suites modernos con Perfect Forward Secrecy (PFS)."

        # ENDPOINTS
        elif asset_type == AssetType.ENDPOINT:
            if change_type == ChangeType.WEAKENED:
                return DEFAULT_RECOMMENDATIONS.get("ENDPOINT_AUTH_REMOVED")
            return (
                "Valide que el endpoint expuesto valide rigurosamente los parámetros de entrada "
                "y posea límites de peticiones (Rate Limiting) para evitar ataques de denegación de servicio."
            )

        return DEFAULT_RECOMMENDATIONS.get("DEFAULT")
