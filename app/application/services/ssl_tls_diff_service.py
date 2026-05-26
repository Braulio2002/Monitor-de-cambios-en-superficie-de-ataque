from typing import Any, Dict, List

from app.domain.entities.ssl_tls_snapshot import SslTlsSnapshot
from app.domain.value_objects.asset_type import AssetType
from app.domain.value_objects.change_type import ChangeType


class SslTlsDiffService:
    def compare(
        self, previous: List[SslTlsSnapshot], current: List[SslTlsSnapshot]
    ) -> List[Dict[str, Any]]:
        """
        Compara configuraciones SSL/TLS y certificados de escaneo anterior vs actual.
        Detecta expiración de certificados, protocolos TLS obsoletos o debilitamiento de directivas.
        """
        changes = []

        prev_map = {s.domain: s for s in previous}
        curr_map = {s.domain: s for s in current}

        all_domains = set(prev_map.keys()).union(set(curr_map.keys()))

        for dom in all_domains:
            prev_ssl = prev_map.get(dom)
            curr_ssl = curr_map.get(dom)

            # Caso 1: Nuevo dominio con HTTPS auditado
            if curr_ssl and not prev_ssl:
                desc = f"Nueva configuración SSL/TLS auditada para {dom} (Emisor: {curr_ssl.issuer or 'desconocido'})"
                changes.append(
                    {
                        "asset_type": AssetType.SSL_TLS,
                        "change_type": ChangeType.ADDED,
                        "asset_identifier": dom,
                        "previous_value": "No auditado",
                        "current_value": f"Certificado válido ({curr_ssl.days_to_expire} días restantes)",
                        "description": desc,
                        "details": {
                            "domain": dom,
                            "check_name": "HTTPS_AUDITED",
                            "previous_value": None,
                            "current_value": f"Emisor: {curr_ssl.issuer}, Días: {curr_ssl.days_to_expire}",
                        },
                    }
                )

            # Caso 2: Dominio retirado de auditoría SSL/TLS
            elif prev_ssl and not curr_ssl:
                changes.append(
                    {
                        "asset_type": AssetType.SSL_TLS,
                        "change_type": ChangeType.REMOVED,
                        "asset_identifier": dom,
                        "previous_value": "Auditado",
                        "current_value": "No registrado en escaneo actual",
                        "description": f"Auditoría SSL/TLS deshabilitada o dominio removido: {dom}",
                        "details": {
                            "domain": dom,
                            "check_name": "HTTPS_REMOVED",
                            "previous_value": prev_ssl.issuer,
                            "current_value": None,
                        },
                    }
                )

            # Caso 3: Cambios de estado en dominio existente
            elif prev_ssl and curr_ssl:
                # 3a. Expiración de certificado o días a expirar
                if not curr_ssl.certificate_valid or curr_ssl.days_to_expire <= 0:
                    changes.append(
                        {
                            "asset_type": AssetType.SSL_TLS,
                            "change_type": ChangeType.WEAKENED,
                            "asset_identifier": dom,
                            "previous_value": "Válido"
                            if prev_ssl.certificate_valid
                            else "Inválido",
                            "current_value": "EXPIRADO o INVÁLIDO",
                            "description": f"CRÍTICO: El certificado SSL/TLS para {dom} ha expirado o no es válido",
                            "details": {
                                "domain": dom,
                                "check_name": "CERTIFICATE_EXPIRED",
                                "previous_value": f"Días: {prev_ssl.days_to_expire}",
                                "current_value": "Expirado / Inválido",
                            },
                        }
                    )
                elif curr_ssl.days_to_expire <= 30 and prev_ssl.days_to_expire > 30:
                    changes.append(
                        {
                            "asset_type": AssetType.SSL_TLS,
                            "change_type": ChangeType.WEAKENED,
                            "asset_identifier": dom,
                            "previous_value": f"{prev_ssl.days_to_expire} días restantes",
                            "current_value": f"{curr_ssl.days_to_expire} días restantes",
                            "description": f"Advertencia: El certificado SSL/TLS para {dom} expirará próximamente ({curr_ssl.days_to_expire} días)",
                            "details": {
                                "domain": dom,
                                "check_name": "CERTIFICATE_EXPIRING_SOON",
                                "previous_value": f"Días: {prev_ssl.days_to_expire}",
                                "current_value": f"Días: {curr_ssl.days_to_expire}",
                            },
                        }
                    )

                # 3b. Cambio de Emisor (Issuer)
                if prev_ssl.issuer != curr_ssl.issuer:
                    changes.append(
                        {
                            "asset_type": AssetType.SSL_TLS,
                            "change_type": ChangeType.MODIFIED,
                            "asset_identifier": dom,
                            "previous_value": prev_ssl.issuer or "Ninguno",
                            "current_value": curr_ssl.issuer or "Ninguno",
                            "description": f"El emisor del certificado SSL/TLS para {dom} ha cambiado de '{prev_ssl.issuer}' a '{curr_ssl.issuer}'",
                            "details": {
                                "domain": dom,
                                "check_name": "CERTIFICATE_ISSUER_CHANGED",
                                "previous_value": prev_ssl.issuer,
                                "current_value": curr_ssl.issuer,
                            },
                        }
                    )

                # 3c. Protocolos TLS Obsoletos habilitados
                # TLS 1.0 habilitado
                if curr_ssl.tls_1_0 and not prev_ssl.tls_1_0:
                    changes.append(
                        {
                            "asset_type": AssetType.SSL_TLS,
                            "change_type": ChangeType.WEAKENED,
                            "asset_identifier": dom,
                            "previous_value": "TLS 1.0 Deshabilitado",
                            "current_value": "TLS 1.0 HABILITADO",
                            "description": f"Seguridad debilitada en {dom}: se habilitó soporte para el protocolo obsoleto e inseguro TLS 1.0",
                            "details": {
                                "domain": dom,
                                "check_name": "TLS_1_0_ENABLED",
                                "previous_value": "False",
                                "current_value": "True",
                            },
                        }
                    )
                # TLS 1.1 habilitado
                if curr_ssl.tls_1_1 and not prev_ssl.tls_1_1:
                    changes.append(
                        {
                            "asset_type": AssetType.SSL_TLS,
                            "change_type": ChangeType.WEAKENED,
                            "asset_identifier": dom,
                            "previous_value": "TLS 1.1 Deshabilitado",
                            "current_value": "TLS 1.1 HABILITADO",
                            "description": f"Seguridad debilitada en {dom}: se habilitó soporte para el protocolo obsoleto TLS 1.1",
                            "details": {
                                "domain": dom,
                                "check_name": "TLS_1_1_ENABLED",
                                "previous_value": "False",
                                "current_value": "True",
                            },
                        }
                    )
                # TLS 1.2 deshabilitado
                if not curr_ssl.tls_1_2 and prev_ssl.tls_1_2:
                    changes.append(
                        {
                            "asset_type": AssetType.SSL_TLS,
                            "change_type": ChangeType.WEAKENED,
                            "asset_identifier": dom,
                            "previous_value": "TLS 1.2 Habilitado",
                            "current_value": "TLS 1.2 DESHABILITADO",
                            "description": f"Advertencia: Se deshabilitó soporte para TLS 1.2 en {dom}",
                            "details": {
                                "domain": dom,
                                "check_name": "TLS_1_2_DISABLED",
                                "previous_value": "True",
                                "current_value": "False",
                            },
                        }
                    )
                # TLS 1.3 deshabilitado
                if not curr_ssl.tls_1_3 and prev_ssl.tls_1_3:
                    changes.append(
                        {
                            "asset_type": AssetType.SSL_TLS,
                            "change_type": ChangeType.WEAKENED,
                            "asset_identifier": dom,
                            "previous_value": "TLS 1.3 Habilitado (Recomendado)",
                            "current_value": "TLS 1.3 DESHABILITADO",
                            "description": f"Se ha removido el soporte para el protocolo moderno y seguro TLS 1.3 en {dom}",
                            "details": {
                                "domain": dom,
                                "check_name": "TLS_1_3_DISABLED",
                                "previous_value": "True",
                                "current_value": "False",
                            },
                        }
                    )

        return changes
