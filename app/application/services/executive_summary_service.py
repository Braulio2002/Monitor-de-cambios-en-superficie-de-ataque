from typing import Dict

from app.domain.value_objects.risk_level import RiskLevel


class ExecutiveSummaryService:
    def generate(self, stats: Dict[str, int], overall_risk: float, risk_level: RiskLevel) -> str:
        """
        Genera un resumen ejecutivo formal y profesional en español, diseñado para
        ser interpretado por la gerencia y directores de seguridad de la información (CISO).
        """
        total = stats.get("total", 0)
        critical = stats.get("critical", 0)
        high = stats.get("high", 0)
        medium = stats.get("medium", 0)
        low = stats.get("low", 0)
        info = stats.get("info", 0)

        # Mapear nivel cualitativo de riesgo
        risk_desc = ""
        if risk_level == RiskLevel.CRITICAL:
            risk_desc = "CRÍTICO. Se requiere intervención y remediación inmediata por parte de los equipos de ingeniería de red y seguridad."
        elif risk_level == RiskLevel.HIGH:
            risk_desc = (
                "ALTO. Existen exposiciones que incrementan significativamente la probabilidad "
                "de un compromiso tecnológico si no se mitigan a corto plazo."
            )
        elif risk_level == RiskLevel.MEDIUM:
            risk_desc = "MEDIO. Se aconseja una planificación programada dentro de los ciclos ordinarios de mantenimiento para corregir desviaciones."
        else:
            risk_desc = "BAJO o INFORMATIVO. La superficie de ataque se mantiene estable y alineada con los parámetros de hardening habituales."

        summary_text = (
            f"Durante la presente evaluación comparativa de la superficie de ataque tecnológica, "
            f"se identificaron un total de {total} cambios en los activos autorizados expuestos a Internet.\n\n"
            f"DISTRIBUCIÓN DE CAMBIOS POR SEVERIDAD:\n"
            f" - Críticos: {critical} cambio(s)\n"
            f" - Altos: {high} cambio(s)\n"
            f" - Medios: {medium} cambio(s)\n"
            f" - Bajos: {low} cambio(s)\n"
            f" - Informativos: {info} cambio(s)\n\n"
            f"EVALUACIÓN CUANTITATIVA DEL RIESGO GLOBAL:\n"
            f"La puntuación de riesgo global calculada es de {overall_risk:.1f}/100, determinando un Nivel de Riesgo {risk_level.value}.\n"
            f"Dictamen Gerencial: {risk_desc}\n\n"
            f"RECOMENDACIONES PRIORITARIAS:\n"
        )

        if critical > 0:
            summary_text += (
                "1. REVISIÓN INMEDIATA: Se deben aislar o bloquear inmediatamente los accesos "
                "a bases de datos o APIs expuestas sin autenticación identificadas en este ciclo.\n"
            )
        if high > 0:
            sensitive_examples = ", ".join(["admin", "staging", "backup"])
            summary_text += (
                "2. ATENCIÓN A CORTO PLAZO: Es prioritario configurar cabeceras de transporte "
                f"seguro (HSTS), renovar certificados en riesgo de expiración y auditar subdominios "
                f"marcados como sensibles ({sensitive_examples}).\n"
            )
        if medium > 0:
            summary_text += (
                "3. HARDENING GENERAL: Planificar la desactivación de protocolos TLS 1.0/1.1 "
                "y asegurar que los nuevos servidores web cuenten con directivas estrictas "
                "de seguridad (CSP, X-Frame-Options).\n"
            )

        if critical == 0 and high == 0 and medium == 0:
            summary_text += (
                "La infraestructura auditada presenta una postura de seguridad robusta. "
                "Se aconseja continuar con el monitoreo defensivo continuo y auditorías periódicas."
            )

        return summary_text
