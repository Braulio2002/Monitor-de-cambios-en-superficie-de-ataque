from pathlib import Path
from typing import Dict, List, Tuple

from app.application.interfaces.report_exporter_interface import ReportExporterInterface
from app.application.interfaces.snapshot_reader_interface import SnapshotReaderInterface
from app.application.services.endpoint_diff_service import EndpointDiffService
from app.application.services.executive_summary_service import ExecutiveSummaryService
from app.application.services.headers_diff_service import HeadersDiffService
from app.application.services.ports_diff_service import PortsDiffService
from app.application.services.recommendation_service import RecommendationService
from app.application.services.risk_score_calculator_service import RiskScoreCalculatorService
from app.application.services.services_diff_service import ServicesDiffService
from app.application.services.severity_classifier_service import SeverityClassifierService
from app.application.services.snapshot_validator_service import SnapshotValidatorService
from app.application.services.ssl_tls_diff_service import SslTlsDiffService
from app.application.services.subdomains_diff_service import SubdomainsDiffService
from app.domain.entities.change_report import ChangeReport
from app.domain.entities.detected_change import DetectedChange
from app.domain.value_objects.severity_level import SeverityLevel
from app.shared.date_utils import get_current_timestamp, get_date_for_reports
from app.shared.logger import logger


class MonitorAttackSurfaceChangesUseCase:
    def __init__(self, reader: SnapshotReaderInterface, exporters: List[ReportExporterInterface]):
        self.reader = reader
        self.exporters = exporters

        # Inyección interna de servicios de aplicación para simplificar la firma del cliente
        self.validator_service = SnapshotValidatorService()
        self.ports_diff = PortsDiffService()
        self.subdomains_diff = SubdomainsDiffService()
        self.services_diff = ServicesDiffService()
        self.headers_diff = HeadersDiffService()
        self.ssl_tls_diff = SslTlsDiffService()
        self.endpoint_diff = EndpointDiffService()

        self.severity_classifier = SeverityClassifierService()
        self.risk_calculator = RiskScoreCalculatorService()
        self.recommendation_service = RecommendationService()
        self.summary_service = ExecutiveSummaryService()

    def execute(
        self,
        prev_dir: Path,
        curr_dir: Path,
        output_dir: Path,
        errors_list: List[Dict[str, str]] = None,
    ) -> Tuple[ChangeReport, List[Path]]:
        """
        Orquesta el flujo completo de comparación de superficie de ataque.
        """
        if errors_list is None:
            errors_list = []

        logger.info("Iniciando auditoría defensiva de cambios en superficie de ataque...")

        # 1. Cargar snapshots
        logger.info("Cargando escaneo anterior...")
        prev_snap = self.reader.read_snapshot(prev_dir, "escaneo_anterior")

        logger.info("Cargando escaneo actual...")
        curr_snap = self.reader.read_snapshot(curr_dir, "escaneo_actual")

        # 2. Validar estructura
        self.validator_service.validate(prev_snap)
        self.validator_service.validate(curr_snap)

        # 3. Comparar activos (Generando diccionarios de cambios en formato unificado)
        logger.info("Comparando puertos...")
        raw_port_changes = self.ports_diff.compare(prev_snap.puertos, curr_snap.puertos)

        logger.info("Comparando subdominios...")
        raw_sub_changes = self.subdomains_diff.compare(prev_snap.subdominios, curr_snap.subdominios)

        logger.info("Comparando servicios...")
        raw_svc_changes = self.services_diff.compare(prev_snap.servicios, curr_snap.servicios)

        logger.info("Comparando headers de seguridad...")
        raw_header_changes = self.headers_diff.compare(prev_snap.headers, curr_snap.headers)

        logger.info("Comparando configuración SSL/TLS...")
        raw_ssl_changes = self.ssl_tls_diff.compare(prev_snap.ssl_tls, curr_snap.ssl_tls)

        logger.info("Comparando endpoints...")
        raw_ep_changes = self.endpoint_diff.compare(prev_snap.endpoints, curr_snap.endpoints)

        # Unir todos los cambios crudos detectados
        all_raw_changes = (
            raw_port_changes
            + raw_sub_changes
            + raw_svc_changes
            + raw_header_changes
            + raw_ssl_changes
            + raw_ep_changes
        )

        # 4. Clasificar severidad, calcular score y recomendaciones para cada cambio
        logger.info("Clasificando severidad y calculando riesgo general...")
        detected_changes: List[DetectedChange] = []
        severity_counts = {
            SeverityLevel.CRITICAL: 0,
            SeverityLevel.HIGH: 0,
            SeverityLevel.MEDIUM: 0,
            SeverityLevel.LOW: 0,
            SeverityLevel.INFO: 0,
        }

        scores: List[float] = []

        for idx, rc in enumerate(all_raw_changes):
            # Asignar severidad
            severity = self.severity_classifier.classify(rc)
            severity_counts[severity] += 1

            # Calcular score de riesgo y nivel cualitativo
            score = self.risk_calculator.calculate_score(rc)
            risk_level = self.risk_calculator.map_score_to_level(score)
            scores.append(score)

            # Generar remediación
            rc["severity"] = severity
            rc["details"]["severity"] = severity.value
            recommendation = self.recommendation_service.get_recommendation(rc)
            rc["details"]["recommendation"] = recommendation

            # Crear ID único
            change_id = (
                f"CHG-{get_current_timestamp().replace(':', '').replace('-', '')[:8]}-{idx + 1:03d}"
            )

            # Construir entidad del dominio
            change_entity = DetectedChange(
                change_id=change_id,
                asset_type=rc["asset_type"],
                change_type=rc["change_type"],
                asset_identifier=rc["asset_identifier"],
                previous_value=rc["previous_value"],
                current_value=rc["current_value"],
                severity=severity,
                risk_score=score,
                risk_level=risk_level,
                description=rc["description"],
                impact=f"Impacto potencial asociado a la exposición de {rc['asset_type'].value} de severidad {severity.value}.",
                recommendation=recommendation,
                detected_at=get_date_for_reports(),
            )
            detected_changes.append(change_entity)

            # Enlazar la entidad con el diccionario crudo original para uso de los exportadores
            rc["entity"] = change_entity

        # 5. Calcular score de riesgo de la superficie global
        overall_risk_score = self.risk_calculator.calculate_overall_risk(scores)
        overall_risk_level = self.risk_calculator.map_score_to_level(overall_risk_score)

        # 6. Generar resumen ejecutivo
        stats_summary = {
            "total": len(detected_changes),
            "critical": severity_counts[SeverityLevel.CRITICAL],
            "high": severity_counts[SeverityLevel.HIGH],
            "medium": severity_counts[SeverityLevel.MEDIUM],
            "low": severity_counts[SeverityLevel.LOW],
            "info": severity_counts[SeverityLevel.INFO],
        }
        executive_summary = self.summary_service.generate(
            stats_summary, overall_risk_score, overall_risk_level
        )

        # 7. Crear entidad reporte consolidada
        report = ChangeReport(
            total_changes=stats_summary["total"],
            critical_changes=stats_summary["critical"],
            high_changes=stats_summary["high"],
            medium_changes=stats_summary["medium"],
            low_changes=stats_summary["low"],
            info_changes=stats_summary["info"],
            changes=detected_changes,
            executive_summary=executive_summary,
            generated_at=get_date_for_reports(),
            riesgo_general=overall_risk_score,
            risk_level_general=overall_risk_level,
        )

        # Adjuntar listas auxiliares para uso de infraestructura (Excel y PDF)
        # Esto evita acoplar el dominio con estructuras complejas de tablas.
        # Guardamos en los meta-atributos del reporte
        report.raw_changes = all_raw_changes
        report.errors = errors_list

        # 8. Exportar reportes
        exported_paths: List[Path] = []
        for exporter in self.exporters:
            name = exporter.__class__.__name__
            logger.info(f"Generando reporte {name.replace('ReportExporter', '')}...")
            try:
                path = exporter.export(report, output_dir)
                exported_paths.append(path)
            except Exception as e:
                logger.error(f"Fallo al exportar reporte con {name}: {str(e)}")
                errors_list.append(
                    {
                        "archivo": "ReportExporter",
                        "tipo_error": name,
                        "mensaje_error": f"Fallo en la exportación: {str(e)}",
                        "fecha": get_date_for_reports(),
                    }
                )

        logger.info("Auditoría de superficie de ataque completada exitosamente.")
        return report, exported_paths
