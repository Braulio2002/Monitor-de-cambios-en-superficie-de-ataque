import json
from pathlib import Path

from app.application.interfaces.report_exporter_interface import ReportExporterInterface
from app.domain.entities.change_report import ChangeReport
from app.shared.filename_utils import generate_unique_report_path
from app.shared.logger import logger


class JsonReportExporter(ReportExporterInterface):
    def export(self, report: ChangeReport, output_dir: Path) -> Path:
        """
        Exporta el reporte de cambios en formato JSON estructurado.
        """
        output_path = generate_unique_report_path(
            output_dir, "attack_surface_changes_report", ".json"
        )

        # Convertir reporte a estructura serializable
        report_dict = {
            "metadata": {
                "generated_at": report.generated_at,
                "total_changes": report.total_changes,
                "critical_changes": report.critical_changes,
                "high_changes": report.high_changes,
                "medium_changes": report.medium_changes,
                "low_changes": report.low_changes,
                "info_changes": report.info_changes,
                "riesgo_general": round(report.riesgo_general, 2),
                "nivel_riesgo_general": report.risk_level_general.value,
            },
            "executive_summary": report.executive_summary,
            "changes": [
                {
                    "change_id": c.change_id,
                    "asset_type": c.asset_type.value,
                    "change_type": c.change_type.value,
                    "asset_identifier": c.asset_identifier,
                    "previous_value": c.previous_value,
                    "current_value": c.current_value,
                    "severity": c.severity.value,
                    "risk_score": c.risk_score,
                    "risk_level": c.risk_level.value,
                    "description": c.description,
                    "impact": c.impact,
                    "recommendation": c.recommendation,
                    "detected_at": c.detected_at,
                }
                for c in report.changes
            ],
            "errors": getattr(report, "errors", []),
        }

        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(report_dict, f, indent=2, ensure_ascii=False)

        logger.info(f"Reporte JSON guardado en: {output_path.name}")
        return output_path
