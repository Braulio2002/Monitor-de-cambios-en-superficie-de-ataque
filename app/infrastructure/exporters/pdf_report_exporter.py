from pathlib import Path

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_LEFT
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.platypus import (
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

from app.application.interfaces.report_exporter_interface import ReportExporterInterface
from app.domain.entities.change_report import ChangeReport
from app.domain.value_objects.severity_level import SeverityLevel
from app.shared.filename_utils import generate_unique_report_path
from app.shared.logger import logger


class PdfReportExporter(ReportExporterInterface):
    def export(self, report: ChangeReport, output_dir: Path) -> Path:
        """
        Exporta el reporte ejecutivo en un PDF elegante y profesional.
        """
        output_path = generate_unique_report_path(
            output_dir, "attack_surface_changes_report", ".pdf"
        )

        # Configurar documento
        doc = SimpleDocTemplate(
            str(output_path),
            pagesize=letter,
            rightMargin=36,
            leftMargin=36,
            topMargin=54,
            bottomMargin=54,
        )

        styles = getSampleStyleSheet()

        # Paleta de colores Ciberseguridad
        c_primary = colors.HexColor("#1B365D")  # Azul marino oscuro
        c_secondary = colors.HexColor("#4A5568")  # Gris oscuro
        c_bg_light = colors.HexColor("#F7FAFC")  # Fondo claro

        severity_colors = {
            "CRITICAL": colors.HexColor("#D32F2F"),  # Rojo
            "HIGH": colors.HexColor("#F57C00"),  # Naranja
            "MEDIUM": colors.HexColor("#FBC02D"),  # Amarillo
            "LOW": colors.HexColor("#1976D2"),  # Azul
            "INFO": colors.HexColor("#388E3C"),  # Verde
        }

        # Registrar estilos de párrafo propios
        title_style = ParagraphStyle(
            "PdfTitle",
            parent=styles["Heading1"],
            fontName="Helvetica-Bold",
            fontSize=22,
            textColor=c_primary,
            spaceAfter=15,
            alignment=TA_LEFT,
        )

        section_style = ParagraphStyle(
            "PdfSection",
            parent=styles["Heading2"],
            fontName="Helvetica-Bold",
            fontSize=14,
            textColor=c_primary,
            spaceBefore=15,
            spaceAfter=10,
        )

        normal_style = ParagraphStyle(
            "PdfNormal",
            parent=styles["Normal"],
            fontName="Helvetica",
            fontSize=10,
            textColor=c_secondary,
            leading=14,
        )

        bold_style = ParagraphStyle("PdfBold", parent=normal_style, fontName="Helvetica-Bold")

        ParagraphStyle(
            "PdfBadge",
            parent=styles["Normal"],
            fontName="Helvetica-Bold",
            fontSize=12,
            textColor=colors.white,
            alignment=TA_CENTER,
        )

        header_table_style = ParagraphStyle(
            "PdfTableHeader",
            parent=styles["Normal"],
            fontName="Helvetica-Bold",
            fontSize=9,
            textColor=colors.white,
            alignment=TA_LEFT,
        )

        cell_table_style = ParagraphStyle(
            "PdfTableCell",
            parent=styles["Normal"],
            fontName="Helvetica",
            fontSize=8,
            textColor=c_secondary,
            leading=10,
            alignment=TA_LEFT,
        )

        story = []

        # --- ENCABEZADO Y TÍTULO ---
        story.append(Paragraph("Monitor de Cambios en Superficie de Ataque", title_style))
        story.append(
            Paragraph(
                f"Reporte Ejecutivo de Auditoría Defensiva — Generado el {report.generated_at}",
                normal_style,
            )
        )
        story.append(Spacer(1, 15))

        # --- TABLA DE METADATOS Y SCORE ---
        risk_color = severity_colors.get(report.risk_level_general.value, c_secondary)

        meta_data = [
            [
                Paragraph("<b>Total de Cambios:</b>", normal_style),
                Paragraph(str(report.total_changes), bold_style),
                Paragraph("<b>Riesgo General:</b>", normal_style),
                Paragraph(
                    f"<font color='{risk_color.hexval()}'><b>{report.riesgo_general:.1f}/100 ({report.risk_level_general.value})</b></font>",
                    bold_style,
                ),
            ],
            [
                Paragraph("<b>Cambios Críticos:</b>", normal_style),
                Paragraph(
                    f"<font color='{severity_colors['CRITICAL'].hexval()}'><b>{report.critical_changes}</b></font>",
                    bold_style,
                ),
                Paragraph("<b>Cambios Altos:</b>", normal_style),
                Paragraph(
                    f"<font color='{severity_colors['HIGH'].hexval()}'><b>{report.high_changes}</b></font>",
                    bold_style,
                ),
            ],
            [
                Paragraph("<b>Cambios Medios:</b>", normal_style),
                Paragraph(str(report.medium_changes), bold_style),
                Paragraph("<b>Cambios Bajos/Info:</b>", normal_style),
                Paragraph(str(report.low_changes + report.info_changes), bold_style),
            ],
        ]

        meta_table = Table(meta_data, colWidths=[130, 100, 130, 180])
        meta_table.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, -1), c_bg_light),
                    ("ALIGN", (0, 0), (-1, -1), "LEFT"),
                    ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                    ("TOPPADDING", (0, 0), (-1, -1), 8),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
                    ("LEFTPADDING", (0, 0), (-1, -1), 12),
                    ("RIGHTPADDING", (0, 0), (-1, -1), 12),
                    ("BOX", (0, 0), (-1, -1), 1, colors.HexColor("#CBD5E0")),
                    ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#E2E8F0")),
                ]
            )
        )
        story.append(meta_table)
        story.append(Spacer(1, 20))

        # --- RESUMEN EJECUTIVO ---
        story.append(Paragraph("Resumen Ejecutivo", section_style))
        # Reemplazar saltos de línea por <br/>
        html_summary = report.executive_summary.replace("\n", "<br/>")
        story.append(Paragraph(html_summary, normal_style))
        story.append(Spacer(1, 20))

        # --- CAMBIOS CRÍTICOS Y ALTOS DETECTADOS ---
        story.append(Paragraph("Detalle de Cambios Críticos y de Alta Prioridad", section_style))

        # Filtrar cambios relevantes
        critical_changes = [
            c
            for c in report.changes
            if c.severity in [SeverityLevel.CRITICAL, SeverityLevel.HIGH, SeverityLevel.MEDIUM]
        ]

        if not critical_changes:
            story.append(
                Paragraph(
                    "No se detectaron cambios de severidad Crítica, Alta o Media en este ciclo de auditoría.",
                    normal_style,
                )
            )
        else:
            table_data = [
                [
                    Paragraph("ID", header_table_style),
                    Paragraph("Activo", header_table_style),
                    Paragraph("Tipo Cambio", header_table_style),
                    Paragraph("Severidad", header_table_style),
                    Paragraph("Descripción / Impacto", header_table_style),
                ]
            ]

            for c in critical_changes:
                sev_color = severity_colors.get(c.severity.value, c_secondary)
                table_data.append(
                    [
                        Paragraph(c.change_id, cell_table_style),
                        Paragraph(
                            f"<b>{c.asset_type.value}</b><br/>{c.asset_identifier}",
                            cell_table_style,
                        ),
                        Paragraph(c.change_type.value, cell_table_style),
                        Paragraph(
                            f"<font color='{sev_color.hexval()}'><b>{c.severity.value}</b></font> (Score: {c.risk_score})",
                            cell_table_style,
                        ),
                        Paragraph(
                            f"{c.description}<br/><i>Mitigación: {c.recommendation}</i>",
                            cell_table_style,
                        ),
                    ]
                )

            # Calcular anchos: total disponible es 540 ptos (letter es 612 ptos de ancho)
            chg_table = Table(table_data, colWidths=[55, 110, 65, 85, 225])
            chg_table.setStyle(
                TableStyle(
                    [
                        ("BACKGROUND", (0, 0), (-1, 0), c_primary),
                        ("ALIGN", (0, 0), (-1, -1), "LEFT"),
                        ("VALIGN", (0, 0), (-1, -1), "TOP"),
                        ("TOPPADDING", (0, 0), (-1, -1), 6),
                        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
                        ("LEFTPADDING", (0, 0), (-1, -1), 6),
                        ("RIGHTPADDING", (0, 0), (-1, -1), 6),
                        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#CBD5E0")),
                        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, c_bg_light]),
                    ]
                )
            )
            story.append(chg_table)

        story.append(Spacer(1, 20))

        # --- ERRORES DE ANÁLISIS ---
        errors = getattr(report, "errors", [])
        if errors:
            story.append(Paragraph("Alertas e Incidencias en la Auditoría", section_style))
            err_data = [
                [
                    Paragraph("Archivo", header_table_style),
                    Paragraph("Tipo de Incidencia", header_table_style),
                    Paragraph("Detalle de la Alerta", header_table_style),
                ]
            ]
            for err in errors:
                err_data.append(
                    [
                        Paragraph(err.get("archivo", ""), cell_table_style),
                        Paragraph(err.get("tipo_error", ""), cell_table_style),
                        Paragraph(err.get("mensaje_error", ""), cell_table_style),
                    ]
                )

            err_table = Table(err_data, colWidths=[100, 120, 320])
            err_table.setStyle(
                TableStyle(
                    [
                        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#E53E3E")),  # Rojo oscuro
                        ("ALIGN", (0, 0), (-1, -1), "LEFT"),
                        ("VALIGN", (0, 0), (-1, -1), "TOP"),
                        ("TOPPADDING", (0, 0), (-1, -1), 5),
                        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
                        ("LEFTPADDING", (0, 0), (-1, -1), 6),
                        ("RIGHTPADDING", (0, 0), (-1, -1), 6),
                        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#E2E8F0")),
                    ]
                )
            )
            story.append(err_table)

        # Generar el PDF
        doc.build(story)
        logger.info(f"Reporte PDF ejecutivo generado correctamente en: {output_path.name}")
        return output_path
