import sys
from pathlib import Path
from typing import Dict, List

from app.application.use_cases.monitor_attack_surface_changes_use_case import (
    MonitorAttackSurfaceChangesUseCase,
)
from app.config.settings import BASE_DIR, CURRENT_SCAN_DIR, OUTPUT_DIR, PREVIOUS_SCAN_DIR
from app.domain.entities.change_report import ChangeReport
from app.infrastructure.exporters.excel_report_exporter import ExcelReportExporter
from app.infrastructure.exporters.json_report_exporter import JsonReportExporter
from app.infrastructure.exporters.pdf_report_exporter import PdfReportExporter
from app.infrastructure.filesystem.directory_manager import DirectoryManager
from app.infrastructure.readers.json_snapshot_reader import JsonSnapshotReader
from app.shared.logger import logger


class AttackSurfaceMonitorCLI:
    def __init__(self):
        self.directory_manager = DirectoryManager(BASE_DIR)

    def run(self) -> None:
        """
        Ejecuta la interfaz de línea de comandos del monitor de cambios de superficie de ataque.
        """
        self._print_banner()

        errors: List[Dict[str, str]] = []

        try:
            # 1. Configurar directorios y semillas de ejemplo
            self.directory_manager.setup_directories()

            # 2. Inicializar adaptadores de infraestructura
            json_reader = JsonSnapshotReader()

            exporters = [JsonReportExporter(), ExcelReportExporter(), PdfReportExporter()]

            # 3. Inicializar Caso de Uso
            use_case = MonitorAttackSurfaceChangesUseCase(reader=json_reader, exporters=exporters)

            # 4. Ejecutar el flujo de comparación
            report, paths = use_case.execute(
                prev_dir=PREVIOUS_SCAN_DIR,
                curr_dir=CURRENT_SCAN_DIR,
                output_dir=OUTPUT_DIR,
                errors_list=errors,
            )

            # Unificar los errores recolectados del lector JSON
            errors.extend(json_reader.errors)

            # 5. Presentar los resultados en consola
            self._print_results(report, paths, errors)

        except Exception as e:
            logger.critical(f"Proceso detenido debido a una excepción crítica: {str(e)}")
            sys.exit(1)

    def _print_banner(self) -> None:
        banner = """
================================================================================
          MONITOR AVANZADO DE CAMBIOS EN SUPERFICIE DE ATAQUE (v1.0.0)
      [Herramienta de Auditoría Defensiva y Monitoreo de Exposición]
================================================================================
        """
        print(banner)

    def _print_results(
        self, report: ChangeReport, paths: List[Path], errors: List[Dict[str, str]]
    ) -> None:
        """Imprime un resumen formateado de los cambios y rutas de reportes."""

        print("\n================================================================================")
        print("                        RESUMEN DE AUDITORÍA DE EXPOSICIÓN                      ")
        print("================================================================================")
        print(f" Fecha de Ejecución:      {report.generated_at}")
        print(f" Puntuación de Riesgo:    {report.riesgo_general:.2f}/100")
        print(f" Nivel de Riesgo Global:  {report.risk_level_general.value}")
        print("--------------------------------------------------------------------------------")
        print(f" Total de Cambios:        {report.total_changes}")
        print(f"   [-] Críticos:          {report.critical_changes}")
        print(f"   [-] Altos:             {report.high_changes}")
        print(f"   [-] Medios:            {report.medium_changes}")
        print(f"   [-] Bajos:             {report.low_changes}")
        print(f"   [-] Informativos:      {report.info_changes}")
        print("--------------------------------------------------------------------------------")
        print(" Reportes generados correctamente en datos_salida/:")
        for path in paths:
            print(f"   [+] {path.name}")

        if errors:
            print(
                "\n--------------------------------------------------------------------------------"
            )
            print(f" Se registraron {len(errors)} incidencias no bloqueantes durante el escaneo:")
            for err in errors[:5]:
                print(
                    f"   [!] [{err.get('archivo')}] - {err.get('tipo_error')}: {err.get('mensaje_error')}"
                )
            if len(errors) > 5:
                print(
                    f"   ... y {len(errors) - 5} alertas adicionales registradas en la pestaña 'Errores' de Excel."
                )

        print("================================================================================")
        print(" Proceso finalizado.")
        print("================================================================================\n")
