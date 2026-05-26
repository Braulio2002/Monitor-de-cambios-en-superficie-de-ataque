import shutil
from pathlib import Path

from app.application.use_cases.monitor_attack_surface_changes_use_case import (
    MonitorAttackSurfaceChangesUseCase,
)
from app.infrastructure.exporters.excel_report_exporter import ExcelReportExporter
from app.infrastructure.exporters.json_report_exporter import JsonReportExporter
from app.infrastructure.exporters.pdf_report_exporter import PdfReportExporter
from app.infrastructure.filesystem.directory_manager import DirectoryManager
from app.infrastructure.readers.json_snapshot_reader import JsonSnapshotReader


def test_full_integration_flow():
    # Crear un directorio temporal de pruebas dentro del workspace
    test_base = Path(
        "d:/PROYECTO TERMINADOS Y SUBIDOS A GITHUB/Monitor de cambios en superficie de ataque/tests_temp_run"
    )
    if test_base.exists():
        shutil.rmtree(test_base)
    test_base.mkdir(parents=True, exist_ok=True)

    try:
        # 1. Configurar directorios con el DirectoryManager
        dir_manager = DirectoryManager(test_base)
        dir_manager.setup_directories()

        # Verificar que se crearon los directorios y archivos de semillas
        assert dir_manager.prev_dir.exists()
        assert dir_manager.curr_dir.exists()
        assert (dir_manager.prev_dir / "ports.json").exists()

        # 2. Inicializar componentes del caso de uso
        reader = JsonSnapshotReader()
        exporters = [JsonReportExporter(), ExcelReportExporter(), PdfReportExporter()]

        use_case = MonitorAttackSurfaceChangesUseCase(reader=reader, exporters=exporters)

        # 3. Ejecutar caso de uso
        errors = []
        report, paths = use_case.execute(
            prev_dir=dir_manager.prev_dir,
            curr_dir=dir_manager.curr_dir,
            output_dir=dir_manager.output_dir,
            errors_list=errors,
        )

        # 4. Validar resultados de la ejecución
        assert report.total_changes > 0
        assert len(paths) == 3  # JSON, Excel, PDF creados

        # Validar la existencia física de los reportes
        for path in paths:
            assert path.exists()

    finally:
        # Limpieza de archivos de prueba
        if test_base.exists():
            shutil.rmtree(test_base)
