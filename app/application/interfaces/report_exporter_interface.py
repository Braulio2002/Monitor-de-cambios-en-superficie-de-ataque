from abc import ABC, abstractmethod
from pathlib import Path

from app.domain.entities.change_report import ChangeReport


class ReportExporterInterface(ABC):
    @abstractmethod
    def export(self, report: ChangeReport, output_dir: Path) -> Path:
        """
        Exporta el reporte consolidado de cambios a un formato específico
        (JSON, Excel, PDF) y retorna la ruta del archivo generado.
        """
        pass
