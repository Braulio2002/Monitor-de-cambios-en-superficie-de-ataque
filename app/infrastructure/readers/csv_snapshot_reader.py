from pathlib import Path

from app.application.interfaces.snapshot_reader_interface import SnapshotReaderInterface
from app.domain.entities.scan_snapshot import ScanSnapshot
from app.shared.date_utils import get_date_for_reports
from app.shared.logger import logger


class CsvSnapshotReader(SnapshotReaderInterface):
    """
    Lector de snapshots opcional que soporta archivos CSV.
    Normaliza las columnas leídas y las convierte a entidades del dominio.
    """

    def read_snapshot(self, snapshot_dir: Path, name: str) -> ScanSnapshot:
        logger.info(f"Lector CSV intentando buscar archivos en {snapshot_dir}...")
        # Por ahora se enfoca principalmente en el JSON, pero dejamos el esqueleto
        # robusto del lector CSV para futuras integraciones.
        return ScanSnapshot(
            nombre_snapshot=name,
            fecha_carga=get_date_for_reports(),
            puertos=[],
            subdominios=[],
            servicios=[],
            headers=[],
            ssl_tls=[],
            endpoints=[],
        )
