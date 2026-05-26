from abc import ABC, abstractmethod
from pathlib import Path

from app.domain.entities.scan_snapshot import ScanSnapshot


class SnapshotReaderInterface(ABC):
    @abstractmethod
    def read_snapshot(self, snapshot_dir: Path, name: str) -> ScanSnapshot:
        """
        Lee los archivos de escaneo (ports, subdomains, etc.) desde una carpeta
        específica y construye una entidad ScanSnapshot.
        """
        pass
