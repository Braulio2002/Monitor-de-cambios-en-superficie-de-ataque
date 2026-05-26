from app.domain.entities.scan_snapshot import ScanSnapshot
from app.shared.logger import logger


class SnapshotValidatorService:
    def validate(self, snapshot: ScanSnapshot) -> bool:
        """
        Valida que el snapshot tenga estructura consistente.
        Permite archivos/datos faltantes para tolerancia a fallos, pero
        registra advertencias o valida campos obligatorios básicos.
        """
        logger.info(f"Validando estructura del snapshot: {snapshot.nombre_snapshot}...")

        # Verificar si está completamente vacío
        is_empty = (
            not snapshot.puertos
            and not snapshot.subdominios
            and not snapshot.servicios
            and not snapshot.headers
            and not snapshot.ssl_tls
            and not snapshot.endpoints
        )

        if is_empty:
            logger.warning(
                f"El snapshot '{snapshot.nombre_snapshot}' no contiene ningún dato. "
                "Esto es válido, pero podría indicar archivos vacíos o faltantes."
            )
            return True

        # Advertencias específicas
        if not snapshot.puertos:
            logger.warning(
                f"[{snapshot.nombre_snapshot}]: No se cargaron datos de puertos (ports.json)."
            )
        if not snapshot.subdominios:
            logger.warning(
                f"[{snapshot.nombre_snapshot}]: No se cargaron datos de subdominios (subdomains.json)."
            )
        if not snapshot.servicios:
            logger.warning(
                f"[{snapshot.nombre_snapshot}]: No se cargaron datos de servicios (services.json)."
            )
        if not snapshot.headers:
            logger.warning(
                f"[{snapshot.nombre_snapshot}]: No se cargaron datos de cabeceras HTTP (headers.json)."
            )
        if not snapshot.ssl_tls:
            logger.warning(
                f"[{snapshot.nombre_snapshot}]: No se cargaron datos SSL/TLS (ssl_tls.json)."
            )

        logger.info(f"Snapshot '{snapshot.nombre_snapshot}' validado correctamente.")
        return True
