from typing import Any, Dict, List

from app.domain.entities.exposed_service import ExposedService
from app.domain.value_objects.asset_type import AssetType
from app.domain.value_objects.change_type import ChangeType


class ServicesDiffService:
    def compare(
        self, previous: List[ExposedService], current: List[ExposedService]
    ) -> List[Dict[str, Any]]:
        """
        Compara servicios expuestos de escaneo anterior vs actual.
        Identifica nuevos servicios expuestos, deshabilitados y cambios de versiones.
        """
        changes = []

        # Mapear por clave única: (host, port)
        prev_map = {(s.host, s.port): s for s in previous}
        curr_map = {(s.host, s.port): s for s in current}

        all_services = set(prev_map.keys()).union(set(curr_map.keys()))

        for key in all_services:
            host, port = key
            prev_svc = prev_map.get(key)
            curr_svc = curr_map.get(key)

            identifier = f"{host}:{port}"

            # Caso 1: Nuevo servicio expuesto
            if curr_svc and not prev_svc:
                version = curr_svc.version or "desconocida"
                desc = f"Nuevo servicio expuesto detectado: {curr_svc.service} en {host}:{port} (versión {version})"

                changes.append(
                    {
                        "asset_type": AssetType.SERVICE,
                        "change_type": ChangeType.ADDED,
                        "asset_identifier": identifier,
                        "previous_value": "No registrado",
                        "current_value": f"{curr_svc.service} (Versión: {version})",
                        "description": desc,
                        "details": {
                            "host": host,
                            "ip": curr_svc.ip,
                            "port": port,
                            "previous_service": None,
                            "current_service": curr_svc.service,
                            "previous_version": None,
                            "current_version": curr_svc.version,
                            "category": curr_svc.category,
                        },
                    }
                )

            # Caso 2: Servicio eliminado
            elif prev_svc and not curr_svc:
                desc = f"Servicio deshabilitado o retirado: {prev_svc.service} en {host}:{port}"
                changes.append(
                    {
                        "asset_type": AssetType.SERVICE,
                        "change_type": ChangeType.REMOVED,
                        "asset_identifier": identifier,
                        "previous_value": f"{prev_svc.service} (Versión: {prev_svc.version or 'desconocida'})",
                        "current_value": "Inactivo / No expuesto",
                        "description": desc,
                        "details": {
                            "host": host,
                            "ip": prev_svc.ip,
                            "port": port,
                            "previous_service": prev_svc.service,
                            "current_service": None,
                            "previous_version": prev_svc.version,
                            "current_version": None,
                            "category": prev_svc.category,
                        },
                    }
                )

            # Caso 3: Modificación en el servicio (cambió versión o servicio)
            elif prev_svc and curr_svc:
                svc_changed = prev_svc.service != curr_svc.service
                version_changed = prev_svc.version != curr_svc.version

                if svc_changed or version_changed:
                    desc_parts = []
                    if svc_changed:
                        desc_parts.append(f"servicio ({prev_svc.service} -> {curr_svc.service})")
                    if version_changed:
                        desc_parts.append(
                            f"versión ({prev_svc.version or 'N/A'} -> {curr_svc.version or 'N/A'})"
                        )

                    desc = f"Cambio de configuración de servicio en {host}:{port}: " + ", ".join(
                        desc_parts
                    )

                    changes.append(
                        {
                            "asset_type": AssetType.SERVICE,
                            "change_type": ChangeType.MODIFIED,
                            "asset_identifier": identifier,
                            "previous_value": f"Servicio: {prev_svc.service}, Versión: {prev_svc.version or 'N/A'}",
                            "current_value": f"Servicio: {curr_svc.service}, Versión: {curr_svc.version or 'N/A'}",
                            "description": desc,
                            "details": {
                                "host": host,
                                "ip": curr_svc.ip,
                                "port": port,
                                "previous_service": prev_svc.service,
                                "current_service": curr_svc.service,
                                "previous_version": prev_svc.version,
                                "current_version": curr_svc.version,
                                "category": curr_svc.category,
                            },
                        }
                    )

        return changes
