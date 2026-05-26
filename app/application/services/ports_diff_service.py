from typing import Any, Dict, List

from app.domain.entities.exposed_port import ExposedPort
from app.domain.value_objects.asset_type import AssetType
from app.domain.value_objects.change_type import ChangeType
from app.shared.normalization_utils import mask_sensitive_data


class PortsDiffService:
    def compare(
        self, previous: List[ExposedPort], current: List[ExposedPort]
    ) -> List[Dict[str, Any]]:
        """
        Compara los puertos del escaneo anterior vs actual.
        Retorna una lista de diccionarios que describen los cambios.
        """
        changes = []

        # Mapear por clave única: (target, port, protocol)
        prev_map = {(p.target, p.port, p.protocol): p for p in previous}
        curr_map = {(p.target, p.port, p.protocol): p for p in current}

        all_keys = set(prev_map.keys()).union(set(curr_map.keys()))

        for key in all_keys:
            target, port, protocol = key
            prev_port = prev_map.get(key)
            curr_port = curr_map.get(key)

            identifier = f"{target}:{port} ({protocol})"

            # Caso 1: Nuevo puerto abierto
            if curr_port and not prev_port:
                service = curr_port.service or "unknown"
                version = curr_port.version or ""
                banner = mask_sensitive_data(curr_port.banner) or ""

                desc = f"Nuevo puerto abierto detectado: {port}/{protocol} exponiendo servicio '{service}'"
                if version:
                    desc += f" (versión {version})"

                changes.append(
                    {
                        "asset_type": AssetType.PORT,
                        "change_type": ChangeType.ADDED,
                        "asset_identifier": identifier,
                        "previous_value": "Cerrado / No expuesto",
                        "current_value": f"Abierto [Servicio: {service}]",
                        "description": desc,
                        "details": {
                            "target": target,
                            "ip": curr_port.ip,
                            "port": port,
                            "protocol": protocol,
                            "previous_status": "closed",
                            "current_status": curr_port.status,
                            "previous_service": None,
                            "current_service": service,
                            "previous_version": None,
                            "current_version": version,
                            "banner": banner,
                        },
                    }
                )

            # Caso 2: Puerto cerrado
            elif prev_port and not curr_port:
                service = prev_port.service or "unknown"
                changes.append(
                    {
                        "asset_type": AssetType.PORT,
                        "change_type": ChangeType.REMOVED,
                        "asset_identifier": identifier,
                        "previous_value": f"Abierto [Servicio: {service}]",
                        "current_value": "Cerrado / No expuesto",
                        "description": f"Puerto cerrado que antes estaba abierto: {port}/{protocol} ({service})",
                        "details": {
                            "target": target,
                            "ip": prev_port.ip,
                            "port": port,
                            "protocol": protocol,
                            "previous_status": prev_port.status,
                            "current_status": "closed",
                            "previous_service": service,
                            "current_service": None,
                            "previous_version": prev_port.version,
                            "current_version": None,
                            "banner": "",
                        },
                    }
                )

            # Caso 3: Modificaciones (cambió el servicio, versión o banner)
            elif prev_port and curr_port:
                service_changed = prev_port.service != curr_port.service
                version_changed = prev_port.version != curr_port.version
                banner_changed = prev_port.banner != curr_port.banner
                status_changed = prev_port.status != curr_port.status

                if service_changed or version_changed or banner_changed or status_changed:
                    desc_parts = []
                    if status_changed:
                        desc_parts.append(f"estado ({prev_port.status} -> {curr_port.status})")
                    if service_changed:
                        desc_parts.append(f"servicio ({prev_port.service} -> {curr_port.service})")
                    if version_changed:
                        desc_parts.append(
                            f"versión ({prev_port.version or 'N/A'} -> {curr_port.version or 'N/A'})"
                        )

                    desc = (
                        f"Modificación en puerto {port}/{protocol}: se detectaron cambios en "
                        + ", ".join(desc_parts)
                    )

                    changes.append(
                        {
                            "asset_type": AssetType.PORT,
                            "change_type": ChangeType.MODIFIED,
                            "asset_identifier": identifier,
                            "previous_value": (
                                f"Estado: {prev_port.status}, Servicio: {prev_port.service or 'N/A'}, "
                                f"Versión: {prev_port.version or 'N/A'}"
                            ),
                            "current_value": (
                                f"Estado: {curr_port.status}, Servicio: {curr_port.service or 'N/A'}, "
                                f"Versión: {curr_port.version or 'N/A'}"
                            ),
                            "description": desc,
                            "details": {
                                "target": target,
                                "ip": curr_port.ip,
                                "port": port,
                                "protocol": protocol,
                                "previous_status": prev_port.status,
                                "current_status": curr_port.status,
                                "previous_service": prev_port.service,
                                "current_service": curr_port.service,
                                "previous_version": prev_port.version,
                                "current_version": curr_port.version,
                                "banner": mask_sensitive_data(curr_port.banner),
                            },
                        }
                    )

        return changes
