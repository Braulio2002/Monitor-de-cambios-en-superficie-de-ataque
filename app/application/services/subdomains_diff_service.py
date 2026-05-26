from typing import Any, Dict, List

from app.domain.entities.subdomain_asset import SubdomainAsset
from app.domain.value_objects.asset_type import AssetType
from app.domain.value_objects.change_type import ChangeType


class SubdomainsDiffService:
    def compare(
        self, previous: List[SubdomainAsset], current: List[SubdomainAsset]
    ) -> List[Dict[str, Any]]:
        """
        Compara los subdominios del escaneo anterior vs actual.
        Detecta adiciones, eliminaciones y cambios en IPs, estado o tecnologías.
        """
        changes = []

        # Mapear por clave única: subdomain
        prev_map = {s.subdomain: s for s in previous}
        curr_map = {s.subdomain: s for s in current}

        all_subdomains = set(prev_map.keys()).union(set(curr_map.keys()))

        for sub in all_subdomains:
            prev_sub = prev_map.get(sub)
            curr_sub = curr_map.get(sub)

            # Caso 1: Nuevo subdominio expuesto
            if curr_sub and not prev_sub:
                tech = curr_sub.technology or "N/A"
                desc = f"Nuevo subdominio detectado: {sub} apuntando a IP {curr_sub.ip}"
                if curr_sub.http_status:
                    desc += f" (HTTP Status: {curr_sub.http_status})"
                if curr_sub.technology:
                    desc += f" usando {tech}"

                changes.append(
                    {
                        "asset_type": AssetType.SUBDOMAIN,
                        "change_type": ChangeType.ADDED,
                        "asset_identifier": sub,
                        "previous_value": "No registrado",
                        "current_value": f"Activo [IP: {curr_sub.ip}]",
                        "description": desc,
                        "details": {
                            "domain": curr_sub.domain,
                            "subdomain": sub,
                            "previous_ip": None,
                            "current_ip": curr_sub.ip,
                            "previous_status": "inactive",
                            "current_status": curr_sub.status,
                            "previous_http_status": None,
                            "current_http_status": curr_sub.http_status,
                            "previous_technology": None,
                            "current_technology": curr_sub.technology,
                        },
                    }
                )

            # Caso 2: Subdominio eliminado o inactivo
            elif prev_sub and not curr_sub:
                changes.append(
                    {
                        "asset_type": AssetType.SUBDOMAIN,
                        "change_type": ChangeType.REMOVED,
                        "asset_identifier": sub,
                        "previous_value": f"Activo [IP: {prev_sub.ip}]",
                        "current_value": "No registrado / Inactivo",
                        "description": f"Subdominio eliminado o fuera de alcance: {sub}",
                        "details": {
                            "domain": prev_sub.domain,
                            "subdomain": sub,
                            "previous_ip": prev_sub.ip,
                            "current_ip": None,
                            "previous_status": prev_sub.status,
                            "current_status": "inactive",
                            "previous_http_status": prev_sub.http_status,
                            "current_http_status": None,
                            "previous_technology": prev_sub.technology,
                            "current_technology": None,
                        },
                    }
                )

            # Caso 3: Modificaciones
            elif prev_sub and curr_sub:
                ip_changed = prev_sub.ip != curr_sub.ip
                status_changed = prev_sub.status != curr_sub.status
                http_status_changed = prev_sub.http_status != curr_sub.http_status
                tech_changed = prev_sub.technology != curr_sub.technology

                if ip_changed or status_changed or http_status_changed or tech_changed:
                    desc_parts = []
                    if ip_changed:
                        desc_parts.append(f"IP ({prev_sub.ip} -> {curr_sub.ip})")
                    if status_changed:
                        desc_parts.append(f"estado ({prev_sub.status} -> {curr_sub.status})")
                    if http_status_changed:
                        desc_parts.append(
                            f"HTTP Status ({prev_sub.http_status or 'N/A'} -> {curr_sub.http_status or 'N/A'})"
                        )
                    if tech_changed:
                        desc_parts.append(
                            f"tecnología ({prev_sub.technology or 'N/A'} -> {curr_sub.technology or 'N/A'})"
                        )

                    desc = (
                        f"Modificación en subdominio {sub}: se detectaron cambios en "
                        + ", ".join(desc_parts)
                    )

                    changes.append(
                        {
                            "asset_type": AssetType.SUBDOMAIN,
                            "change_type": ChangeType.MODIFIED,
                            "asset_identifier": sub,
                            "previous_value": f"IP: {prev_sub.ip}, HTTP: {prev_sub.http_status or 'N/A'}, Tech: {prev_sub.technology or 'N/A'}",
                            "current_value": f"IP: {curr_sub.ip}, HTTP: {curr_sub.http_status or 'N/A'}, Tech: {curr_sub.technology or 'N/A'}",
                            "description": desc,
                            "details": {
                                "domain": curr_sub.domain,
                                "subdomain": sub,
                                "previous_ip": prev_sub.ip,
                                "current_ip": curr_sub.ip,
                                "previous_status": prev_sub.status,
                                "current_status": curr_sub.status,
                                "previous_http_status": prev_sub.http_status,
                                "current_http_status": curr_sub.http_status,
                                "previous_technology": prev_sub.technology,
                                "current_technology": curr_sub.technology,
                            },
                        }
                    )

        return changes
