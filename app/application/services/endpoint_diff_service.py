from typing import Any, Dict, List

from app.domain.entities.exposed_endpoint import ExposedEndpoint
from app.domain.value_objects.asset_type import AssetType
from app.domain.value_objects.change_type import ChangeType


class EndpointDiffService:
    def compare(
        self, previous: List[ExposedEndpoint], current: List[ExposedEndpoint]
    ) -> List[Dict[str, Any]]:
        """
        Compara endpoints expuestos. Detecta endpoints nuevos, eliminados
        y modificaciones de autorización (de privado a público) o códigos de estado.
        """
        changes = []

        prev_map = {(e.url, e.method): e for e in previous}
        curr_map = {(e.url, e.method): e for e in current}

        all_endpoints = set(prev_map.keys()).union(set(curr_map.keys()))

        for key in all_endpoints:
            url, method = key
            prev_ep = prev_map.get(key)
            curr_ep = curr_map.get(key)

            identifier = f"{method} {url}"

            # Caso 1: Nuevo endpoint expuesto
            if curr_ep and not prev_ep:
                auth_desc = (
                    "requiere autenticación"
                    if curr_ep.requires_auth
                    else "NO REQUIERE AUTENTICACIÓN (PÚBLICO)"
                )
                desc = f"Nuevo endpoint web expuesto: {method} {url} [{curr_ep.name}] ({auth_desc})"

                changes.append(
                    {
                        "asset_type": AssetType.ENDPOINT,
                        "change_type": ChangeType.ADDED,
                        "asset_identifier": identifier,
                        "previous_value": "No expuesto",
                        "current_value": f"Expuesto [Requiere Auth: {curr_ep.requires_auth}]",
                        "description": desc,
                        "details": {
                            "name": curr_ep.name,
                            "url": url,
                            "method": method,
                            "previous_auth": None,
                            "current_auth": curr_ep.requires_auth,
                            "previous_status": None,
                            "current_status": curr_ep.status_code,
                        },
                    }
                )

            # Caso 2: Endpoint eliminado
            elif prev_ep and not curr_ep:
                desc = f"Endpoint web removido o deshabilitado: {method} {url} [{prev_ep.name}]"
                changes.append(
                    {
                        "asset_type": AssetType.ENDPOINT,
                        "change_type": ChangeType.REMOVED,
                        "asset_identifier": identifier,
                        "previous_value": f"Expuesto [Requiere Auth: {prev_ep.requires_auth}]",
                        "current_value": "No expuesto",
                        "description": desc,
                        "details": {
                            "name": prev_ep.name,
                            "url": url,
                            "method": method,
                            "previous_auth": prev_ep.requires_auth,
                            "current_auth": None,
                            "previous_status": prev_ep.status_code,
                            "current_status": None,
                        },
                    }
                )

            # Caso 3: Modificaciones (especialmente si perdió autenticación)
            elif prev_ep and curr_ep:
                auth_lost = prev_ep.requires_auth and not curr_ep.requires_auth
                auth_gained = not prev_ep.requires_auth and curr_ep.requires_auth
                status_changed = prev_ep.status_code != curr_ep.status_code

                if auth_lost or auth_gained or status_changed:
                    if auth_lost:
                        change_type = ChangeType.WEAKENED
                        desc = f"CRÍTICO: El endpoint {method} {url} [{curr_ep.name}] perdió su autenticación y ahora responde públicamente"
                    elif auth_gained:
                        change_type = ChangeType.IMPROVED
                        desc = f"Mejora de seguridad: Se añadió control de autenticación al endpoint {method} {url}"
                    else:
                        change_type = ChangeType.MODIFIED
                        desc = f"Modificación de código de estado en endpoint {method} {url}: {prev_ep.status_code} -> {curr_ep.status_code}"

                    changes.append(
                        {
                            "asset_type": AssetType.ENDPOINT,
                            "change_type": change_type,
                            "asset_identifier": identifier,
                            "previous_value": f"Auth: {prev_ep.requires_auth}, HTTP: {prev_ep.status_code}",
                            "current_value": f"Auth: {curr_ep.requires_auth}, HTTP: {curr_ep.status_code}",
                            "description": desc,
                            "details": {
                                "name": curr_ep.name,
                                "url": url,
                                "method": method,
                                "previous_auth": prev_ep.requires_auth,
                                "current_auth": curr_ep.requires_auth,
                                "previous_status": prev_ep.status_code,
                                "current_status": curr_ep.status_code,
                            },
                        }
                    )

        return changes
