from typing import Any, Dict, List

from app.domain.entities.header_snapshot import HeaderSnapshot
from app.domain.value_objects.asset_type import AssetType
from app.domain.value_objects.change_type import ChangeType
from app.shared.constants import SECURITY_HEADERS


class HeadersDiffService:
    def compare(
        self, previous: List[HeaderSnapshot], current: List[HeaderSnapshot]
    ) -> List[Dict[str, Any]]:
        """
        Compara las cabeceras de seguridad de escaneo anterior vs actual.
        Detecta cabeceras agregadas, removidas o debilitadas.
        """
        changes = []

        # Mapear por URL
        prev_map = {h.url: h for h in previous}
        curr_map = {h.url: h for h in current}

        all_urls = set(prev_map.keys()).union(set(curr_map.keys()))

        for url in all_urls:
            prev_snap = prev_map.get(url)
            curr_snap = curr_map.get(url)

            # Si la URL completa desapareció, no evaluamos cabecera por cabecera,
            # pero si la URL existía antes y ahora no, podemos indicar que las cabeceras desaparecieron.
            # O mejor, evaluamos cada cabecera de la lista configurada.

            prev_headers = prev_snap.headers if prev_snap else {}
            curr_headers = curr_snap.headers if curr_snap else {}

            for header in SECURITY_HEADERS:
                prev_val = prev_headers.get(header)
                curr_val = curr_headers.get(header)

                identifier = f"{url} -> {header}"

                # Caso 1: Cabecera eliminada
                if prev_val and not curr_val:
                    changes.append(
                        {
                            "asset_type": AssetType.HEADER,
                            "change_type": ChangeType.REMOVED,
                            "asset_identifier": identifier,
                            "previous_value": prev_val,
                            "current_value": "No configurada",
                            "description": f"Cabecera de seguridad eliminada en {url}: {header}",
                            "details": {
                                "url": url,
                                "header": header,
                                "previous_value": prev_val,
                                "current_value": None,
                            },
                        }
                    )

                # Caso 2: Cabecera agregada
                elif not prev_val and curr_val:
                    changes.append(
                        {
                            "asset_type": AssetType.HEADER,
                            "change_type": ChangeType.ADDED,
                            "asset_identifier": identifier,
                            "previous_value": "No configurada",
                            "current_value": curr_val,
                            "description": f"Nueva cabecera de seguridad configurada en {url}: {header}",
                            "details": {
                                "url": url,
                                "header": header,
                                "previous_value": None,
                                "current_value": curr_val,
                            },
                        }
                    )

                # Caso 3: Modificada / Evaluada si se debilitó
                elif prev_val and curr_val and prev_val != curr_val:
                    is_weakened = self._check_if_weakened(header, prev_val, curr_val)
                    change_type = ChangeType.WEAKENED if is_weakened else ChangeType.MODIFIED

                    desc = f"Cabecera {header} en {url} modificada"
                    if is_weakened:
                        desc = f"Cabecera {header} en {url} debilitada (se redujeron políticas de seguridad)"

                    changes.append(
                        {
                            "asset_type": AssetType.HEADER,
                            "change_type": change_type,
                            "asset_identifier": identifier,
                            "previous_value": prev_val,
                            "current_value": curr_val,
                            "description": f"{desc}. Anterior: '{prev_val}', Actual: '{curr_val}'",
                            "details": {
                                "url": url,
                                "header": header,
                                "previous_value": prev_val,
                                "current_value": curr_val,
                            },
                        }
                    )

        return changes

    def _check_if_weakened(self, header: str, prev_val: str, curr_val: str) -> bool:
        """
        Determina de forma heurística si el cambio en la cabecera representa un debilitamiento.
        """
        p_lower = prev_val.lower()
        c_lower = curr_val.lower()

        # 1. HSTS (Strict-Transport-Security)
        if header.lower() == "strict-transport-security":
            # Si antes incluía subdominios y ahora no
            if "includesubdomains" in p_lower and "includesubdomains" not in c_lower:
                return True
            # Comparar max-age
            import re

            p_age = re.search(r"max-age=(\d+)", p_lower)
            c_age = re.search(r"max-age=(\d+)", c_lower)
            if p_age and c_age:
                try:
                    if int(c_age.group(1)) < int(p_age.group(1)):
                        return True
                except ValueError:
                    pass

        # 2. X-Frame-Options
        elif header.lower() == "x-frame-options":
            # Si pasó de DENY/SAMEORIGIN a ALLOW-FROM o algo menos estricto
            if ("deny" in p_lower or "sameorigin" in p_lower) and not (
                "deny" in c_lower or "sameorigin" in c_lower
            ):
                return True

        # 3. Content-Security-Policy
        elif header.lower() == "content-security-policy":
            # Si se habilitó 'unsafe-inline' o 'unsafe-eval' o '*' y antes no estaba
            for unsafe in ["'unsafe-inline'", "'unsafe-eval'", "*"]:
                if unsafe not in p_lower and unsafe in c_lower:
                    return True

        # 4. Set-Cookie / Cookie headers
        elif "cookie" in header.lower():
            for security_flag in ["secure", "httponly"]:
                if security_flag in p_lower and security_flag not in c_lower:
                    return True

        return False
