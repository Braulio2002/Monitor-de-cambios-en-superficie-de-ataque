import re
from typing import Optional


def normalize_domain(domain: Optional[str]) -> str:
    if not domain:
        return ""
    return domain.strip().lower()


def normalize_url(url: Optional[str]) -> str:
    if not url:
        return ""
    return url.strip().lower().rstrip("/")


def normalize_service_name(service: Optional[str]) -> str:
    if not service:
        return "unknown"
    return service.strip().lower()


def normalize_header_name(header: Optional[str]) -> str:
    if not header:
        return ""
    # Retorna con formato capitalizado estándar e.g. strict-transport-security -> Strict-Transport-Security
    parts = header.strip().split("-")
    return "-".join(part.capitalize() for part in parts)


def mask_sensitive_data(value: Optional[str]) -> str:
    """Enmascara banners, tokens de API, contraseñas o datos sensibles detectados."""
    if not value:
        return ""

    value_str = str(value)

    # Patrones comunes de secretos
    api_key_pattern = re.compile(
        r'(key|token|auth|pass|secret|pwd|apikey)([\s:=\'"]+)([a-zA-Z0-9_\-\.]{8,})', re.IGNORECASE
    )

    def replace_secret(match):
        prefix = match.group(1) + match.group(2)
        secret = match.group(3)
        masked = secret[:3] + "********" + secret[-3:] if len(secret) > 6 else "********"
        return f"{prefix}{masked}"

    masked_value = api_key_pattern.sub(replace_secret, value_str)

    # Limitar longitud máxima de banners muy largos para evitar contaminación visual
    if len(masked_value) > 200:
        return masked_value[:200] + " ... [TRUNCATED FOR SECURITY]"

    return masked_value
