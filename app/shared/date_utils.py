from datetime import datetime, timezone


def get_current_timestamp() -> str:
    """Retorna la fecha y hora actual con zona horaria UTC en formato ISO 8601."""
    return datetime.now(timezone.utc).isoformat()


def get_date_for_reports() -> str:
    """Retorna la fecha formateada para mostrar en reportes (YYYY-MM-DD HH:MM:SS)."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
