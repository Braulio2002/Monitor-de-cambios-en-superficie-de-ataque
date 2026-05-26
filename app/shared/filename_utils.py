from pathlib import Path


def generate_unique_report_path(base_dir: Path, base_name: str, extension: str) -> Path:
    """
    Genera una ruta única para un reporte. Si ya existe un archivo con ese nombre,
    agrega un sufijo numérico incremental e.g. report.xlsx -> report_1.xlsx -> report_2.xlsx
    """
    # Limpiar extensión del base_name por si acaso
    clean_base = base_name
    if base_name.endswith(extension):
        clean_base = base_name[: -len(extension)].rstrip(".")

    ext = extension.lstrip(".")

    candidate = base_dir / f"{clean_base}.{ext}"
    if not candidate.exists():
        return candidate

    counter = 1
    while True:
        candidate = base_dir / f"{clean_base}_{counter}.{ext}"
        if not candidate.exists():
            return candidate
        counter += 1
