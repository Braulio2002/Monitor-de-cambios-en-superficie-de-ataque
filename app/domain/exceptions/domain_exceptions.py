class DomainException(Exception):
    """Clase base para todas las excepciones del dominio."""

    pass


class InvalidSnapshotException(DomainException):
    """Excepción lanzada cuando los datos de un snapshot son inválidos o están corruptos."""

    pass


class ValidationException(DomainException):
    """Excepción lanzada en caso de fallos de validación estructural."""

    pass


class ReaderException(DomainException):
    """Excepción lanzada cuando falla la lectura o carga de snapshots."""

    pass


class ExporterException(DomainException):
    """Excepción lanzada cuando ocurre un error al exportar reportes."""

    pass
