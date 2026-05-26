from dataclasses import dataclass


@dataclass
class ExposedEndpoint:
    name: str
    url: str
    method: str
    requires_auth: bool
    status_code: int
