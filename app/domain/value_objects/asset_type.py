from enum import Enum


class AssetType(str, Enum):
    PORT = "PORT"
    SUBDOMAIN = "SUBDOMAIN"
    SERVICE = "SERVICE"
    HEADER = "HEADER"
    SSL_TLS = "SSL_TLS"
    ENDPOINT = "ENDPOINT"
