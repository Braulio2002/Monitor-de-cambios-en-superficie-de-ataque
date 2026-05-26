from pathlib import Path

from app.shared.constants import (
    SECURITY_HEADERS,
    SENSITIVE_PORTS,
    SENSITIVE_SERVICES,
    SENSITIVE_SUBDOMAINS,
)

# Directorios principales (raíz del repositorio)
BASE_DIR = Path(__file__).resolve().parents[2]

INPUT_DIR = BASE_DIR / "datos_entrada"
OUTPUT_DIR = BASE_DIR / "datos_salida"

PREVIOUS_SCAN_DIR = INPUT_DIR / "escaneo_anterior"
CURRENT_SCAN_DIR = INPUT_DIR / "escaneo_actual"

# Nombres de archivos estándar esperados
PORTS_FILE = "ports.json"
SUBDOMAINS_FILE = "subdomains.json"
SERVICES_FILE = "services.json"
HEADERS_FILE = "headers.json"
SSL_TLS_FILE = "ssl_tls.json"
ENDPOINTS_FILE = "endpoints.json"  # Opcional

# Configuración de Activos Sensibles
CONFIGURED_SENSITIVE_PORTS = SENSITIVE_PORTS
CONFIGURED_SENSITIVE_SERVICES = SENSITIVE_SERVICES
CONFIGURED_SENSITIVE_SUBDOMAINS = SENSITIVE_SUBDOMAINS
CONFIGURED_SECURITY_HEADERS = SECURITY_HEADERS

# Configuración de Scoring de Riesgo (Pesos base)
RISK_WEIGHTS = {
    # Puertos
    "PORT_OPEN_CRITICAL_DB": 95,
    "PORT_OPEN_DOCKER_API": 100,
    "PORT_OPEN_RDP": 85,
    "PORT_OPEN_SSH": 70,
    "PORT_OPEN_WEB": 40,
    "PORT_OPEN_GENERIC": 30,
    # Subdominios
    "SUBDOMAIN_NEW_SENSITIVE": 65,
    "SUBDOMAIN_NEW_GENERIC": 35,
    "SUBDOMAIN_IP_CHANGED": 50,
    # Servicios
    "SERVICE_NEW_SENSITIVE": 80,
    "SERVICE_VERSION_CHANGED_SENSITIVE": 55,
    "SERVICE_VERSION_CHANGED_GENERIC": 20,
    # Headers de seguridad
    "HEADER_REMOVED": 70,
    "HEADER_WEAKENED": 60,
    "HEADER_ADDED": 5,
    # SSL/TLS
    "SSL_TLS_EXPIRED": 95,
    "SSL_TLS_EXPIRE_SOON": 60,
    "SSL_TLS_WEAK_PROTOCOL": 75,
    "SSL_TLS_NEW_CERT": 10,
    # Endpoints
    "ENDPOINT_NEW_UNAUTH": 95,
    "ENDPOINT_NEW": 20,
    "ENDPOINT_REMOVED": 10,
    # Por defecto
    "DEFAULT": 10,
}
