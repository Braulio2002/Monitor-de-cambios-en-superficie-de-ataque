SENSITIVE_PORTS = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    110: "POP3",
    139: "NetBIOS",
    143: "IMAP",
    445: "SMB",
    1433: "MSSQL",
    2049: "NFS",
    2375: "Docker API",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    5672: "RabbitMQ",
    5900: "VNC",
    6379: "Redis",
    8080: "HTTP-Alt / Jenkins",
    9000: "SonarQube",
    9200: "Elasticsearch",
    27017: "MongoDB",
}

SENSITIVE_SUBDOMAINS = [
    "admin",
    "panel",
    "dev",
    "qa",
    "staging",
    "test",
    "beta",
    "internal",
    "intranet",
    "vpn",
    "backup",
    "db",
    "database",
    "redis",
    "grafana",
    "kibana",
    "prometheus",
    "sonar",
    "jenkins",
    "gitlab",
    "ci",
    "cd",
]

SENSITIVE_SERVICES = [
    "ssh",
    "rdp",
    "ftp",
    "telnet",
    "smb",
    "mysql",
    "postgresql",
    "redis",
    "mongodb",
    "elasticsearch",
    "docker api",
    "jenkins",
    "gitlab",
    "grafana",
    "kibana",
    "prometheus",
    "rabbitmq",
    "sonarqube",
]

SECURITY_HEADERS = [
    "Content-Security-Policy",
    "Strict-Transport-Security",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Referrer-Policy",
    "Permissions-Policy",
    "Cache-Control",
    "Set-Cookie",
]

DEFAULT_RECOMMENDATIONS = {
    "PORT_OPEN_SENSITIVE": (
        "Cierre este puerto inmediatamente en el firewall o restrinja el acceso "
        "únicamente a IPs de administración autorizadas a través de una VPN corporativa."
    ),
    "PORT_OPEN_WEB": (
        "Asegúrese de que el servidor web esté actualizado, tenga un certificado SSL/TLS válido, "
        "cabeceras de seguridad activadas y no exponga errores ni banners detallados."
    ),
    "PORT_OPEN_GENERIC": (
        "Revise si este puerto es requerido para fines comerciales. "
        "En caso negativo, deshabilite el servicio y cierre el puerto."
    ),
    "SUBDOMAIN_SENSITIVE_NEW": (
        "Se ha expuesto un subdominio sensible. Valide que esté protegido detrás de un Gateway "
        "con Web Application Firewall (WAF) y autenticación robusta."
    ),
    "SUBDOMAIN_IP_CHANGE": (
        "El subdominio ha cambiado de IP. Verifique si el cambio fue autorizado y que no apunte "
        "a IPs huérfanas de nubes públicas para mitigar ataques de Subdomain Takeover."
    ),
    "SERVICE_SENSITIVE_NEW": (
        "Se ha detectado un servicio crítico expuesto. Aplique parches de seguridad, "
        "deshabilite autenticación básica y restrinja el acceso a nivel de red."
    ),
    "HEADER_REMOVED": (
        "La cabecera de seguridad fue removida. Vuelva a configurarla en el servidor web o CDN "
        "para mitigar vulnerabilidades como Clickjacking (X-Frame-Options) o XSS."
    ),
    "HEADER_WEAKENED": (
        "La directiva de la cabecera se ha debilitado. Revise las políticas de CSP, HSTS o "
        "Set-Cookie para asegurar que sigan las mejores prácticas del estándar OWASP."
    ),
    "SSL_TLS_EXPIRED": (
        "El certificado SSL/TLS ha expirado. Renueve e instale un certificado válido "
        "inmediatamente para evitar la interrupción del servicio y advertencias de seguridad."
    ),
    "SSL_TLS_EXPIRE_SOON": (
        "El certificado SSL/TLS vencerá próximamente. Planifique la renovación automatizada "
        "mediante Let's Encrypt o su entidad certificadora autorizada."
    ),
    "SSL_TLS_WEAK_PROTOCOL": (
        "Deshabilite los protocolos obsoletos TLS 1.0 y TLS 1.1 en el servidor. "
        "Configure únicamente TLS 1.2 y TLS 1.3 con Cipher Suites seguros."
    ),
    "ENDPOINT_AUTH_REMOVED": (
        "CRÍTICO: Un endpoint sensible ya no requiere autenticación. "
        "Restablezca el control de acceso en la API para evitar fugas de información masivas."
    ),
    "DEFAULT": (
        "Revise la configuración de seguridad del activo afectado para alinearlo "
        "con los estándares de hardening corporativos."
    ),
}
