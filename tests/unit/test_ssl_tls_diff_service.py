from app.application.services.ssl_tls_diff_service import SslTlsDiffService
from app.domain.entities.ssl_tls_snapshot import SslTlsSnapshot
from app.domain.value_objects.change_type import ChangeType


def test_ssl_tls_expired():
    service = SslTlsDiffService()
    prev = [
        SslTlsSnapshot(
            domain="api.com", https_available=True, certificate_valid=True, days_to_expire=80
        )
    ]
    curr = [
        SslTlsSnapshot(
            domain="api.com", https_available=True, certificate_valid=False, days_to_expire=0
        )
    ]
    changes = service.compare(prev, curr)

    # Puede detectar expiración e issuer change si se mapea
    expired_change = [c for c in changes if c["details"]["check_name"] == "CERTIFICATE_EXPIRED"]
    assert len(expired_change) == 1
    assert expired_change[0]["change_type"] == ChangeType.WEAKENED


def test_ssl_tls_protocol_weakened():
    service = SslTlsDiffService()
    prev = [
        SslTlsSnapshot(
            domain="api.com",
            https_available=True,
            certificate_valid=True,
            days_to_expire=80,
            tls_1_0=False,
        )
    ]
    curr = [
        SslTlsSnapshot(
            domain="api.com",
            https_available=True,
            certificate_valid=True,
            days_to_expire=80,
            tls_1_0=True,
        )
    ]
    changes = service.compare(prev, curr)

    tls_change = [c for c in changes if c["details"]["check_name"] == "TLS_1_0_ENABLED"]
    assert len(tls_change) == 1
    assert tls_change[0]["change_type"] == ChangeType.WEAKENED
