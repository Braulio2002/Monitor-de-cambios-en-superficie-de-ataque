from app.application.services.severity_classifier_service import SeverityClassifierService
from app.domain.value_objects.asset_type import AssetType
from app.domain.value_objects.change_type import ChangeType
from app.domain.value_objects.severity_level import SeverityLevel


def test_severity_critical_port():
    classifier = SeverityClassifierService()

    # Exposición de MySQL
    rc_db = {
        "asset_type": AssetType.PORT,
        "change_type": ChangeType.ADDED,
        "details": {"port": 3306, "current_service": "mysql"},
    }
    assert classifier.classify(rc_db) == SeverityLevel.CRITICAL


def test_severity_high_port():
    classifier = SeverityClassifierService()

    # Exposición de SSH
    rc_ssh = {
        "asset_type": AssetType.PORT,
        "change_type": ChangeType.ADDED,
        "details": {"port": 22, "current_service": "ssh"},
    }
    assert classifier.classify(rc_ssh) == SeverityLevel.HIGH


def test_severity_medium_port():
    classifier = SeverityClassifierService()

    # Exposición de Web
    rc_web = {
        "asset_type": AssetType.PORT,
        "change_type": ChangeType.ADDED,
        "details": {"port": 443, "current_service": "https"},
    }
    assert classifier.classify(rc_web) == SeverityLevel.MEDIUM
