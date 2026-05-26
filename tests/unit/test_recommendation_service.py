from app.application.services.recommendation_service import RecommendationService
from app.domain.value_objects.asset_type import AssetType
from app.domain.value_objects.change_type import ChangeType
from app.shared.constants import DEFAULT_RECOMMENDATIONS


def test_recommendation_sensitive_port():
    service = RecommendationService()
    rc_ssh = {
        "asset_type": AssetType.PORT,
        "change_type": ChangeType.ADDED,
        "details": {"port": 22},
    }
    reco = service.get_recommendation(rc_ssh)
    assert reco == DEFAULT_RECOMMENDATIONS["PORT_OPEN_SENSITIVE"]
