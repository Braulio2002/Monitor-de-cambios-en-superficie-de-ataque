from app.application.services.risk_score_calculator_service import RiskScoreCalculatorService
from app.domain.value_objects.asset_type import AssetType
from app.domain.value_objects.change_type import ChangeType
from app.domain.value_objects.risk_level import RiskLevel


def test_risk_score_db():
    calc = RiskScoreCalculatorService()

    rc_db = {
        "asset_type": AssetType.PORT,
        "change_type": ChangeType.ADDED,
        "details": {"port": 3306, "current_service": "mysql"},
    }
    score = calc.calculate_score(rc_db)
    assert score == 95.0
    assert calc.map_score_to_level(score) == RiskLevel.CRITICAL


def test_risk_score_removed():
    calc = RiskScoreCalculatorService()

    rc_closed = {
        "asset_type": AssetType.PORT,
        "change_type": ChangeType.REMOVED,
        "details": {"port": 22},
    }
    score = calc.calculate_score(rc_closed)
    assert score == 0.0
    assert calc.map_score_to_level(score) == RiskLevel.LOW
