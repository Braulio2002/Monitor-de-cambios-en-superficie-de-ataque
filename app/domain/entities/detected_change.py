from dataclasses import dataclass

from app.domain.value_objects.asset_type import AssetType
from app.domain.value_objects.change_type import ChangeType
from app.domain.value_objects.risk_level import RiskLevel
from app.domain.value_objects.severity_level import SeverityLevel


@dataclass
class DetectedChange:
    change_id: str
    asset_type: AssetType
    change_type: ChangeType
    asset_identifier: str
    previous_value: str
    current_value: str
    severity: SeverityLevel
    risk_score: float
    risk_level: RiskLevel
    description: str
    impact: str
    recommendation: str
    detected_at: str
