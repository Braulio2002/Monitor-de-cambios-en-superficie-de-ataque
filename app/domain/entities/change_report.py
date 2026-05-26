from dataclasses import dataclass, field
from typing import List

from app.domain.entities.detected_change import DetectedChange
from app.domain.value_objects.risk_level import RiskLevel


@dataclass
class ChangeReport:
    total_changes: int
    critical_changes: int
    high_changes: int
    medium_changes: int
    low_changes: int
    info_changes: int
    changes: List[DetectedChange] = field(default_factory=list)
    executive_summary: str = ""
    generated_at: str = ""
    riesgo_general: float = 0.0
    risk_level_general: RiskLevel = RiskLevel.LOW
