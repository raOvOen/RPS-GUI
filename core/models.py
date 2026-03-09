from dataclasses import dataclass, field
from enum import Enum
from typing import List, Optional


class Severity(Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class Finding:
    description: str
    severity: Severity
    penalty: float
    detail: Optional[str] = None


@dataclass
class ModuleResult:
    module_name: str
    score: float
    findings: List[Finding] = field(default_factory=list)
    recommendations: List[str] = field(default_factory=list)


class StrengthLevel(Enum):
    VERY_WEAK = "Очень слабый"
    WEAK = "Слабый"
    MEDIUM = "Средний"
    STRONG = "Надёжный"
    VERY_STRONG = "Очень надёжный"


@dataclass
class AnalysisResult:
    overall_score: float
    strength_level: StrengthLevel
    module_results: List[ModuleResult]
    top_recommendations: List[str]
