from dataclasses import dataclass, field

@dataclass
class ScanResult:
    name: str
    value: float
    weight: float
    category: str
    severity: str
    group: str
    details: dict = field(default_factory=dict)
