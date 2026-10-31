from dataclasses import dataclass

@dataclass
class ResultBase:
    value: float
    normalized: float | None = None
    details: dict | None = None
