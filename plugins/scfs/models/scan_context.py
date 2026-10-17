from dataclasses import dataclass, field
from datetime import datetime, timezone
from time import perf_counter
from uuid import uuid4

@dataclass
class TargetData:
    name: str = ""
    data: bytes = field(default=b"", repr=False)
    sha256: str = ""
    structure: dict = field(default_factory=dict)
    strings: list[str] = field(default_factory=list)
    strings_truncated: bool = False
    reputation: dict | None = None
    evidence_text: str = ""
    features: dict = field(default_factory=dict)

@dataclass
class ScanMeta:
    scan_id: str = field(default_factory=lambda: uuid4().hex)
    start: float = field(default_factory=perf_counter)
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

@dataclass
class ScanContext:
    target: TargetData = field(default_factory=TargetData)
    meta: ScanMeta = field(default_factory=ScanMeta)
    heuristics: list[dict] = field(default_factory=list)
    score: float | None = None
    raw_score: float | None = None
    scoring: dict = field(default_factory=dict)
    classification: str = "unknown"
    risk: str = "unknown"
    warnings: list[str] = field(default_factory=list)
