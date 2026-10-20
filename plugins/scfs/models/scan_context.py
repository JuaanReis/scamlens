from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from time import perf_counter
from typing import Optional
from uuid import uuid4


@dataclass
class TargetData:
    name: str = ""
    data: bytes = b""
    sha256: str = ""
    structure: dict = field(default_factory=dict)
    strings: list[str] = field(default_factory=list)
    strings_truncated: bool = False
    evidence_text: str = ""
    features: dict = field(default_factory=dict)
    reputation: dict | None = None


@dataclass
class ScanMeta:
    scan_id: str = field(default_factory=lambda: uuid4().hex)
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    start: float = field(default_factory=perf_counter)

@dataclass
class ScanContext:
    source: Path | bytes | str | None = None
    file_hint: Optional[str] = None
    target: TargetData = field(default_factory=TargetData)
    meta: ScanMeta = field(default_factory=ScanMeta)
    heuristics: list[dict] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    scoring: dict = field(default_factory=dict)
    raw_score: float | None = None
    score: float | None = None
    classification: str = "unknown"
    risk: str = "unknown"
