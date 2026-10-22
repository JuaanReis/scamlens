from dataclasses import dataclass, field
from datetime import datetime, timezone
from hashlib import sha256
from time import perf_counter
from uuid import uuid4


@dataclass
class ScanMeta:
    scan_id: str = field(default_factory=lambda: uuid4().hex)
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    start: float = field(default_factory=perf_counter)


@dataclass
class TargetData:
    name: str = "pix"
    payload_hash: str = ""
    size_bytes: int = 0
    structure: dict = field(default_factory=dict)
    expectations: dict = field(default_factory=dict)
    features: dict = field(default_factory=dict)

    def set_payload(self, payload: str):
        data = payload.encode("utf-8")
        self.payload_hash = sha256(data).hexdigest()
        self.size_bytes = len(data)


@dataclass
class ScanContext:
    target: TargetData = field(default_factory=TargetData)
    meta: ScanMeta = field(default_factory=ScanMeta)
    heuristics: list[dict] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    scoring: dict = field(default_factory=dict)
    raw_score: float | None = None
    score: float | None = None
    risk: str = "unknown"
    classification: str = "unknown"
