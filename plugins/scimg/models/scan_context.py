from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from time import monotonic

@dataclass
class ImageData:
    """Equivalente ao TargetData do scurl para uma imagem."""
    source: Path | bytes | None = None
    structure: dict = field(default_factory=dict)
    features: dict = field(default_factory=dict)

@dataclass
class ScanMeta:
    """Equivalente ao ScanMeta do scurl."""
    scan_id: str = ""
    image_hash: str = ""
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    start: float = field(default_factory=monotonic)
    threads: int = 1

@dataclass
class ScanContext:
    target: ImageData = field(default_factory=ImageData)
    meta: ScanMeta = field(default_factory=ScanMeta)
    image_name: str = ""
    image_data: Path | bytes = b""
    image_hash: str = ""
    image_size: int = 0
    content_bytes: bytes = b""
    source: Path | bytes | None = None
    file_hint: str | None = None
    metadata: dict = field(default_factory=dict)
    features: dict = field(default_factory=dict)
    results: list = field(default_factory=list)
    results_map: dict = field(default_factory=dict)
    scan_id: str = ""
    scores: list = field(default_factory=list)
    weights: list = field(default_factory=list)
    heuristics: list = field(default_factory=list)
    skipped: list = field(default_factory=list)
    score: float | None = None
    risk: str = "unknown"
    classification: str = "inconclusive"
    start: float = field(default_factory=monotonic)
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
