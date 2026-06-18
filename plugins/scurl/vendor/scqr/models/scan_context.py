from pathlib import Path
from dataclasses import dataclass, field
from time import time

@dataclass
class ScanContext:
    src: bytes | str | Path
    src_resolved: bytes | None = None
    decoded: str | None = None
    points: object = None
    qr_type: str | None = None
    start: float = field(default_factory=time)
    heuristics: list[dict] = field(default_factory=list)