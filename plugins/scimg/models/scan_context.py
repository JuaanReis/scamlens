from dataclasses import dataclass, field
from pathlib import Path

@dataclass
class ScanContext:
    image_name: str = ""
    image_data: Path | bytes = b""
    image_hash: str = ""
    image_size: int = 0
    content_bytes: bytes = b""
    source: Path | bytes | None = None
    file_hint: str | None = None
    metadata: dict = field(default_factory=dict)
