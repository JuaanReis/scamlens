from dataclasses import dataclass
from pathlib import Path

@dataclass
class ScanContext:
    image_name: str
    image_data: Path | bytes
    image_hash: str
    image_size: int
    content_bytes: bytes