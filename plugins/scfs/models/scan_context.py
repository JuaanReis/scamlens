from dataclasses import dataclass
from pathlib import Path
from typing import Optional

@dataclass
class ScanContext:
    source: Path | bytes
    file_hint: Optional[str]