from dataclasses import dataclass
from math import isfinite

@dataclass(frozen=True)
class Settings:
    k: float = 5.0
    max_file_bytes: int = 64 * 1024 * 1024
    max_strings: int = 30000
    disabled_rules: tuple[str, ...] = ()
    score_model: str = "grouped"

    def __post_init__(self):
        if self.score_model not in ("grouped", "legacy"):
            raise ValueError("score_model must be grouped or legacy")
        if not isfinite(self.k) or not 0.1 <= self.k <= 20:
            raise ValueError("k must be finite and between 0.1 and 20")
        if not 1 <= self.max_file_bytes <= 512 * 1024 * 1024:
            raise ValueError("max_file_bytes must be between 1 and 512 MiB")
        if not 1 <= self.max_strings <= 100000:
            raise ValueError("max_strings must be between 1 and 100000")
