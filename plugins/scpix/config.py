from dataclasses import dataclass
from math import isfinite


@dataclass(frozen=True)
class Settings:
    """Configurações locais; não há arquivo TOML ou inicialização de rede."""
    k: float = 4.0
    max_payload_bytes: int = 8192
    max_payload_chars: int = 4096
    disabled_rules: tuple[str, ...] = ()
    score_model: str = "grouped"

    def __post_init__(self):
        if type(self.k) not in (int, float) or not isfinite(self.k) or not 0.1 <= self.k <= 20:
            raise ValueError("k deve estar entre 0.1 e 20")
        if type(self.max_payload_bytes) is not int or not 128 <= self.max_payload_bytes <= 65536:
            raise ValueError("max_payload_bytes deve estar entre 128 e 65536")
        if type(self.max_payload_chars) is not int or not 128 <= self.max_payload_chars <= 8192:
            raise ValueError("max_payload_chars deve estar entre 128 e 8192")
        if self.score_model != "grouped":
            raise ValueError("score_model deve ser grouped")
        if not isinstance(self.disabled_rules, (tuple, list)) or any(not isinstance(name, str) for name in self.disabled_rules):
            raise ValueError("disabled_rules deve conter apenas nomes de regras")
