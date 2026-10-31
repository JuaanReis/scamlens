"""Contrato futuro: mantém a IA fora da média heurística até haver validação."""
from dataclasses import dataclass
from typing import Protocol

@dataclass(frozen=True)
class ModelResult:
    model_id: str
    raw_score: float
    calibrated_probability: float | None = None
    calibration_id: str | None = None

class VisualModel(Protocol):
    def predict(self, image_bytes: bytes) -> ModelResult:
        """Prediz a partir de uma imagem; a implementação ficará para versão futura."""
        ...
