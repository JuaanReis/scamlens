"""Heurística high_tile_entropy_dispersion: mede tile_entropy_std; sinal experimental não calibrado."""
from plugins.scimg.models.result_base import ResultBase
from ..registry import register
from .._metric_rule import evaluate_metric

@register(name='high_tile_entropy_dispersion', category='texture', severity="low", weight=1.0,
          tags=["image", 'texture', "experimental", 'tile_entropy'], group='texture')
def high_tile_entropy_dispersion(features: dict, threshold: float = 0.43, span: float = 0.32) -> ResultBase:
    return evaluate_metric(features, key='tile_entropy_std', direction='high',
                           threshold=threshold, span=span)
