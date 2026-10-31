"""Heurística weak_tile_entropy: mede tile_entropy_mean; sinal experimental não calibrado."""
from plugins.scimg.models.result_base import ResultBase
from ..registry import register
from .._metric_rule import evaluate_metric

@register(name='weak_tile_entropy', category='texture', severity="low", weight=1.0,
          tags=["image", 'texture', "experimental", 'tile_entropy'], group='texture')
def weak_tile_entropy(features: dict, threshold: float = 0.23, span: float = 0.2) -> ResultBase:
    return evaluate_metric(features, key='tile_entropy_mean', direction='low',
                           threshold=threshold, span=span)
