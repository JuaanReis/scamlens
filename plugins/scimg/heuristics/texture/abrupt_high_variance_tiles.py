"""Heurística abrupt_high_variance_tiles: mede high_variance_tile_fraction; sinal experimental não calibrado."""
from plugins.scimg.models.result_base import ResultBase
from ..registry import register
from .._metric_rule import evaluate_metric

@register(name='abrupt_high_variance_tiles', category='texture', severity="low", weight=1.0,
          tags=["image", 'texture', "experimental", 'tile_variance'], group='texture')
def abrupt_high_variance_tiles(features: dict, threshold: float = 0.74, span: float = 0.23) -> ResultBase:
    return evaluate_metric(features, key='high_variance_tile_fraction', direction='high',
                           threshold=threshold, span=span)
