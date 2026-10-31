"""Heurística repeated_small_tiles: mede tile_repetition; sinal experimental não calibrado."""
from plugins.scimg.models.result_base import ResultBase
from ..registry import register
from .._metric_rule import evaluate_metric

@register(name='repeated_small_tiles', category='geometry', severity="low", weight=1.0,
          tags=["image", 'geometry', "experimental", 'tile_repeat'], group='geometry')
def repeated_small_tiles(features: dict, threshold: float = 0.18, span: float = 0.5) -> ResultBase:
    return evaluate_metric(features, key='tile_repetition', direction='high',
                           threshold=threshold, span=span)
