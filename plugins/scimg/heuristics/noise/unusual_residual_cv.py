"""Heurística unusual_residual_cv: mede residual_cv; sinal experimental não calibrado."""
from plugins.scimg.models.result_base import ResultBase
from ..registry import register
from .._metric_rule import evaluate_metric

@register(name='unusual_residual_cv', category='noise', severity="low", weight=1.0,
          tags=["image", 'noise', "experimental", 'residual_dispersion'], group='noise')
def unusual_residual_cv(features: dict, threshold: float = 0.5, span: float = 0.35) -> ResultBase:
    return evaluate_metric(features, key='residual_cv', direction='high',
                           threshold=threshold, span=span)
