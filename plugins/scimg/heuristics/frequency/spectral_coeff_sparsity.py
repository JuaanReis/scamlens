"""Heurística spectral_coeff_sparsity: mede freq_sparsity; sinal experimental não calibrado."""
from plugins.scimg.models.result_base import ResultBase
from ..registry import register
from .._metric_rule import evaluate_metric

@register(name='spectral_coeff_sparsity', category='frequency', severity="low", weight=1.0,
          tags=["image", 'frequency', "experimental", 'spectral_sparse'], group='frequency')
def spectral_coeff_sparsity(features: dict, threshold: float = 0.88, span: float = 0.11) -> ResultBase:
    return evaluate_metric(features, key='freq_sparsity', direction='high',
                           threshold=threshold, span=span)
