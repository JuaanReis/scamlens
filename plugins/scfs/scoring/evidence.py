"""Transparent fixed-budget evidence aggregation; not a probability model."""
from .weighted_average import weighted_average
from .sigmoid import sigmoid

MODEL_VERSION = "grouped-top3-v1"
SLOT_WEIGHTS = (3.0, 2.0, 1.0)

def grouped_score(heuristics, k):
    evaluated = [r for r in heuristics if r['score'] is not None]
    if not evaluated:
        return None, None, dict(method=MODEL_VERSION, groups=[], selected_groups=[], slot_weights=list(SLOT_WEIGHTS))
    by_group={}
    for rule in evaluated:
        # Rule weights express evidence reliability on a 0..3 reference scale.
        # Higher weights (external reputation=4) saturate, never exceed 1.
        strength=rule['score'] * min(rule['weight']/3.0,1.0)
        group=rule.get('group',rule['category'])
        previous=by_group.get(group)
        if previous is None or strength > previous['strength']:
            by_group[group]=dict(group=group, strength=strength, rule=rule['name'])
    groups=sorted(by_group.values(),key=lambda row:(-row['strength'],row['group']))
    selected=[row for row in groups if row['strength']>0][:3]
    values=[row['strength'] for row in selected]+[0.0]*(3-len(selected))
    return weighted_average(values,SLOT_WEIGHTS), sigmoid(values,SLOT_WEIGHTS,k), dict(
        method=MODEL_VERSION, groups=groups, selected_groups=selected, slot_scores=values,
        slot_weights=list(SLOT_WEIGHTS), rule_weight_reference=3.0)
