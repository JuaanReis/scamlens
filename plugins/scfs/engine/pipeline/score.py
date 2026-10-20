from ...scoring.sigmoid import sigmoid
from ...scoring.weighted_average import weighted_average
from ...scoring.evidence import grouped_score
from ..analysis.classification import classify

def calculate_score(ctx, k, model="grouped"):
    if model == "legacy":
        scores=[r['score'] for r in ctx.heuristics]
        weights=[r['weight'] for r in ctx.heuristics]
        ctx.raw_score=weighted_average(scores,weights)
        ctx.score=sigmoid(scores,weights,k)
        ctx.scoring=dict(method="weighted_average_sigmoid", model="legacy")
        
    else:
        ctx.raw_score,ctx.score,ctx.scoring=grouped_score(ctx.heuristics,k)
        ctx.scoring['model']="grouped"
    ctx.classification,ctx.risk=classify(ctx.score)
