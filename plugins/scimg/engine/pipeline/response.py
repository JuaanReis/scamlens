from plugins.scimg import __version__
from time import monotonic

def build_response(ctx, total, score_model, k, average):
    provenance = [h for h in ctx.heuristics if h["category"] == "provenance"]
    return {
        "status": "ok",
        "engine": {"name": "scimg", "version": __version__},
        "meta": {"image_name": ctx.image_name, "sha256": ctx.image_hash,
                 "size_bytes": ctx.image_size, "timestamp": ctx.timestamp.isoformat(),
                 "scan_time_s": round(monotonic() - ctx.start, 4),
                 "width": ctx.metadata["width"], "height": ctx.metadata["height"],
                 "format": ctx.metadata["format"]},
        "result": {"score": round(ctx.score, 2), "risk_level": ctx.risk,
                   "verdict": ctx.classification,
                   "note": "Pontuação heurística experimental, não probabilidade de geração por IA"},
        "stats": {"rules_total": total, "rules_evaluated": len(ctx.results),
                  "rules_skipped": len(ctx.skipped),
                  "rules_triggered": len(ctx.heuristics),
                  "trigger_rate": round(len(ctx.heuristics) / total, 3) if total else 0},
        "scoring": {"model": score_model, "k": k, "weighted_average": round(average, 5),
                    "calibration": "unvalidated"},
        "provenance": {"unverified_metadata_markers": [h["name"] for h in provenance],
                       "cryptographic_validation": False},
        "heuristics": ctx.heuristics,
        "skipped_rules": ctx.skipped,
        "ai_model": {"status": "not_implemented", "probability": None}
    }
