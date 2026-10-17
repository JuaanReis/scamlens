from time import perf_counter

def build_response(ctx, k):
    from ... import __version__
    evaluated = sum(r['status'] == 'ok' for r in ctx.heuristics)
    failed = sum(r['status'] == 'error' for r in ctx.heuristics)
    status = "inconclusive" if not evaluated else "partial" if ctx.warnings or failed else "ok"

    result = dict(score=round(ctx.score, 2) if ctx.score is not None else None,
                  risk_level=ctx.risk, verdict=ctx.classification)
    
    scan = dict(status=status, engine=dict(name="scfs", version=__version__),
        meta=dict(scan_id=ctx.meta.scan_id, timestamp=ctx.meta.timestamp,
                  scan_time_s=round(perf_counter()-ctx.meta.start, 4), file_hash=ctx.target.sha256, threads=1),
        result=result,
        stats=dict(rules_total=len(ctx.heuristics), rules_evaluated=evaluated,
                   rules_triggered=sum(r['triggered'] for r in ctx.heuristics), rules_failed=failed,
                   rules_disabled=sum(r['status']=='disabled' for r in ctx.heuristics),
                   rules_unavailable=sum(r['status']=='unavailable' for r in ctx.heuristics)),
        scoring=dict(ctx.scoring, k=k, raw_score=ctx.raw_score,
                     calibrated=False, calibration_scope="engineering_controls_only", score_is_probability=False),
        heuristics=ctx.heuristics, warnings=ctx.warnings,
        insight="Análise estática heurística: ausência de indicadores não garante segurança.")
    
    structure = {k:v for k,v in ctx.target.structure.items() if k != 'text'}
    target = dict(identity=dict(name=ctx.target.name, size_bytes=len(ctx.target.data), sha256=ctx.target.sha256),
                  executable=structure, content=dict(strings_count=len(ctx.target.strings),
                  strings_truncated=ctx.target.strings_truncated), reputation=ctx.target.reputation)
    
    return scan, target

def build_error_response(ctx, code, message):
    from ... import __version__
    return dict(status="error", engine=dict(name="scfs", version=__version__),
                meta=dict(scan_id=ctx.meta.scan_id, timestamp=ctx.meta.timestamp),
                result=dict(score=None, risk_level="unknown", verdict="unknown"),
                error=dict(code=code, message=message)), {}
