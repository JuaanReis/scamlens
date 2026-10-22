from time import perf_counter


def _mask_key(key):
    if not key:
        return None
    return "***" + key[-4:] if len(key) > 4 else "***"


def build_response(ctx, settings):
    from ... import __version__
    data = ctx.target.structure
    evaluated = sum(r["status"] == "ok" for r in ctx.heuristics)
    failed = sum(r["status"] == "error" for r in ctx.heuristics)
    status = "inconclusive" if not evaluated else "partial" if ctx.warnings or failed else "ok"
    return {
        "status": status,
        "engine": {"name": "scpix", "version": __version__},
        "meta": {
            "scan_id": ctx.meta.scan_id, "timestamp": ctx.meta.timestamp,
            "scan_time_s": round(perf_counter() - ctx.meta.start, 4),
            "payload_hash": ctx.target.payload_hash, "threads": 1,
        },
        "result": {"score": ctx.score, "risk_level": ctx.risk,
                   "verdict": ctx.classification},
        "stats": {
            "rules_total": len(ctx.heuristics),
            "rules_evaluated": evaluated,
            "rules_triggered": sum(r["triggered"] for r in ctx.heuristics),
            "rules_failed": failed,
            "rules_disabled": sum(r["status"] == "disabled" for r in ctx.heuristics),
            "rules_unavailable": sum(r["status"] == "unavailable" for r in ctx.heuristics),
        },
        "scoring": ctx.scoring,
        "heuristics": ctx.heuristics,
        "warnings": ctx.warnings,
        "insight": "Score reflete anomalias técnicas/contextuais, não probabilidade de fraude. Valide recebedor e dados no aplicativo bancário antes de pagar.",
    }, {
        "identity": {"name": ctx.target.name, "size_bytes": ctx.target.size_bytes,
                     "sha256": ctx.target.payload_hash},
        "pix": {
            "type": data["type"], "payload_format": data["fields"].get("00"),
            "merchant_category": data["fields"].get("52"),
            "currency": data["fields"].get("53"), "country": data["fields"].get("58"),
            "merchant_name": data["merchant_name"], "merchant_city": data["merchant_city"],
            "amount": data["amount"], "txid": data["txid"],
            "key_kind": ctx.target.features.get("key_kind"),
            "key_masked": _mask_key(data["key"]),
            "crc_valid": data["crc_valid"],
            "location_hosts": [loc["host"] for loc in data["locations"]],
            "location_count": len(data["locations"]),
            "recurrence": data["recurring"],
        },
        "verification": {
            "recipient_registration_checked": False,
            "psp_authorization_checked": False,
            "remote_charge_resolved": False,
        },
    }


def build_error_response(ctx, code, message):
    from ... import __version__
    return {
        "status": "error", "engine": {"name": "scpix", "version": __version__},
        "meta": {"scan_id": ctx.meta.scan_id, "timestamp": ctx.meta.timestamp},
        "result": {"score": None, "risk_level": "unknown", "verdict": "unknown"},
        "error": {"code": code, "message": message},
    }, {}
