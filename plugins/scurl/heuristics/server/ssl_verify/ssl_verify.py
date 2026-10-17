from datetime import datetime, timezone
from plugins.scurl.models.result_base import ResultBase
from ...registry import register


@register(
    name="ssl_score",
    category="server",
    severity="medium",
    weight=2.0,
    tags=["server", "ssl"],
)
def ssl_score(structure):
    if structure.get("scheme") == "http":
        return ResultBase(0, None, {"error": "HTTP target; no TLS"})
    data = structure.get("ssl")
    if not data or any(
        data.get(k) for k in ("timeout", "unknown", "connection_error", "dns_error")
    ):
        return ResultBase(None, None, {"error": "TLS metadata unavailable"})
    if data.get("invalid_cert"):
        return ResultBase(0.8, 0.8, {"invalid_cert": True})
    if data.get("hostname_valid") is False:
        return ResultBase(0.8, 0.8, {"hostname_mismatch": True})
    try:
        expired = datetime.fromisoformat(data["valid_until"]).replace(
            tzinfo=timezone.utc
        ) < datetime.now(timezone.utc)
    except (KeyError, ValueError):
        return ResultBase(None, None, {"error": "TLS expiry unavailable"})
    score = 0.8 if expired else 0.6 if data.get("self_signed") else 0
    return ResultBase(
        score,
        score,
        dict(
            expired=expired,
            self_signed=data.get("self_signed"),
            chain_verified=data.get("chain_verified"),
            recent_issuance_not_scored=True,
        ),
    )
