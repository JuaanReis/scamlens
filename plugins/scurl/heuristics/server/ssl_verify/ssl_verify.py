from datetime import datetime, timezone
from plugins.scurl.models.result_base import ResultBase
from plugins.scurl.scoring.sigmoid import sigmoid
from .certificate_scoring import (
    f_age, f_validity, f_san, f_wildcard,
    f_issuer, f_mismatch, f_self_signed,
    f_expiry, f_org, f_sig_algorithm,
)
from providers.ssl.info_ssl import get_ssl_cert
from ...registry import register


@register(name="ssl_score", category="server", severity="high", weight=3.5, tags=["server", "ssl", "certificate"])
def ssl_score(structure: dict) -> ResultBase:
    """
    Avalia a segurança do certificado SSL/TLS do servidor.

    Fatores considerados:
        - Idade do certificado desde a emissão (f_age)
        - Período de validade total (f_validity)
        - Proximidade do vencimento (f_expiry)
        - Número de SANs (f_san)
        - Presença de wildcard (f_wildcard)
        - Confiabilidade da CA emissora (f_issuer)
        - Correspondência com o hostname (f_mismatch)
        - Autoassinado (f_self_signed)
        - Presença de campo Organization (f_org)
        - Algoritmo de assinatura (f_sig_algorithm)

    Funções que retornam None (falha de parse) são excluídas do cálculo —
    sem penalização por dados indisponíveis.

    Score final via sigmoid ponderada (k=5), normalizado em [0, 1].
    Valores mais altos indicam maior risco.
    """
    ssl_data = get_ssl_cert(structure)

    if ssl_data.get("connection_refused", False):
        return ResultBase(
            value=None,
            normalized=0.65,
            details={"error": "Connection refused or SSL not supported"},
        )

    if ssl_data.get("timeout", False):
        return ResultBase(
            value=None,
            normalized=0.0,
            details={"error": "Connection timed out while retrieving SSL certificate"},
        )

    if ssl_data.get("invalid_cert", False):
        return ResultBase(
            value=None,
            normalized=0.9,
            details={"error": "Invalid SSL certificate"},
        )

    if ssl_data.get("unknown", False):
        return ResultBase(
            value=None,
            normalized=None,
            details={"error": "Unknown error while retrieving SSL certificate"},
        )

    try:
        issued = datetime.strptime(ssl_data["valid_from"], "%Y-%m-%d").replace(tzinfo=timezone.utc)
        expire = datetime.strptime(ssl_data["valid_until"], "%Y-%m-%d").replace(tzinfo=timezone.utc)
    except Exception:
        return ResultBase(
            value=None,
            normalized=None,
            details={"error": "Invalid SSL date format"},
        )

    now = datetime.now(timezone.utc)
    age_days = (now - issued).days
    validity_days = (expire - issued).days
    days_until_expiry = (expire - now).days

    issuer = ssl_data.get("issuer_detail", {}).get("commonName", "") or \
    ssl_data.get("issuer_detail", {}).get("organizationName", "")

    san = ssl_data.get("san", [])
    hostname_valid = ssl_data.get("hostname_valid", True)
    organization = ssl_data.get("organization", "")
    sig_algorithm = ssl_data.get("signature_algorithm", "")

    raw_scores = [
        (f_age(age_days),                              1.5),
        (f_validity(validity_days),                    1.0),
        (f_expiry(days_until_expiry),                  1.5),
        (f_san(len(san)),                              0.5),
        (f_wildcard(san),                              0.3),
        (f_issuer(issuer),                             1.0),
        (f_mismatch(not hostname_valid),               2.0),
        (f_self_signed(ssl_data.get("self_signed")),   2.0),
        (f_org(organization),                          0.5),
        (f_sig_algorithm(sig_algorithm),               1.0),
    ]

    valid = [(v, w) for v, w in raw_scores if v is not None]

    if not valid:
        return ResultBase(
            value=None,
            normalized=None,
            details={"error": "No valid SSL metrics available"},
        )

    values, weights = zip(*valid)
    f_score = sigmoid(list(values), list(weights), k=5) / 100

    return ResultBase(
        value=f_score,
        normalized=f_score,
        details={
            "age_days": age_days,
            "validity_days": validity_days,
            "days_until_expiry": days_until_expiry,
            "san_count": len(san),
            "issuer": issuer,
            "hostname_valid": hostname_valid,
            "self_signed": ssl_data.get("self_signed", False),
            "organization": organization or None,
            "sig_algorithm": sig_algorithm or None,
        },
    )