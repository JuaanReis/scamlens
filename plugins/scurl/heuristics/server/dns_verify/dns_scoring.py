from math import exp, log
from plugins.scurl.models.sub_score import SubScore
import dns.resolver
import statistics

def dns_mx(has_mx: bool) -> SubScore:
    """
    Avalia risco baseado na ausência de registro MX.
    normalized_score ∈ {0, 1}
    """
    if has_mx is None:
        return SubScore(
            normalized=None,
            weight=1.0
        )

    normalized = 0.0 if has_mx else 1.0

    return SubScore(
        normalized=normalized if normalized != 0.0 else None,
        weight=1.0
    )

def get_stable_ttl(hostname: str, samples: int = 1) -> int:
    ttls = []
    for _ in range(samples):
        try:
            answers = dns.resolver.resolve(hostname, "A")
            ttls.append(answers.rrset.ttl)
        except Exception:
            continue
    return int(statistics.median(ttls)) if ttls else None

def dns_ttl(ttl: int, has_mx: bool = None) -> SubScore:
    if ttl is None:
        return SubScore(
            normalized=0.0,
            weight=0.8
        )

    if ttl < 60:
        raw = 1.0
        context = "ttl_very_low"
    elif ttl < 300:
        raw = 0.5
        context = "ttl_low"
    elif ttl <= 3600:
        raw = 0.0   
        context = "ttl_normal"
    else:
        raw = 0.1  
        context = "ttl_high"

    if has_mx is True and ttl < 300:
        normalized = raw * 0.4
        context += "_mx_attenuated"

    elif has_mx is False and ttl < 300:
        normalized = min(raw * 1.2, 1.0)
        context += "_no_mx_amplified"

    else:
        normalized = raw

    return SubScore(
        normalized=round(normalized, 4) if normalized > 0.05 else None,
        weight=0.8
    )


def dns_a(ips: list, ttl: int = None) -> SubScore:
    """
    Avalia risco baseado na quantidade de IPs associados ao domínio.
    Cruzamento: muitos IPs + TTL baixo indica rotação ativa de IP (bulletproof hosting).
    normalized_score ∈ [0, 1]
    """
    if not ips:
        return SubScore(
            normalized=1.0,
            weight=0.9
        )

    count = len(ips)

    if count <= 8:
        base_normalized = None
        context = "ip_count_normal"
    else:
        base_normalized = min(log(count - 1) / log(9), 1.0)
        context = "ip_count_high"


    if base_normalized is not None and ttl is not None and ttl < 120:
        normalized = min(base_normalized * 1.3, 1.0)
        context = "ip_rotation_suspected"
    else:
        normalized = base_normalized

    return SubScore(
        normalized=round(normalized, 4) if normalized and normalized > 0.05 else None,
        weight=0.9
    )

def dns_spf(txt_records: list, has_mx: bool = None) -> SubScore:
    if not txt_records:
        if has_mx is True:
            normalized = 1.0
            context = "no_txt_but_has_mx"

        else:
            normalized = None
            context = "no_txt_no_mx_neutral"

        return SubScore(
            normalized=normalized,
            weight=0.7
        )

    has_spf = any("v=spf1" in r.lower() for r in txt_records)

    if not has_spf and has_mx is True:
        normalized = 1.0
        context = "no_spf_with_mx"
    elif not has_spf and has_mx is False:
        normalized = None
        context = "no_spf_no_mx_neutral"
    else:
        normalized = None
        context = "spf_ok"

    return SubScore(
        normalized=normalized,
        weight=0.7
    )

def dns_dkim(txt_records: list, has_mx: bool = None, dkim_found: bool = False) -> SubScore:
    has_dkim = dkim_found or any("v=dkim1" in r.lower() for r in txt_records)

    if not has_dkim and has_mx is True:
        normalized = 0.1
        context = "no_dkim_with_mx"
    elif not has_dkim and has_mx is False:
        normalized = None
        context = "no_dkim_no_mx_neutral"
    else:
        normalized = None
        context = "dkim_ok"

    return SubScore(
        normalized=normalized,
        weight=0.6
    )

COMMON_SELECTORS = ["google", "default", "mail", "dkim", "k1", "s1", "s2"]

def check_dkim_selectors(hostname: str) -> bool:
    """Tenta seletores DKIM comuns antes de declarar ausência."""
    for selector in COMMON_SELECTORS:
        try:
            dns.resolver.resolve(f"{selector}._domainkey.{hostname}", "TXT")
            return True
        except Exception:
            continue
    return False