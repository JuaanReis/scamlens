import dns.resolver
from time import perf_counter

def _resolve(hostname, record_type, timeout=2):
    try:
        answer = dns.resolver.resolve(hostname, record_type, lifetime=timeout)
        return [r.to_text() for r in answer], answer.rrset.ttl, None
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
        return [], None, None
    except Exception as exc:
        return [], None, type(exc).__name__

def get_dns_info(hostname, timeout=2, include_mail=False):
    hostname = hostname.strip().lower().rstrip(".")
    data = {}
    errors = {}
    ttl = None
    deadline = perf_counter() + timeout
    for kind in ("A", "AAAA", "NS", "CNAME"):
        remaining = deadline - perf_counter()
        records, record_ttl, error = (
            _resolve(hostname, kind, max(0.05, remaining))
            if remaining > 0
            else ([], None, "budget_exhausted")
        )

        data[kind.lower()] = [x.rstrip(".") for x in records]
        if kind == "A":
            ttl = record_ttl
        if error:
            errors[kind] = error
            
    data.update(
        mx=[],
        txt=[],
        spf=None,
        dmarc=None,
        dkim=None,
        ttl=ttl,
        has_mx=None,
        errors=errors,
    )

    if include_mail:
        mx, _, error = _resolve(hostname, "MX", timeout)
        data["mx"] = [
            dict(priority=int(x.split()[0]), host=x.split()[-1].rstrip("."))
            for x in mx
            if len(x.split()) == 2
        ]
        txt, _, _ = _resolve(hostname, "TXT", timeout)
        data.update(
            txt=txt, has_mx=bool(mx), spf=any("v=spf1" in x.lower() for x in txt)
        )
    return data
