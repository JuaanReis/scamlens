import dns.resolver

def _resolve(hostname: str, record_type: str) -> tuple[list, int | None]:
    try:
        answers = dns.resolver.resolve(hostname, record_type)
        records = [r.to_text() for r in answers]
        ttl = answers.rrset.ttl
        return records, ttl
    except Exception:
        return [], None

def _extract_spf(txt_records: list[str]) -> bool:
    return any(r.strip('"').startswith("v=spf1") for r in txt_records)

def _extract_dmarc(hostname: str) -> bool:
    records, _ = _resolve(f"_dmarc.{hostname}", "TXT")
    return any("v=DMARC1" in r for r in records)

def _extract_dkim(hostname: str, selector: str = "default") -> bool:
    records, _ = _resolve(f"{selector}._domainkey.{hostname}", "TXT")
    return any("v=DKIM1" in r for r in records)

def get_dns_info(hostname: str) -> dict:
    hostname = hostname.removeprefix("www.").strip().lower()

    a_records, ttl = _resolve(hostname, "A")
    aaaa_records, _ = _resolve(hostname, "AAAA")
    ns_records, _ = _resolve(hostname, "NS")
    cname_records, _ = _resolve(hostname, "CNAME")
    txt_records, _ = _resolve(hostname, "TXT")

    mx_raw, _ = _resolve(hostname, "MX")
    mx_records = []
    for entry in mx_raw:
        parts = entry.split()
        if len(parts) == 2:
            mx_records.append({"priority": int(parts[0]), "host": parts[1].rstrip(".")})
        else:
            mx_records.append({"priority": None, "host": entry})

    spf = _extract_spf(txt_records)
    dmarc = _extract_dmarc(hostname)
    dkim = _extract_dkim(hostname)

    return {
        "a": a_records,
        "aaaa": aaaa_records,
        "mx": mx_records,
        "ns": [r.rstrip(".") for r in ns_records],
        "cname": [r.rstrip(".") for r in cname_records],
        "txt": txt_records,
        "spf": spf,
        "dmarc": dmarc,
        "dkim": dkim,
        "ttl": ttl,
        "has_mx": len(mx_records) > 0,
    }