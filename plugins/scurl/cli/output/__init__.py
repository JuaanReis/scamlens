_R   = "\033[31m"
_Y   = "\033[33m"
_G   = "\033[32m"
_C   = "\033[36m"
_DIM = "\033[2m"
_RST = "\033[0m"

_VERDICT_COLOR = {
    "dangerous":  _R,
    "suspicious": _Y,
    "safe":       _G,
    "very_low":   _G,
}

def _col(text: str, color: str) -> str:
    return f"{color}{text}{_RST}"

def _verdict_color(verdict: str) -> str:
    return _VERDICT_COLOR.get(verdict.lower(), "")

def _yn(val) -> str:
    if val is None:
        return "n/a"
    return "yes" if val else "no"

def _lst(items: list | None, limit: int = 3) -> str:
    if not items:
        return "none"
    out = ", ".join(str(i) for i in items[:limit])
    if len(items) > limit:
        out += f" (+{len(items) - limit})"
    return out

def _fmt_score(score: float) -> str:
    if score >= 70:
        return _col(f"{score:.2f}", _R)
    if score >= 40:
        return _col(f"{score:.2f}", _Y)
    return _col(f"{score:.2f}", _G)

def _ms(val) -> str:
    return f"{val}ms" if val is not None else "n/a"

def _trunc(s: str, n: int = 80) -> str:
    """Truncate a long string with ellipsis."""
    if not s:
        return "n/a"
    s = str(s)
    return s if len(s) <= n else s[:n] + "..."

def _fmt_mx(mx_list: list) -> str:
    """Format MX records — handles both dicts and plain strings."""
    if not mx_list:
        return "none"
    parts = []
    for entry in mx_list[:3]:
        if isinstance(entry, dict):
            host = entry.get("host", "?")
            pri  = entry.get("priority", "")
            parts.append(f"{host} ({pri})" if pri != "" else host)
        else:
            parts.append(str(entry))
    out = ", ".join(parts)
    if len(mx_list) > 3:
        out += f" (+{len(mx_list) - 3})"
    return out

_KEY_W_MIN = 17

def _kv_block(rows: list[tuple[str, str]]) -> None:
    key_w    = max(max((len(k) for k, _ in rows if k), default=8), _KEY_W_MIN) + 2
    ansi_pad = len(_DIM) + len(_RST)
    for key, val in rows:
        if not key:
            print()
            continue
        print(f"  {_col(key, _DIM):<{key_w + ansi_pad}}  {val}")

def _print_verdict(result: dict) -> None:
    score   = result.get("score", 0.0)
    verdict = result.get("verdict", "unknown")
    risk    = result.get("risk_level", "unknown")
    vc      = _verdict_color(verdict)

    rows = [
        ("verdict",     _col(verdict.upper(), vc)),
        ("score",       f"{_fmt_score(score)} / 100"),
        ("risk_level",  risk.upper()),
    ]

    confidence = result.get("confidence")
    if confidence is not None:
        rows.append(("confidence", f"{confidence:.2f}"))

    ml_score = result.get("ml_score")
    if ml_score is not None:
        rows.append(("ml_score", f"{ml_score:.4f}"))

    print()
    _kv_block(rows)
    print()

def _print_heuristics(heuristics: list, verbose: bool) -> None:
    if not heuristics:
        return

    rule_w = max(len(h.get("name", "")) for h in heuristics)
    rule_w = max(rule_w, len("RULE"))

    print(f"  {'MODULE':<8}  {'RULE':<{rule_w}}  {'VAL':>5}  {'WT':>4}  {'CONTRIB':>7}")
    print(f"  {'-'*8}  {'-'*rule_w}  {'-'*5}  {'-'*4}  {'-'*7}")

    for h in heuristics:
        cat     = h.get("category", "")
        name    = h.get("name", "")
        val     = h.get("value", 0.0)
        weight  = h.get("weight", 0.0)
        contrib = h.get("contribution", 0.0)
        print(f"  {cat:<8}  {name:<{rule_w}}  {val:>5.2f}  {weight:>4.1f}  {contrib:>7.1f}")

        if verbose:
            details = h.get("details", {})
            _print_heuristic_details(details, rule_w)

    print()

def _print_heuristic_details(details: dict, rule_w: int) -> None:
    """Print heuristic detail rows indented under their parent rule."""
    indent = f"  {'':8}  {'':>{rule_w}}    "
    ansi_pad = len(_DIM) + len(_RST)
    key_w = 20

    for dk, dv in details.items():
        if dv is None:
            continue
        if isinstance(dv, dict):
            for sk, sv in dv.items():
                if sv is None:
                    continue
                label = f"{dk}.{sk}"
                print(f"{indent}{_col(label, _DIM):<{key_w + ansi_pad}}  {sv}")
        elif isinstance(dv, list):
            if not dv:
                continue
            displayed = [_trunc(str(x), 60) for x in dv[:3]]
            suffix    = f" (+{len(dv) - 3})" if len(dv) > 3 else ""
            print(f"{indent}{_col(dk, _DIM):<{key_w + ansi_pad}}  {', '.join(displayed)}{suffix}")
        else:
            print(f"{indent}{_col(dk, _DIM):<{key_w + ansi_pad}}  {dv}")

def _print_findings(heuristics: list, score: float) -> None:
    lines = []
    for h in heuristics:
        val      = h.get("value", 0)
        is_alert = val > 0.4
        for r in h.get("reasons", []):
            if not is_alert and score < 20:
                continue
            tag = "[!]" if is_alert else "[i]"
            lines.append((tag, r))

    if not lines:
        return

    seen: set[str] = set()
    for tag, msg in lines:
        if msg in seen:
            continue
        seen.add(msg)
        color = _Y if tag == "[!]" else _DIM
        print(f"  {_col(tag, color)} {msg}")
    print()

def _print_insights(insight: list) -> None:
    for line in insight:
        print(f"  {_col('[*]', _C)} {line}")
    if insight:
        print()

def _print_target_flat(identity: dict, network: dict, tls: dict,
                       dns: dict, http: dict, domain: dict,
                       content: dict, verbose: bool) -> None:
    rows: list[tuple[str, str]] = []
    rows.append(("host",           identity.get("hostname", "n/a")))
    rows.append(("registered",     identity.get("registered_domain", "n/a")))
    rows.append(("tld",            identity.get("tld", "n/a")))
    rows.append(("scheme",         identity.get("scheme", "n/a").upper()))
    subdomains = identity.get("subdomains") or []
    rows.append(("subdomains",     _lst(subdomains) if subdomains else "none"))
    rows.append(("url_length",     str(identity.get("url_length", "n/a"))))
    rows.append(("domain_length",  str(identity.get("domain_length", "n/a"))))
    rows.append(("entropy",        f"{identity.get('domain_entropy', 0):.3f}"))
    rows.append(("has_ip",         _yn(identity.get("has_ip"))))
    rows.append(("has_port",       _yn(identity.get("has_port"))))
    rows.append(("idn",            _yn(identity.get("is_idn"))))
    rows.append(("homograph",      _yn(identity.get("is_homograph"))))
    if verbose:
        rows.append(("punycode",   identity.get("punycode", "n/a")))
        path = identity.get("path", "")
        if path and path != "/":
            rows.append(("path",  path))
        query = identity.get("query", "")
        if query:
            rows.append(("query", query))
    rows.append(("", ""))
    status = http.get("status_code")
    rows.append(("status",         f"{status} OK" if status == 200 else str(status)))
    rows.append(("response_time",  f"{http.get('response_time_s', 'n/a')}s"))
    rows.append(("content_type",   http.get("content_type", "n/a")))
    size = http.get("content_length")
    rows.append(("payload",        f"{size / 1024:.1f} KB" if size else "n/a"))
    rows.append(("compression",    http.get("encoding", "none")))
    rows.append(("keep_alive",     _yn(http.get("keep_alive"))))
    rows.append(("redirects",      str(http.get("redirects", 0))))
    http_ver = network.get("http_version")
    rows.append(("http_version",   http_ver if http_ver else "n/a"))
    alt_svc = http.get("alt_svc")
    rows.append(("alt_svc",        _trunc(alt_svc, 60) if alt_svc else "none"))
    rows.append(("server",         http.get("server", "unknown")))
    ipv4 = network.get("ipv4") or []
    rows.append(("ipv4",           _lst(ipv4)))
    ipv6 = network.get("ipv6") or []
    rows.append(("ipv6",           _lst(ipv6, limit=2)))
    rows.append(("reverse_dns",    network.get("reverse_dns") or "n/a"))
    rows.append(("cdn",            network.get("cdn") or "n/a"))
    rows.append(("waf",            network.get("waf") or "n/a"))
    rows.append(("asn",            str(network.get("asn")) if network.get("asn") else "n/a"))
    rows.append(("isp",            network.get("isp") or "n/a"))
    geo = network.get("geo")
    rows.append(("geo",            str(geo) if geo else "n/a"))

    if verbose:
        timings = network.get("timings", {})
        rows.append(("timing_total", _ms(timings.get("total_ms"))))
        rows.append(("timing_dns",   _ms(timings.get("dns_ms"))))
        rows.append(("timing_tcp",   _ms(timings.get("tcp_ms"))))
        rows.append(("timing_tls",   _ms(timings.get("tls_ms"))))
        rows.append(("timing_ttfb",  _ms(timings.get("ttfb_ms"))))

        chain = http.get("redirect_chain", [])
        if len(chain) > 1:
            for i, hop in enumerate(chain):
                rows.append((f"redirect_{i}", f"{hop.get('status')}  {hop.get('url', '')}"))

        sec_headers = http.get("security_headers", {})
        for hk, hv in (sec_headers or {}).items():
            key   = f"header_{hk.lower().replace('-', '_')}"
            value = _trunc(str(hv), 80)
            rows.append((key, value))

    rows.append(("", ""))
    rows.append(("tls",              tls.get("version", "n/a")))
    rows.append(("cipher",           tls.get("cipher_suite", "n/a")))
    rows.append(("issuer",           tls.get("issuer", "n/a")))
    org = (tls.get("issuer_detail") or {}).get("organizationName")
    if org and org != tls.get("issuer"):
        rows.append(("issuer_org",   org))
    rows.append(("subject",          tls.get("subject", "n/a")))
    rows.append(("cert_valid_from",  tls.get("valid_from", "n/a")))
    rows.append(("cert_valid_until", tls.get("valid_until", "n/a")))
    rows.append(("validity_days",    str(tls.get("validity_days", "n/a"))))
    rows.append(("san_count",        str(tls.get("san_count", "n/a"))))
    san_list = tls.get("san") or []
    rows.append(("san",              _lst(san_list, limit=3)))
    rows.append(("wildcard",         _yn(tls.get("wildcard"))))
    rows.append(("self_signed",      _yn(tls.get("self_signed"))))
    rows.append(("public_key_alg",   tls.get("public_key_algorithm", "n/a")))
    rows.append(("sig_algorithm",    tls.get("signature_algorithm", "n/a")))
    rows.append(("ocsp_stapling",    _yn(tls.get("ocsp_stapling"))))
    rows.append(("ocsp_reachable",   _yn(tls.get("ocsp_reachable"))))
    if verbose:
        fps = tls.get("fingerprints", {})
        if fps.get("sha1"):
            rows.append(("cert_sha1",   fps["sha1"]))
        if fps.get("sha256"):
            rows.append(("cert_sha256", fps["sha256"]))
        if tls.get("serial_number"):
            rows.append(("serial",      tls["serial_number"]))
    rows.append(("", ""))
    a_records = dns.get("a") or []
    rows.append(("a",     _lst(a_records)))
    aaaa = dns.get("aaaa") or []
    rows.append(("aaaa",  _lst(aaaa, limit=2)))
    mx_list = dns.get("mx") or []
    rows.append(("mx",    _fmt_mx(mx_list) if mx_list else _yn(dns.get("has_mx"))))
    ns = dns.get("ns") or []
    rows.append(("ns",    _lst(ns, limit=2)))
    cname = dns.get("cname") or []
    rows.append(("cname", _lst(cname) if cname else "none"))
    txt = dns.get("txt") or []
    rows.append(("txt",   _lst(txt, limit=2) if txt else "none"))
    rows.append(("spf",   _yn(dns.get("spf"))))
    rows.append(("dmarc", _yn(dns.get("dmarc"))))
    rows.append(("dkim",  _yn(dns.get("dkim"))))
    rows.append(("ttl",   str(dns.get("ttl", "n/a"))))
    rows.append(("", ""))
    title = content.get("title")
    rows.append(("title",       title if title else "n/a"))
    rows.append(("language",    content.get("language") or "n/a"))
    rows.append(("html_size",   f"{content.get('html_size_kb', 'n/a')} KB"))
    rows.append(("spa",         _yn(content.get("spa"))))
    rows.append(("favicon",     _trunc(content.get("favicon") or "none", 60)))
    rows.append(("canonical",   _trunc(content.get("canonical") or "none", 60)))
    rows.append(("generator",   content.get("generator") or "none"))
    scripts = content.get("scripts", {})
    rows.append(("scripts",     f"{scripts.get('total', 0)} total  {scripts.get('external', 0)} external  {scripts.get('inline', 0)} inline"))
    rows.append(("stylesheets", str(content.get("stylesheets", 0))))
    rows.append(("iframes",     str(content.get("iframes", 0))))
    forms = content.get("forms", {})
    rows.append(("forms",       f"{forms.get('count', 0)}  password_fields: {forms.get('password_fields', 0)}"))
    rows.append(("inputs",      str(content.get("inputs", 0))))
    rows.append(("images",      str(content.get("images", 0))))
    rows.append(("anchors",     str(content.get("anchors", 0))))
    if verbose:
        meta_tags = content.get("meta_tags", {})
        for mk, mv in (meta_tags or {}).items():
            rows.append((f"meta_{mk}", _trunc(str(mv), 80)))
        html_hash = content.get("html_sha256")
        if html_hash:
            rows.append(("html_sha256", html_hash))
    rows.append(("", ""))

    rows.append(("registrar",     domain.get("registrar", "n/a")))
    rows.append(("created",       domain.get("created_at", "n/a")))
    rows.append(("updated",       domain.get("updated_at", "n/a")))
    rows.append(("expires",       domain.get("expires_at", "n/a")))
    rows.append(("age",           f"{domain.get('age_days', 'n/a')} days"))
    status_list = domain.get("status") or []
    rows.append(("domain_status", _lst(status_list)))

    _kv_block(rows)

def _print_engine(meta: dict, stats: dict) -> None:
    scan_id   = meta.get("scan_id", "n/a")[:16]
    url_hash  = meta.get("url_hash", "n/a")[:24] + "..."
    timestamp = meta.get("timestamp", "n/a")
    threads   = str(meta.get("threads", 1))
    scan_time = f"{meta.get('scan_time_s', 'n/a')}s"

    rules_total = stats.get("rules_total", 0)
    triggered   = stats.get("rules_triggered", 0)
    suppressed  = rules_total - triggered
    rate        = stats.get("trigger_rate", 0)

    rows = [
        ("scan_id",      scan_id),
        ("url_hash",     url_hash),
        ("timestamp",    timestamp),
        ("threads",      threads),
        ("rules_loaded", str(rules_total)),
        ("triggered",    str(triggered)),
        ("suppressed",   str(suppressed)),
        ("trigger_rate", f"{rate * 100:.1f}%"),
        ("scan_time",    scan_time),
    ]

    print()
    _kv_block(rows)
    print()

def print_output(scan: dict, target: dict, verbose: bool = False, time=None):
    status = scan.get("status")
    if status == "error":
        err: dict = scan.get("error", {})
        print(f"FALHA {err.get('type')}: {err.get('message')}")
        return

    meta:       dict  = scan.get("meta", {})
    result:     dict  = scan.get("result", {})
    stats:      dict  = scan.get("stats", {})
    heuristics: list  = scan.get("heuristics", [])
    insight:    list  = scan.get("insight", [])
    score:      float = result.get("score", 0.0)

    identity: dict = target.get("identity", {})
    network:  dict = target.get("network", {})
    tls:      dict = target.get("tls", {})
    dns:      dict = target.get("dns", {})
    http:     dict = target.get("http", {})
    domain:   dict = target.get("domain", {})
    content:  dict = target.get("content", {})

    _print_verdict(result)
    _print_heuristics(heuristics, verbose)
    _print_findings(heuristics, score)
    _print_insights(insight)
    _print_target_flat(identity, network, tls, dns, http, domain, content, verbose)
    _print_engine(meta, stats)