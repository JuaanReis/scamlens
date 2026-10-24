from time import time
from plugins.math.shannon_entropy import shannon_entropy
from plugins.scurl.models.scan_context import ScanContext
from plugins.scurl.engine.analysis.insights import insights
from plugins.scurl import __version__
import hashlib
from datetime import datetime, timezone

def _build_identity(ctx: ScanContext) -> dict:
    structure = ctx.target.structure
    response = ctx.target.response
    hostname = structure.get("hostname", "")
    registered_domain = structure.get("registered_domain", "")

    try:
        hostname.encode("ascii")
        is_idn = False
        punycode = hostname
        unicode_domain = hostname
    except UnicodeEncodeError:
        is_idn = True
        punycode = hostname.encode("idna").decode("ascii")
        unicode_domain = hostname

    return {
        "original_url": ctx.target.url,
        "final_url": response.url if response else None,
        "scheme": structure.get("scheme", ""),
        "hostname": hostname,
        "registered_domain": registered_domain,
        "tld": structure.get("tld", ""),
        "subdomains": structure.get("subdomain", []),
        "subdomain_count": structure.get("subdomain_count", 0),
        "port": structure.get("port"),
        "path": structure.get("path", ""),
        "query": structure.get("query", ""),
        "fragment": structure.get("fragment", ""),
        "normalized_url": structure.get("url", ""),
        "punycode": punycode,
        "unicode_domain": unicode_domain,
        "is_idn": is_idn,
        "is_homograph": False,
        "is_https": structure.get("scheme", "").lower() == "https",
        "domain_length": structure.get("domain_length", 0),
        "domain_entropy": round(shannon_entropy(registered_domain), 5),
        "url_length": structure.get("url_length", 0),
        "has_ip": bool(structure.get("has_ip")),
        "has_port": bool(structure.get("has_port")),
    }

def _build_network(ctx: ScanContext) -> dict:
    dns = ctx.target.dns or {}
    response = ctx.target.response

    return {
        "ipv4": dns.get("a", []),
        "ipv6": dns.get("aaaa", []),
        "reverse_dns": None,
        "asn": None,
        "geo": None,
        "isp": None,
        "cdn": None,
        "waf": None,
        "http_version": None,
        "timings": {
            "total_ms": round(response.elapsed * 1000) if response else None,
            "dns_ms": None,
            "tcp_ms": None,
            "tls_ms": None,
            "ttfb_ms": None,
        }
    }

def _build_tls(ctx: ScanContext) -> dict:
    ssl = ctx.target.ssl or {}

    if not ssl or ssl.get("connection_error") or ssl.get("timeout") or ssl.get("unknown"):
        return {"enabled": False}

    issuer = ssl.get("issuer_detail") or {}
    subject = ssl.get("subject_detail") or {}

    return {
        "enabled": ssl.get("enabled", False),
        "version": ssl.get("version"),
        "cipher_suite": ssl.get("cipher_suite"),
        "issuer": issuer.get("organizationName") or issuer.get("commonName"),
        "issuer_detail": issuer,
        "subject": subject.get("commonName"),
        "valid_from": ssl.get("valid_from"),
        "valid_until": ssl.get("valid_until"),
        "validity_days": ssl.get("validity_days"),
        "san": ssl.get("san", []),
        "san_count": ssl.get("san_count", 0),
        "wildcard": ssl.get("wildcard", False),
        "self_signed": ssl.get("self_signed", False),
        "serial_number": ssl.get("serial_number"),
        "signature_algorithm": ssl.get("signature_algorithm"),
        "public_key_algorithm": ssl.get("public_key_algorithm"),
        "ocsp_stapling": ssl.get("ocsp_stapling"),
        "ocsp_reachable": ssl.get("ocsp_reachable"),
        "fingerprints": ssl.get("fingerprints"),
    }

def _build_dns(ctx: ScanContext) -> dict:
    dns = ctx.target.dns or {}

    return {
        "a": dns.get("a", []),
        "aaaa": dns.get("aaaa", []),
        "mx": dns.get("mx", []),
        "ns": dns.get("ns", []),
        "cname": dns.get("cname", []),
        "txt": dns.get("txt", []),
        "spf": dns.get("spf", False),
        "dmarc": dns.get("dmarc", False),
        "dkim": dns.get("dkim"),
        "ttl": dns.get("ttl"),
        "has_mx": dns.get("has_mx", False),
    }

def _build_http(ctx: ScanContext) -> dict:
    response = ctx.target.response
    if not response:
        return {}

    headers = dict(response.headers)
    content_type = headers.get("content-type", "")
    encoding = headers.get("content-encoding", "")

    compression_map = {"br": "brotli", "gzip": "gzip", "deflate": "deflate", "zstd": "zstd"}

    security_headers = {
        k: v for k, v in headers.items()
        if k.lower() in {
            "content-security-policy", "strict-transport-security",
            "x-frame-options", "x-content-type-options",
            "referrer-policy", "permissions-policy",
            "cross-origin-opener-policy", "cross-origin-resource-policy"
        }
    }

    return {
        "status_code": response.status,
        "response_time_s": round(response.elapsed, 3),
        "redirects": response.redirects,
        "redirect_chain": response.redirect_chain or [],
        "content_type": content_type,
        "content_length": response.size,
        "size_kb": round(response.size / 1024, 2) if response.size else 0,
        "encoding": encoding,
        "compression": {
            "enabled": encoding in compression_map,
            "algorithm": compression_map.get(encoding)
        },
        "server": headers.get("server"),
        "alt_svc": headers.get("alt-svc"),
        "keep_alive": "keep-alive" in headers.get("connection", "").lower(),
        "security_headers": security_headers,
        "cookies": None,
    }

def _build_content(ctx: ScanContext) -> dict | None:
    html = ctx.target.html
    structure = ctx.target.structure

    if not html:
        return None

    root = html

    try:
        title = root.css_first("title")
        title_text = title.text(strip=True) if title else None
    except Exception:
        title_text = None

    try:
        lang_node = root.css_first("html")
        language = lang_node.attributes.get("lang") if lang_node else None
    except Exception:
        language = None

    try:
        scripts = root.css("script")
        external_scripts = [s for s in scripts if s.attributes.get("src")]
        inline_scripts = [s for s in scripts if not s.attributes.get("src")]
    except Exception:
        scripts = external_scripts = inline_scripts = []

    try:
        iframes = root.css("iframe")
    except Exception:
        iframes = []

    try:
        forms = root.css("form")
        password_fields = root.css("input[type='password']")
    except Exception:
        forms = password_fields = []

    try:
        inputs = root.css("input")
    except Exception:
        inputs = []

    try:
        images = root.css("img")
    except Exception:
        images = []

    try:
        anchors = root.css("a")
    except Exception:
        anchors = []

    try:
        stylesheets = root.css("link[rel='stylesheet']")
    except Exception:
        stylesheets = []

    try:
        canonical_node = root.css_first("link[rel='canonical']")
        canonical = canonical_node.attributes.get("href") if canonical_node else None
    except Exception:
        canonical = None

    try:
        favicon_node = root.css_first("link[rel*='icon']")
        favicon = favicon_node.attributes.get("href") if favicon_node else None
    except Exception:
        favicon = None

    try:
        generator_node = root.css_first("meta[name='generator']")
        generator = generator_node.attributes.get("content") if generator_node else None
    except Exception:
        generator = None

    try:
        meta_tags = {
            node.attributes.get("name") or node.attributes.get("property"): node.attributes.get("content")
            for node in root.css("meta")
            if (node.attributes.get("name") or node.attributes.get("property")) and node.attributes.get("content")
        }
    except Exception:
        meta_tags = {}

    body_html = ""
    try:
        body_node = root.css_first("body")
        if body_node:
            body_html = body_node.html or ""
    except Exception:
        pass

    html_hash = hashlib.sha256(body_html.encode()).hexdigest() if body_html else None
    spa = any(
        root.css_first(sel) is not None
        for sel in ["[ng-app]", "[data-reactroot]", "[data-react-helmet]", "#__next", "#app", "#vue-app"]
    )

    return {
        "title": title_text,
        "language": language,
        "html_size_kb": ctx.target.size_kb,
        "scripts": {
            "total": len(list(scripts)),
            "external": len(external_scripts),
            "inline": len(inline_scripts),
        },
        "stylesheets": len(list(stylesheets)),
        "iframes": len(list(iframes)),
        "forms": {
            "count": len(list(forms)),
            "password_fields": len(list(password_fields)),
        },
        "inputs": len(list(inputs)),
        "images": len(list(images)),
        "anchors": len(list(anchors)),
        "favicon": favicon,
        "canonical": canonical,
        "meta_tags": meta_tags,
        "generator": generator,
        "spa": spa,
        "html_sha256": html_hash,
    }

def _parse_rdap_date(events: list, action: str) -> str | None:
    for event in events:
        if event.get("eventAction") == action:
            return event.get("eventDate", "").split("T")[0]
    return None

def _rdap_registrar(entities: list) -> str | None:
    for entity in entities:
        if "registrar" in entity.get("roles", []):
            vcard = entity.get("vcardArray", [])
            if len(vcard) > 1:
                for field in vcard[1]:
                    if field[0] == "fn" and field[3]:
                        return field[3]
    return None

def _build_domain(ctx: ScanContext) -> dict:
    rdap = ctx.target.rdap or {}

    events = rdap.get("events", [])
    entities = rdap.get("entities", [])

    created_at = _parse_rdap_date(events, "registration")
    expires_at = _parse_rdap_date(events, "expiration")
    updated_at = _parse_rdap_date(events, "last changed")

    age_days = None
    if created_at:
        try:
            delta = datetime.now(timezone.utc) - datetime.fromisoformat(created_at).replace(tzinfo=timezone.utc)
            age_days = delta.days
        except Exception:
            pass

    return {
        "registrar": _rdap_registrar(entities),
        "created_at": created_at,
        "updated_at": updated_at,
        "expires_at": expires_at,
        "age_days": age_days,
        "status": rdap.get("status", []),
    }

def build_target(ctx: ScanContext) -> dict:
    return {
        "identity": _build_identity(ctx),
        "network": _build_network(ctx),
        "tls": _build_tls(ctx),
        "dns": _build_dns(ctx),
        "http": _build_http(ctx),
        "content": _build_content(ctx),
        "domain": _build_domain(ctx),
    }

def build_error_response(ctx: ScanContext, error_type: str, message: str) -> dict:
    return {
        "status": "error",
        "meta": {
            "url": ctx.target.url,
            "scan_time_s": round(time() - ctx.meta.start, 3),
            "version": __version__
        },
        "error": {
            "type": error_type,
            "message": message
        }
    }

def build_scan(ctx: ScanContext, rules_total: int) -> dict:
    rules_triggered = len(ctx.heuristics)

    return {
        "status": "ok",
        "engine": {
            "name": "scurl",
            "version": __version__
        },
        "meta": {
            "scan_id": ctx.meta.scan_id,
            "scan_time_s": round(time() - ctx.meta.start, 3),
            "url_hash": ctx.meta.url_hash,
            "url": ctx.target.url,
            "threads": ctx.meta.threads,
            "timestamp": ctx.meta.timestamp.isoformat()
        },
        "result": {
            "score": round(ctx.score, 2),
            "risk_level": ctx.risk,
            "verdict": ctx.classification,
        },
        "stats": {
            "rules_total": rules_total,
            "rules_triggered": rules_triggered,
            "trigger_rate": round(rules_triggered / rules_total, 3) if rules_total else 0
        },
        "heuristics": ctx.heuristics,
        "insight": insights(ctx.heuristics, ctx.score)
    }

def build_response(ctx: ScanContext, rules_total: int) -> tuple[dict, dict]:
    return build_scan(ctx, rules_total), build_target(ctx)
