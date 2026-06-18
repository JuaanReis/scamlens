from pydantic import BaseModel, HttpUrl
from typing import Any

class AnalyzeRequest(BaseModel):
    url: HttpUrl
    use_cache: bool = False

class EngineInfo(BaseModel):
    name: str
    version: str

class Meta(BaseModel):
    scan_id: str
    scan_time_s: float
    url_hash: str
    url: str
    threads: int
    timestamp: str

class Result(BaseModel):
    score: float
    risk_level: str
    verdict: str

class Stats(BaseModel):
    rules_total: int
    rules_triggered: int
    trigger_rate: float

class Heuristic(BaseModel):
    name: str
    category: str
    value: float
    weight: float
    contribution: float
    details: dict[str, Any]
    reasons: list[str]

class ScanResponse(BaseModel):
    status: str
    engine: EngineInfo
    meta: Meta
    result: Result
    stats: Stats
    heuristics: list[Heuristic]
    insight: list[str]

class Identity(BaseModel):
    original_url: str
    final_url: str | None
    scheme: str
    hostname: str
    registered_domain: str
    tld: str
    subdomains: list[str]
    subdomain_count: int
    port: int | None
    path: str
    query: str
    fragment: str
    normalized_url: str
    punycode: str
    unicode_domain: str
    is_idn: bool
    is_homograph: bool
    domain_length: int
    domain_entropy: float
    url_length: int
    has_ip: bool
    has_port: bool

class Timings(BaseModel):
    total_ms: int | None
    dns_ms: int | None
    tcp_ms: int | None
    tls_ms: int | None
    ttfb_ms: int | None

class ASN(BaseModel):
    number: int | None
    organization: str | None

class Geo(BaseModel):
    country: str | None
    region: str | None
    city: str | None

class CDN(BaseModel):
    detected: bool | None
    provider: str | None

class WAF(BaseModel):
    detected: bool | None
    provider: str | None

class Network(BaseModel):
    ipv4: list[str]
    ipv6: list[str]
    reverse_dns: str | None
    asn: ASN | None
    geo: Geo | None
    isp: str | None
    cdn: CDN | None
    waf: WAF | None
    http_version: str | None
    timings: Timings

class Fingerprints(BaseModel):
    sha1: str
    sha256: str

class TLS(BaseModel):
    enabled: bool
    version: str | None = None
    cipher_suite: str | None = None
    issuer: str | None = None
    issuer_detail: dict[str, Any] | None = None
    subject: str | None = None
    valid_from: str | None = None
    valid_until: str | None = None
    validity_days: int | None = None
    san: list[str] = []
    san_count: int = 0
    wildcard: bool = False
    self_signed: bool = False
    serial_number: str | None = None
    signature_algorithm: str | None = None
    public_key_algorithm: str | None = None
    ocsp_stapling: bool | None = None
    ocsp_reachable: bool | None = None
    fingerprints: Fingerprints | None = None

class MXRecord(BaseModel):
    priority: int | None
    host: str

class DNS(BaseModel):
    a: list[str]
    aaaa: list[str]
    mx: list[MXRecord]
    ns: list[str]
    cname: list[str]
    txt: list[str]
    spf: bool
    dmarc: bool
    dkim: bool | None
    ttl: int | None
    has_mx: bool

class Compression(BaseModel):
    enabled: bool
    algorithm: str | None

class HTTP(BaseModel):
    status_code: int | None
    response_time_s: float | None
    redirects: int
    redirect_chain: list[dict] | None
    content_type: str | None
    content_length: int | None
    encoding: str | None
    compression: Compression | None
    server: str | None
    alt_svc: str | None
    keep_alive: bool
    security_headers: dict[str, str]
    cookies: Any | None

class Scripts(BaseModel):
    total: int
    external: int
    inline: int

class Forms(BaseModel):
    count: int
    password_fields: int

class Content(BaseModel):
    title: str | None
    language: str | None
    html_size_kb: float
    scripts: Scripts
    stylesheets: int
    iframes: int
    forms: Forms
    inputs: int
    images: int
    anchors: int
    favicon: str | None
    canonical: str | None
    meta_tags: dict[str, str | None]
    generator: str | None
    spa: bool
    html_sha256: str | None

class Domain(BaseModel):
    registrar: str | None
    created_at: str | None
    updated_at: str | None
    expires_at: str | None
    age_days: int | None
    status: list[str]

class TargetResponse(BaseModel):
    identity: Identity
    network: Network
    tls: TLS
    dns: DNS
    http: HTTP
    content: Content | None
    domain: Domain

class AnalyzeResponse(BaseModel):
    scan: ScanResponse
    target: TargetResponse

class ScanSummary(BaseModel):
    url: str
    score: float
    risk_level: str
    verdict: str
    scan_id: str
    timestamp: str
    url_hash: str

class ScansListResponse(BaseModel):
    status: str
    total: int
    scans: list[ScanSummary]