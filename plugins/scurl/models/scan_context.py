from dataclasses import dataclass, field
from datetime import datetime, timezone
from hashlib import sha256
from time import time
from urllib.parse import ParseResult, urlparse, urlunparse
from providers.http.http_result import HTTPResult

@dataclass
class TargetData:
    url: str = ""
    parsed_url: ParseResult | None = None
    response: HTTPResult | None = None
    html: object | None = None
    rdap: dict | None = None
    dns: dict | None = None
    ssl: dict | None = None
    structure: dict = field(default_factory=dict)
    size_kb: float = 0.0
    safe_browsing: dict | None = None

@dataclass
class ScanMeta:
    scan_id: str = ""
    url_hash: str = ""
    threads: int = 1
    start: float = field(default_factory=time)
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    resolved_ip: object | None = None
    resolved_addresses: tuple = ()

@dataclass
class ScanContext:
    target: TargetData = field(default_factory=TargetData)
    meta: ScanMeta = field(default_factory=ScanMeta)
    results: list = field(default_factory=list)
    results_map: dict[str, float | None] = field(default_factory=dict)
    scores: list[float] = field(default_factory=list)
    weights: list[float] = field(default_factory=list)
    heuristics: list[dict] = field(default_factory=list)
    score: float = 0.0
    classification: str = ""
    risk: str = ""

    def __post_init__(self):
        if self.target.url and not self.meta.url_hash:
            parsed = urlparse(self.target.url)
            normalized = urlunparse(parsed)
            self.meta.url_hash = sha256(normalized.encode()).hexdigest()
