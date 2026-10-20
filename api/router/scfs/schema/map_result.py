from typing import Any, Literal
from pydantic import BaseModel


class EngineInfo(BaseModel):
    name: Literal["scfs"]
    version: str


class Meta(BaseModel):
    scan_id: str
    timestamp: str
    scan_time_s: float
    file_hash: str
    threads: int


class Result(BaseModel):
    score: float | None
    risk_level: str
    verdict: str


class Stats(BaseModel):
    rules_total: int
    rules_evaluated: int
    rules_triggered: int
    rules_failed: int
    rules_disabled: int
    rules_unavailable: int


class Heuristic(BaseModel):
    name: str
    category: str
    severity: str
    weight: float
    tags: list[str]
    group: str
    score: float | None
    status: str
    triggered: bool
    message: str
    evidence: list[str]


class ScanResponse(BaseModel):
    status: Literal["ok", "partial", "inconclusive"]
    engine: EngineInfo
    meta: Meta
    result: Result
    stats: Stats
    scoring: dict[str, Any]
    heuristics: list[Heuristic]
    warnings: list[str]
    insight: str


class Identity(BaseModel):
    name: str
    size_bytes: int
    sha256: str


class Content(BaseModel):
    strings_count: int
    strings_truncated: bool


class TargetResponse(BaseModel):
    identity: Identity
    executable: dict[str, Any]
    content: Content
    reputation: dict[str, Any] | None


class AnalyzeResponse(BaseModel):
    scan: ScanResponse
    target: TargetResponse
