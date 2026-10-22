from typing import Any, Literal
from pydantic import BaseModel, Field


class PixAnalyzeRequest(BaseModel):
    payload: str = Field(min_length=1, max_length=4096)
    expected: dict[str, str] | None = None


class EngineInfo(BaseModel):
    name: Literal["scpix"]
    version: str


class Meta(BaseModel):
    scan_id: str
    timestamp: str
    scan_time_s: float
    payload_hash: str
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


class TargetResponse(BaseModel):
    identity: dict[str, Any]
    pix: dict[str, Any]
    verification: dict[str, bool]


class AnalyzeResponse(BaseModel):
    scan: ScanResponse
    target: TargetResponse
