"""Contratos HTTP do SCIMG, seguindo o padrão api/router/scfs/schema/map_result.py."""
from typing import Any, Literal
from pydantic import BaseModel, Field

class EngineInfo(BaseModel):
    name: Literal["scimg"]
    version: str

class Meta(BaseModel):
    scan_id: str
    image_name: str
    sha256: str
    size_bytes: int
    timestamp: str
    scan_time_s: float
    width: int
    height: int
    format: str

class Result(BaseModel):
    score: float = Field(ge=0, le=100)
    risk_level: str
    verdict: str
    note: str

class Stats(BaseModel):
    rules_total: int
    rules_evaluated: int
    rules_skipped: int
    rules_triggered: int
    trigger_rate: float

class Heuristic(BaseModel):
    name: str
    category: str
    value: float
    weight: float
    contribution: float
    details: dict[str, Any] | None = None
    reasons: list[str] = Field(default_factory=list)

class Provenance(BaseModel):
    unverified_metadata_markers: list[str]
    cryptographic_validation: bool

class AIModel(BaseModel):
    status: str
    probability: float | None = None

class ScanResponse(BaseModel):
    status: Literal["ok"]
    engine: EngineInfo
    meta: Meta
    result: Result
    stats: Stats
    scoring: dict[str, Any]
    provenance: Provenance
    heuristics: list[Heuristic]
    skipped_rules: list[Any]
    ai_model: AIModel

class Identity(BaseModel):
    name: str
    size_bytes: int
    sha256: str

class ImageInfo(BaseModel):
    width: int
    height: int
    format: str

class TargetResponse(BaseModel):
    identity: Identity
    image: ImageInfo

class AnalyzeResponse(BaseModel):
    scan: ScanResponse
    target: TargetResponse
