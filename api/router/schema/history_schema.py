from pydantic import BaseModel
from providers.database.history import HistoryModule


class HistoryEntry(BaseModel):
    module: HistoryModule
    scan_id: str | None
    target_hash: str
    target_name: str
    status: str
    score: float | None
    risk_level: str | None
    verdict: str | None
    scan_time_s: float | None
    timestamp: str | None
    user_id: int | None
    url: str | None = None
    url_hash: str | None = None


class ScanHistoryResponse(BaseModel):
    status: str = "ok"
    total: int
    limit: int
    offset: int
    scans: list[HistoryEntry]
