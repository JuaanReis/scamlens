from typing import Literal
from pydantic import BaseModel
from .map_result import EngineInfo, Result


class ErrorMeta(BaseModel):
    scan_id: str
    timestamp: str
    scan_time_s: float


class ErrorDetail(BaseModel):
    code: str
    message: str


class ErrorResponse(BaseModel):
    status: Literal["error"]
    engine: EngineInfo
    meta: ErrorMeta
    result: Result
    error: ErrorDetail
