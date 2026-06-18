from pydantic import BaseModel

class ErrorMeta(BaseModel):
    url: str | None
    scan_time_s: float
    version: str

class ErrorDetail(BaseModel):
    type: str
    message: str

class ErrorResponse(BaseModel):
    status: str
    meta: ErrorMeta
    error: ErrorDetail