from typing import Literal
from pydantic import BaseModel

class ErrorDetail(BaseModel):
    type: str
    message: str

class ErrorResponse(BaseModel):
    status: Literal["error"]
    error: ErrorDetail
