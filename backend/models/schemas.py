import re
from datetime import datetime, timezone
from typing import Any, Optional

from pydantic import BaseModel, validator


ERROR_CODES = {
    "VALIDATION_ERROR": "VALIDATION_ERROR",
    "ANALYSIS_FAILED": "ANALYSIS_FAILED",
    "NOT_FOUND": "NOT_FOUND",
    "RATE_LIMITED": "RATE_LIMITED",
    "INTERNAL_ERROR": "INTERNAL_ERROR",
}


class AnalyzeRequest(BaseModel):
    code: str
    contract_name: Optional[str] = None
    job_id: Optional[str] = None
    language: Optional[str] = "en"

    @validator("code")
    def validate_solidity(cls, v: str) -> str:
        v = v.strip()
        if len(v) < 10:
            raise ValueError("code must be at least 10 characters")
        if not re.search(r"\b(contract|interface|library)\b", v):
            raise ValueError(
                "code must contain a Solidity contract, interface, or library declaration"
            )
        return v


class APIResponse:
    @staticmethod
    def success(data: Any) -> dict:
        return {
            "status": "success",
            "data": data,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

    @staticmethod
    def error(code: str, message: str) -> dict:
        return {
            "status": "error",
            "code": code,
            "message": message,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
