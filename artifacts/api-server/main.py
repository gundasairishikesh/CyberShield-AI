from __future__ import annotations

import time
from collections import defaultdict
from typing import Literal

from fastapi import FastAPI, HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field

from threat_analysis import analyze_message, analyze_url


Language = Literal["en", "hi", "te"]
RiskLevel = Literal["low", "medium", "high"]
ScanKind = Literal["url", "message"]


class InputModel(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    language: Language = "en"


class UrlScanInput(InputModel):
    url: str = Field(min_length=1, max_length=4096)


class MessageScanInput(InputModel):
    message: str = Field(min_length=1, max_length=10000)


class ThreatIndicator(BaseModel):
    code: str
    title: str
    detail: str


class ThreatAssessment(BaseModel):
    id: str
    kind: ScanKind
    riskLevel: RiskLevel
    riskScore: int = Field(ge=0, le=100)
    indicators: list[ThreatIndicator]
    recommendations: list[str]
    explanation: str
    engine: Literal["rule-based"]
    evaluatedAt: str
    language: Language


app = FastAPI(title="CyberShield AI API", docs_url=None, redoc_url=None)
rate_windows: dict[str, tuple[float, int]] = defaultdict(lambda: (0.0, 0))


@app.middleware("http")
async def request_limits(request: Request, call_next):
    content_length = request.headers.get("content-length")
    if content_length:
        try:
            if int(content_length) > 64 * 1024:
                return JSONResponse(status_code=413, content={"error": "The request is larger than the allowed limit."})
        except ValueError:
            return JSONResponse(status_code=400, content={"error": "Invalid request length."})

    if request.url.path in {"/api/analyze/url", "/api/analyze/message"}:
        now = time.monotonic()
        address = request.client.host if request.client else "unknown"
        start, count = rate_windows[address]
        if now - start >= 60:
            rate_windows[address] = (now, 1)
        elif count >= 30:
            retry_after = max(1, int(60 - (now - start)))
            return JSONResponse(
                status_code=429,
                content={"error": "Scan limit reached. Please wait a moment before trying again."},
                headers={"Retry-After": str(retry_after)},
            )
        else:
            rate_windows[address] = (start, count + 1)

        if len(rate_windows) > 2000:
            for key, (window_start, _) in list(rate_windows.items()):
                if now - window_start >= 60:
                    rate_windows.pop(key, None)
    return await call_next(request)


@app.exception_handler(RequestValidationError)
async def validation_error_handler(_request: Request, _error: RequestValidationError):
    return JSONResponse(
        status_code=400,
        content={"error": "Input is invalid or exceeds the allowed length."},
    )


@app.exception_handler(HTTPException)
async def http_error_handler(_request: Request, error: HTTPException):
    return JSONResponse(status_code=error.status_code, content={"error": str(error.detail)})


@app.get("/api/healthz")
async def health_check():
    return {"status": "ok"}


@app.post("/api/analyze/url", response_model=ThreatAssessment)
async def analyze_url_endpoint(data: UrlScanInput):
    try:
        return analyze_url(data.url, data.language)
    except ValueError as error:
        raise HTTPException(status_code=400, detail=str(error)) from error


@app.post("/api/analyze/message", response_model=ThreatAssessment)
async def analyze_message_endpoint(data: MessageScanInput):
    return analyze_message(data.message, data.language)
