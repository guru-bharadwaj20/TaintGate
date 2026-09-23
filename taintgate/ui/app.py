"""Local authenticated dry-run UI. No production servers are configured here."""

from __future__ import annotations

import asyncio
import secrets
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from dataclasses import asdict
from pathlib import Path
from typing import Any

from fastapi import Depends, FastAPI, Header, HTTPException
from fastapi.responses import HTMLResponse
from pydantic import BaseModel, ConfigDict, Field

from taintgate.demo import make_demo


class PlanRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    source: str = Field(min_length=1, max_length=32_000)


class ApprovalRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    scope: str = Field(min_length=64, max_length=64)
    reason: str = Field(min_length=1, max_length=512)


def create_app(token: str | None = None) -> FastAPI:
    @asynccontextmanager
    async def lifespan(api: FastAPI) -> AsyncIterator[None]:
        application, server = make_demo()
        api.state.application = application
        api.state.server = server
        try:
            yield
        finally:
            application.audit.close()
            if application.gateway.guard is not None:
                application.gateway.guard.pins.close()

    api = FastAPI(title="TaintGate dry-run", docs_url=None, redoc_url=None, lifespan=lifespan)
    session_token = token or secrets.token_urlsafe(32)
    api.state.token = session_token
    api.state.runs = {}
    lock = asyncio.Lock()

    def authenticated(authorization: str | None = Header(default=None)) -> None:
        expected = "Bearer " + session_token
        if authorization is None or not secrets.compare_digest(authorization, expected):
            raise HTTPException(401, "A local session token is required")

    @api.get("/", response_class=HTMLResponse)
    def index() -> str:
        return Path(__file__).with_name("index.html").read_text(encoding="utf-8")

    @api.post("/runs", dependencies=[Depends(authenticated)])
    async def run(request: PlanRequest) -> dict[str, Any]:
        async with lock:
            try:
                result = await api.state.application.run(request.source)
            except (ValueError, TypeError):
                raise HTTPException(400, "Plan rejected during preflight") from None
            output = asdict(result)
            if len(api.state.runs) >= 100:
                del api.state.runs[next(iter(api.state.runs))]
            api.state.runs[result.run_id] = output
            return output

    @api.get("/runs/{run_id}", dependencies=[Depends(authenticated)])
    def inspect_run(run_id: str) -> dict[str, Any]:
        if run_id not in api.state.runs:
            raise HTTPException(404, "Unknown run")
        return dict(api.state.runs[run_id])

    @api.post("/approvals", dependencies=[Depends(authenticated)])
    async def approve(request: ApprovalRequest) -> dict[str, Any]:
        async with lock:
            try:
                api.state.application.approve(request.scope, request.reason)
            except ValueError:
                raise HTTPException(409, "Unknown, expired or non-approvable scope") from None
        return {"approved": True, "scope": request.scope}

    return api
