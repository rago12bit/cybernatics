from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, Field


class GitSource(BaseModel):
    type: Literal["git"]
    url: str = Field(max_length=300, examples=["https://github.com/OWASP/NodeGoat"])


class ScanRequest(BaseModel):
    source: GitSource
    tools: list[str] | None = Field(default=None, description="Defaults to all tools.")


class ScanCreated(BaseModel):
    id: str
    status: str


class ToolStatus(BaseModel):
    status: str
    findings: int = 0
    exit_code: int | None = None
    duration_seconds: float | None = None
    error: str | None = None
    raw_artifact: str | None = Field(default=None, description="withheld/available")


class ScanView(BaseModel):
    id: str
    status: str
    source_type: str
    source_label: str
    tools: list[str]
    created_at: datetime
    started_at: datetime | None
    finished_at: datetime | None
    error: str | None
    tool_status: dict[str, ToolStatus]
    severity_counts: dict[str, int]


class FindingsPage(BaseModel):
    total: int
    limit: int
    offset: int
    items: list[dict[str, Any]]
