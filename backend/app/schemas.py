from datetime import UTC, datetime
from typing import Any, Literal

from pydantic import BaseModel, Field, field_validator, model_validator
from urllib.parse import urlparse


class ScannerStatus(BaseModel):
    tool: str
    status: Literal["pending", "running", "completed", "failed", "cancelled"]
    error: str = ""
    details: str = ""
    duration_ms: int = Field(default=0, alias="durationMs", ge=0)

    model_config = {"populate_by_name": True}


class Finding(BaseModel):
    id: str
    tool: str
    rule_id: str = Field(alias="ruleId")
    title: str
    severity: Literal["error", "warning", "information"]
    raw_severity: str = Field(alias="rawSeverity")
    category: str
    cwe: str = ""
    file: str
    start_line: int = Field(alias="startLine", ge=0)
    start_column: int = Field(alias="startColumn", ge=0)
    end_line: int = Field(alias="endLine", ge=0)
    end_column: int = Field(alias="endColumn", ge=0)
    help_uri: str = Field(default="", alias="helpUri")

    model_config = {"populate_by_name": True, "extra": "allow"}


class Correlation(BaseModel):
    id: str
    type: Literal["same-location", "shared-cwe", "dependency-match", "endpoint-source"]
    confidence: Literal["high", "medium", "low"]
    title: str
    reason: str
    tools: list[str]
    cwes: list[str] = Field(default_factory=list)
    finding_ids: list[str] = Field(alias="findingIds")
    count: int = Field(ge=2)

    model_config = {"populate_by_name": True}


class ScanResult(BaseModel):
    workspace: str
    findings: list[Finding]
    scanners: list[ScannerStatus]
    correlations: list[Correlation] = Field(default_factory=list)
    finished_at: datetime = Field(default_factory=lambda: datetime.now(UTC))


class StoredScan(BaseModel):
    scan_id: int
    result: ScanResult


class ScanListItem(BaseModel):
    scan_id: int
    workspace: str
    finding_count: int
    scanner_count: int
    finished_at: datetime


class FindingStatusUpdate(BaseModel):
    status: Literal[
        "new", "triaged", "probable", "confirmed", "fixed", "validated",
        "false_positive", "accepted"
    ]
    actor: str = Field(default="local-user", min_length=1, max_length=100)
    comment: str = Field(default="", max_length=1000)

    @model_validator(mode="after")
    def justification_required(self):
        if self.status in {"false_positive", "accepted"} and not self.comment.strip():
            raise ValueError("A justification is required for false_positive and accepted")
        return self


class AuditEvent(BaseModel):
    event_id: int
    created_at: datetime
    scan_id: int | None = None
    finding_id: str | None = None
    action: str
    actor: str
    comment: str = ""
    category: str | None = None
    actor_type: str | None = None
    result: str | None = None
    project: str | None = None
    resource: str | None = None
    resource_type: str | None = None
    reason: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)


class AuditEventCreate(BaseModel):
    scan_id: int | None = Field(default=None, ge=0)
    finding_id: str | None = Field(default=None, max_length=500)
    action: str = Field(min_length=1, max_length=100)
    actor: str = Field(default="Security Center", min_length=1, max_length=100)
    comment: str = Field(default="", max_length=1000)
    category: str | None = Field(default=None, max_length=50)
    actor_type: str | None = Field(default=None, max_length=50)
    result: str | None = Field(default=None, max_length=50)
    project: str | None = Field(default=None, max_length=500)
    resource: str | None = Field(default=None, max_length=1000)
    resource_type: str | None = Field(default=None, max_length=50)
    reason: str | None = Field(default=None, max_length=1000)
    metadata: dict[str, Any] = Field(default_factory=dict)

    @model_validator(mode="after")
    def sensitive_action_requires_context(self):
        if self.action.endswith(":authorized") and not self.comment.strip():
            raise ValueError("A justification is required for authorization events")
        self.metadata = _redact_audit_metadata(self.metadata)
        return self


_AUDIT_SENSITIVE_KEYS = {"authorization", "cookie", "password", "passwd", "secret", "token", "api_key", "apikey", "private_key"}


def _redact_audit_metadata(value: Any, key: str = "") -> Any:
    normalized_key = key.lower().replace("-", "_")
    if any(sensitive in normalized_key for sensitive in _AUDIT_SENSITIVE_KEYS):
        return "[REDACTED]"
    if isinstance(value, dict):
        return {name: _redact_audit_metadata(item, name) for name, item in value.items()}
    if isinstance(value, list):
        return [_redact_audit_metadata(item) for item in value]
    return value


class DashboardSummary(BaseModel):
    scan_id: int | None = None
    workspace: str = ""
    total: int = 0
    by_tool: dict[str, int] = Field(default_factory=dict)
    by_severity: dict[str, int] = Field(default_factory=dict)
    scanners: list[ScannerStatus] = Field(default_factory=list)
    finished_at: datetime | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)


class HttpRequestRecord(BaseModel):
    method: str
    url: str
    headers: dict[str, str] = Field(default_factory=dict)
    body: str = ""
    sensitive_headers: list[str] = Field(default_factory=list)

    @field_validator("url")
    @classmethod
    def local_url_only(cls, value: str) -> str:
        parsed = urlparse(value)
        if parsed.scheme not in {"http", "https"}:
            raise ValueError("Only HTTP and HTTPS requests are supported")
        if parsed.hostname not in {"127.0.0.1", "localhost", "::1", "host.docker.internal"}:
            raise ValueError("The MVP accepts local HTTP targets only")
        return value


class HttpResponseRecord(BaseModel):
    status_code: int = Field(alias="statusCode", ge=100, le=599)
    headers: dict[str, str] = Field(default_factory=dict)
    body: str = ""
    body_sha256: str = Field(default="", alias="bodySha256")

    model_config = {"populate_by_name": True}


class HttpScenarioCreate(BaseModel):
    name: str = Field(min_length=1, max_length=200)
    source: Literal["har", "burp", "zap", "manual"]
    request: HttpRequestRecord
    response: HttpResponseRecord | None = None
    tags: list[str] = Field(default_factory=list)


class StoredHttpScenario(HttpScenarioCreate):
    scenario_id: int
    created_at: datetime
