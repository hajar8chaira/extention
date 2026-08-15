import os
import hmac
from html import escape
from contextlib import asynccontextmanager
from datetime import UTC, datetime
from pathlib import Path

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse

from .database import ScanRepository
from .schemas import (
    AuditEvent, AuditEventCreate, DashboardSummary, FindingStatusUpdate, HttpScenarioCreate, ScanListItem,
    ScanResult, StoredHttpScenario, StoredScan,
)


database_path = Path(os.getenv("SECURITY_CENTER_DB", "data/security-center.db"))
repository = ScanRepository(database_path)
burp_last_seen: datetime | None = None


@asynccontextmanager
async def lifespan(_: FastAPI):
    repository.initialize()
    yield


app = FastAPI(
    title="Security Center Local API",
    version="0.1.0",
    description="Backend local de normalisation, stockage et corrélation des scans.",
    lifespan=lifespan,
)


@app.middleware("http")
async def require_api_key(request: Request, call_next):
    """Protects API routes when SECURITY_CENTER_API_KEY is configured."""
    expected = os.getenv("SECURITY_CENTER_API_KEY", "")
    if request.url.path.startswith("/api/v1/") and expected:
        supplied = request.headers.get("x-security-center-key", "")
        if not hmac.compare_digest(supplied, expected):
            return JSONResponse(status_code=401, content={"detail": "Invalid or missing Security Center API key"})
    return await call_next(request)


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok", "service": "security-center-backend"}


@app.post("/api/v1/scans/results", response_model=StoredScan, status_code=201)
def save_scan(result: ScanResult) -> StoredScan:
    scan_id = repository.save(result)
    return StoredScan(scan_id=scan_id, result=result)


@app.get("/api/v1/scans/latest", response_model=StoredScan | None)
def latest_scan() -> StoredScan | None:
    return repository.latest()


@app.get("/api/v1/scans", response_model=list[ScanListItem])
def list_scans(limit: int = 50) -> list[ScanListItem]:
    return repository.list_scans(max(1, min(limit, 200)))


@app.get("/api/v1/scans/{scan_id}", response_model=StoredScan)
def get_scan(scan_id: int) -> StoredScan:
    stored = repository.get(scan_id)
    if stored is None:
        raise HTTPException(status_code=404, detail="Scan not found")
    return stored


@app.patch("/api/v1/scans/{scan_id}/findings/{finding_id}/status", response_model=StoredScan)
def update_finding_status(scan_id: int, finding_id: str, update: FindingStatusUpdate) -> StoredScan:
    stored = repository.update_finding_status(scan_id, finding_id, update.status, update.actor, update.comment)
    if stored is None:
        raise HTTPException(status_code=404, detail="Scan or finding not found")
    return stored


@app.get("/api/v1/audit-events", response_model=list[AuditEvent])
def list_audit_events(limit: int = 200) -> list[AuditEvent]:
    return repository.list_audit_events(max(1, min(limit, 1000)))


@app.post("/api/v1/audit-events", response_model=AuditEvent, status_code=201)
def create_audit_event(event: AuditEventCreate) -> AuditEvent:
    return repository.create_audit_event(event)


@app.get("/api/v1/scans/{scan_id}/export.json", response_model=StoredScan)
def export_scan_json(scan_id: int) -> StoredScan:
    return get_scan(scan_id)


@app.get("/api/v1/scans/{scan_id}/export.html", response_class=HTMLResponse)
def export_scan_html(scan_id: int) -> HTMLResponse:
    stored = get_scan(scan_id)
    findings = "".join(
        "<tr>"
        f"<td>{escape(finding.tool)}</td>"
        f"<td>{escape(finding.raw_severity)}</td>"
        f"<td>{escape(finding.title)}</td>"
        f"<td>{escape(finding.file)}:{finding.start_line + 1}</td>"
        f"<td>{escape(str(getattr(finding, 'triageStatus', 'new')))}</td>"
        "</tr>"
        for finding in stored.result.findings
    ) or '<tr><td colspan="5">Aucun résultat</td></tr>'
    html = f"""<!doctype html><html lang="fr"><head><meta charset="utf-8">
<title>Security Center — scan {stored.scan_id}</title>
<style>body{{font:14px system-ui;margin:32px;color:#1f2328}}table{{border-collapse:collapse;width:100%}}th,td{{border:1px solid #d0d7de;padding:8px;text-align:left}}th{{background:#f6f8fa}}</style>
</head><body><h1>Rapport Security Center</h1>
<p>Scan #{stored.scan_id} — {escape(stored.result.workspace)} — {stored.result.finished_at.isoformat()}</p>
<p>{len(stored.result.findings)} résultat(s), {len(stored.result.correlations)} corrélation(s).</p>
<table><thead><tr><th>Outil</th><th>Sévérité</th><th>Résultat</th><th>Emplacement</th><th>Statut</th></tr></thead>
<tbody>{findings}</tbody></table></body></html>"""
    return HTMLResponse(html, headers={"Content-Disposition": f'attachment; filename="security-center-scan-{scan_id}.html"'})


@app.get("/api/v1/dashboard", response_model=DashboardSummary)
def dashboard() -> DashboardSummary:
    stored = repository.latest()
    if stored is None:
        return DashboardSummary()

    by_tool: dict[str, int] = {}
    by_severity: dict[str, int] = {}
    for finding in stored.result.findings:
        by_tool[finding.tool] = by_tool.get(finding.tool, 0) + 1
        by_severity[finding.raw_severity] = by_severity.get(finding.raw_severity, 0) + 1

    return DashboardSummary(
        scan_id=stored.scan_id,
        workspace=stored.result.workspace,
        total=len(stored.result.findings),
        by_tool=by_tool,
        by_severity=by_severity,
        scanners=stored.result.scanners,
        finished_at=stored.result.finished_at,
        metadata={
            "correlations": len(stored.result.correlations),
            "high_confidence_correlations": sum(
                1 for correlation in stored.result.correlations
                if correlation.confidence == "high"
            ),
        },
    )


@app.post("/api/v1/http-scenarios", response_model=StoredHttpScenario, status_code=201)
def save_http_scenario(scenario: HttpScenarioCreate) -> StoredHttpScenario:
    return repository.save_http_scenario(scenario)


@app.post("/api/v1/integrations/burp/requests", response_model=StoredHttpScenario, status_code=201)
def receive_burp_request(scenario: HttpScenarioCreate) -> StoredHttpScenario:
    """Receives an explicitly selected Burp request from the local Montoya connector."""
    burp_scenario = scenario.model_copy(update={"source": "burp"})
    return repository.save_http_scenario(burp_scenario)


@app.get("/api/v1/integrations/burp/status")
def burp_connector_status() -> dict[str, str | int | bool | None]:
    scenarios = repository.list_http_scenarios(500)
    connected = (
        burp_last_seen is not None
        and (datetime.now(UTC) - burp_last_seen).total_seconds() < 15
    )
    return {
        "status": "ready",
        "connector": "security-center-burp",
        "connected": connected,
        "last_seen": burp_last_seen.isoformat() if burp_last_seen else None,
        "received_requests": sum(1 for scenario in scenarios if scenario.source == "burp"),
    }


@app.post("/api/v1/integrations/burp/heartbeat")
def burp_connector_heartbeat() -> dict[str, str]:
    global burp_last_seen
    burp_last_seen = datetime.now(UTC)
    return {"status": "connected", "last_seen": burp_last_seen.isoformat()}


@app.get("/api/v1/http-scenarios", response_model=list[StoredHttpScenario])
def list_http_scenarios(limit: int = 100) -> list[StoredHttpScenario]:
    return repository.list_http_scenarios(max(1, min(limit, 500)))
