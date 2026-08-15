from datetime import UTC, datetime

from fastapi.testclient import TestClient

from app.database import ScanRepository
from app import main


def finding(finding_id: str = "finding-1", title: str = "SQL <script>alert(1)</script>") -> dict:
    return {
        "id": finding_id,
        "tool": "Semgrep",
        "ruleId": "javascript.lang.security.audit.sqli",
        "title": title,
        "severity": "error",
        "rawSeverity": "HIGH",
        "category": "sql-injection",
        "cwe": "CWE-89",
        "file": "routes/search.ts",
        "startLine": 10,
        "startColumn": 2,
        "endLine": 10,
        "endColumn": 20,
        "helpUri": "https://semgrep.dev/rule",
        "triageStatus": "new",
    }


def scan_payload() -> dict:
    return {
        "workspace": "C:/demo/<juice-shop>",
        "findings": [finding()],
        "scanners": [{
            "tool": "Semgrep", "status": "completed", "details": "1 résultat", "durationMs": 1250
        }],
        "correlations": [],
        "finished_at": datetime.now(UTC).isoformat(),
    }


def client(tmp_path) -> TestClient:
    main.repository = ScanRepository(tmp_path / "security-center.db")
    main.repository.initialize()
    return TestClient(main.app)


def test_health_and_empty_dashboard(tmp_path):
    with client(tmp_path) as api:
        assert api.get("/health").json()["status"] == "ok"
        assert api.get("/api/v1/dashboard").json()["total"] == 0


def test_api_key_protects_api_but_keeps_health_public(tmp_path, monkeypatch):
    monkeypatch.setenv("SECURITY_CENTER_API_KEY", "test-secret-key")
    with client(tmp_path) as api:
        assert api.get("/health").status_code == 200
        unauthorized = api.get("/api/v1/dashboard")
        assert unauthorized.status_code == 401
        assert api.get("/api/v1/dashboard", headers={"X-Security-Center-Key": "wrong"}).status_code == 401
        authorized = api.get("/api/v1/dashboard", headers={"X-Security-Center-Key": "test-secret-key"})
        assert authorized.status_code == 200


def test_scan_history_detail_and_exports(tmp_path):
    with client(tmp_path) as api:
        created = api.post("/api/v1/scans/results", json=scan_payload())
        assert created.status_code == 201, created.text
        scan_id = created.json()["scan_id"]

        history = api.get("/api/v1/scans").json()
        assert history[0]["scan_id"] == scan_id
        assert history[0]["finding_count"] == 1
        assert api.get(f"/api/v1/scans/{scan_id}").json()["result"]["findings"][0]["id"] == "finding-1"

        exported_json = api.get(f"/api/v1/scans/{scan_id}/export.json")
        assert exported_json.status_code == 200
        assert exported_json.json()["result"]["workspace"] == "C:/demo/<juice-shop>"

        exported_html = api.get(f"/api/v1/scans/{scan_id}/export.html")
        assert exported_html.status_code == 200
        assert "attachment" in exported_html.headers["content-disposition"]
        assert "SQL &lt;script&gt;alert(1)&lt;/script&gt;" in exported_html.text
        assert "<script>alert(1)</script>" not in exported_html.text


def test_persists_finding_status_and_rejects_unknown_values(tmp_path):
    with client(tmp_path) as api:
        scan_id = api.post("/api/v1/scans/results", json=scan_payload()).json()["scan_id"]
        updated = api.patch(
            f"/api/v1/scans/{scan_id}/findings/finding-1/status",
            json={"status": "confirmed"},
        )
        assert updated.status_code == 200
        assert updated.json()["result"]["findings"][0]["triageStatus"] == "confirmed"
        assert api.get(f"/api/v1/scans/{scan_id}").json()["result"]["findings"][0]["triageStatus"] == "confirmed"

        invalid = api.patch(
            f"/api/v1/scans/{scan_id}/findings/finding-1/status",
            json={"status": "invented"},
        )
        assert invalid.status_code == 422
        assert api.get("/api/v1/scans/999999").status_code == 404

        missing_justification = api.patch(
            f"/api/v1/scans/{scan_id}/findings/finding-1/status",
            json={"status": "false_positive", "actor": "reviewer"},
        )
        assert missing_justification.status_code == 422
        accepted = api.patch(
            f"/api/v1/scans/{scan_id}/findings/finding-1/status",
            json={"status": "accepted", "actor": "reviewer", "comment": "Risque validé jusqu'au prochain sprint."},
        )
        assert accepted.status_code == 200
        audit = api.get("/api/v1/audit-events").json()
        assert audit[0]["actor"] == "reviewer"
        assert audit[0]["action"] == "status:accepted"
        assert audit[0]["comment"] == "Risque validé jusqu'au prochain sprint."


def test_burp_accepts_only_local_requests_and_tracks_heartbeat(tmp_path):
    with client(tmp_path) as api:
        scenario = {
            "name": "GET /api/users",
            "source": "manual",
            "request": {"method": "GET", "url": "http://127.0.0.1:3000/api/users"},
        }
        received = api.post("/api/v1/integrations/burp/requests", json=scenario)
        assert received.status_code == 201
        assert received.json()["source"] == "burp"
        duplicate = api.post("/api/v1/integrations/burp/requests", json=scenario)
        assert duplicate.status_code == 201
        assert duplicate.json()["scenario_id"] == received.json()["scenario_id"]
        assert api.post("/api/v1/integrations/burp/heartbeat").status_code == 200
        status = api.get("/api/v1/integrations/burp/status").json()
        assert status["connected"] is True
        assert status["received_requests"] == 1

        scenario["request"]["url"] = "https://example.com/api/users"
        assert api.post("/api/v1/integrations/burp/requests", json=scenario).status_code == 422


def test_sensitive_audit_event_requires_actor_and_justification(tmp_path):
    with client(tmp_path) as api:
        missing_comment = api.post("/api/v1/audit-events", json={
            "finding_id": "zap:http://127.0.0.1:3000",
            "action": "zap:active:authorized",
            "actor": "reviewer",
            "comment": "",
        })
        assert missing_comment.status_code == 422
        created = api.post("/api/v1/audit-events", json={
            "finding_id": "zap:http://127.0.0.1:3000",
            "action": "zap:active:authorized",
            "actor": "reviewer",
            "comment": "Test local explicitement autorisé.",
        })
        assert created.status_code == 201
        assert created.json()["action"] == "zap:active:authorized"
        assert api.get("/api/v1/audit-events").json()[0]["actor"] == "reviewer"


def test_normalized_audit_event_is_additive_and_legacy_records_remain_readable(tmp_path):
    with client(tmp_path) as api:
        legacy = api.post("/api/v1/audit-events", json={
            "scan_id": 0,
            "finding_id": "zap:http://127.0.0.1:3000",
            "action": "zap:active:authorized",
            "actor": "reviewer",
            "comment": "Test local explicitement autorisé.",
        })
        assert legacy.status_code == 201
        assert legacy.json()["action"] == "zap:active:authorized"
        assert legacy.json()["metadata"] == {}

        normalized = api.post("/api/v1/audit-events", json={
            "action": "AI_FIX_REJECTED",
            "actor": "AI Remediation",
            "actor_type": "COMPONENT",
            "category": "AI_REMEDIATION",
            "result": "REJECTED",
            "resource": "src/users.js",
            "resource_type": "FILE",
            "reason": "ROOT_CAUSE_NOT_FIXED",
            "metadata": {"provider": "Ollama", "projectModified": False},
        })
        assert normalized.status_code == 201
        payload = normalized.json()
        assert payload["scan_id"] is None
        assert payload["finding_id"] is None
        assert payload["category"] == "AI_REMEDIATION"
        assert payload["metadata"]["projectModified"] is False

        events = api.get("/api/v1/audit-events").json()
        assert len(events) == 2
        assert events[1]["action"] == "zap:active:authorized"
