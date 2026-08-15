import hashlib
import json
import sqlite3
from pathlib import Path

from datetime import UTC, datetime

from .schemas import AuditEvent, AuditEventCreate, HttpScenarioCreate, ScanListItem, ScanResult, StoredHttpScenario, StoredScan


class ScanRepository:
    def __init__(self, database_path: Path) -> None:
        self.database_path = database_path

    def initialize(self) -> None:
        self.database_path.parent.mkdir(parents=True, exist_ok=True)
        with sqlite3.connect(self.database_path) as connection:
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS scan_runs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    created_at TEXT NOT NULL,
                    workspace TEXT NOT NULL,
                    payload TEXT NOT NULL
                )
                """
            )
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS http_scenarios (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    created_at TEXT NOT NULL,
                    name TEXT NOT NULL,
                    source TEXT NOT NULL,
                    payload TEXT NOT NULL
                )
                """
            )
            columns = {row[1] for row in connection.execute("PRAGMA table_info(http_scenarios)")}
            if "fingerprint" not in columns:
                connection.execute("ALTER TABLE http_scenarios ADD COLUMN fingerprint TEXT")
            connection.execute(
                "CREATE INDEX IF NOT EXISTS idx_http_scenarios_fingerprint ON http_scenarios(fingerprint)"
            )
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS audit_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    created_at TEXT NOT NULL,
                    scan_id INTEGER NOT NULL,
                    finding_id TEXT NOT NULL,
                    action TEXT NOT NULL,
                    actor TEXT NOT NULL,
                    comment TEXT NOT NULL DEFAULT ''
                )
                """
            )
            audit_columns = {row[1] for row in connection.execute("PRAGMA table_info(audit_events)")}
            audit_additions = {
                "category": "TEXT", "actor_type": "TEXT", "result": "TEXT", "project": "TEXT",
                "resource": "TEXT", "resource_type": "TEXT", "reason": "TEXT", "metadata_json": "TEXT NOT NULL DEFAULT '{}'",
            }
            for column, definition in audit_additions.items():
                if column not in audit_columns:
                    connection.execute(f"ALTER TABLE audit_events ADD COLUMN {column} {definition}")

    def save(self, result: ScanResult) -> int:
        payload = result.model_dump_json(by_alias=True)
        with sqlite3.connect(self.database_path) as connection:
            cursor = connection.execute(
                "INSERT INTO scan_runs(created_at, workspace, payload) VALUES (?, ?, ?)",
                (result.finished_at.isoformat(), result.workspace, payload),
            )
            return int(cursor.lastrowid)

    def latest(self) -> StoredScan | None:
        with sqlite3.connect(self.database_path) as connection:
            row = connection.execute(
                "SELECT id, payload FROM scan_runs ORDER BY id DESC LIMIT 1"
            ).fetchone()
        if row is None:
            return None
        return StoredScan(scan_id=int(row[0]), result=ScanResult.model_validate(json.loads(row[1])))

    def get(self, scan_id: int) -> StoredScan | None:
        with sqlite3.connect(self.database_path) as connection:
            row = connection.execute(
                "SELECT id, payload FROM scan_runs WHERE id = ?", (scan_id,)
            ).fetchone()
        if row is None:
            return None
        return StoredScan(scan_id=int(row[0]), result=ScanResult.model_validate(json.loads(row[1])))

    def list_scans(self, limit: int = 50) -> list[ScanListItem]:
        with sqlite3.connect(self.database_path) as connection:
            rows = connection.execute(
                "SELECT id, workspace, payload FROM scan_runs ORDER BY id DESC LIMIT ?",
                (limit,),
            ).fetchall()
        items: list[ScanListItem] = []
        for scan_id, workspace, payload in rows:
            result = ScanResult.model_validate(json.loads(payload))
            items.append(ScanListItem(
                scan_id=int(scan_id),
                workspace=workspace,
                finding_count=len(result.findings),
                scanner_count=len(result.scanners),
                finished_at=result.finished_at,
            ))
        return items

    def update_finding_status(self, scan_id: int, finding_id: str, status: str, actor: str, comment: str) -> StoredScan | None:
        stored = self.get(scan_id)
        if stored is None:
            return None
        updated = False
        findings: list[dict] = []
        for finding in stored.result.findings:
            payload = finding.model_dump(by_alias=True)
            if finding.id == finding_id:
                payload["triageStatus"] = status
                payload["triageActor"] = actor
                payload["triageComment"] = comment
                payload["triageUpdatedAt"] = datetime.now(UTC).isoformat()
                updated = True
            findings.append(payload)
        if not updated:
            return None
        result_payload = stored.result.model_dump(by_alias=True)
        result_payload["findings"] = findings
        result = ScanResult.model_validate(result_payload)
        with sqlite3.connect(self.database_path) as connection:
            connection.execute(
                "UPDATE scan_runs SET payload = ? WHERE id = ?",
                (result.model_dump_json(by_alias=True), scan_id),
            )
            connection.execute(
                "INSERT INTO audit_events(created_at, scan_id, finding_id, action, actor, comment) VALUES (?, ?, ?, ?, ?, ?)",
                (datetime.now(UTC).isoformat(), scan_id, finding_id, f"status:{status}", actor, comment),
            )
        return StoredScan(scan_id=scan_id, result=result)

    def list_audit_events(self, limit: int = 200) -> list[AuditEvent]:
        with sqlite3.connect(self.database_path) as connection:
            rows = connection.execute(
                "SELECT id, created_at, scan_id, finding_id, action, actor, comment, category, actor_type, result, project, resource, resource_type, reason, metadata_json FROM audit_events ORDER BY id DESC LIMIT ?",
                (limit,),
            ).fetchall()
        return [AuditEvent(
            event_id=row[0], created_at=datetime.fromisoformat(row[1]), scan_id=row[2] or None, finding_id=row[3] or None,
            action=row[4], actor=row[5], comment=row[6], category=row[7], actor_type=row[8], result=row[9],
            project=row[10], resource=row[11], resource_type=row[12], reason=row[13],
            metadata=json.loads(row[14] or "{}"),
        ) for row in rows]

    def create_audit_event(self, event: AuditEventCreate) -> AuditEvent:
        created_at = datetime.now(UTC)
        with sqlite3.connect(self.database_path) as connection:
            cursor = connection.execute(
                """INSERT INTO audit_events(
                    created_at, scan_id, finding_id, action, actor, comment, category, actor_type, result,
                    project, resource, resource_type, reason, metadata_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (created_at.isoformat(), event.scan_id or 0, event.finding_id or "", event.action, event.actor, event.comment,
                 event.category, event.actor_type, event.result, event.project, event.resource, event.resource_type,
                 event.reason, json.dumps(event.metadata, ensure_ascii=False)),
            )
            event_id = int(cursor.lastrowid)
        return AuditEvent(event_id=event_id, created_at=created_at, **event.model_dump())

    def save_http_scenario(self, scenario: HttpScenarioCreate) -> StoredHttpScenario:
        created_at = datetime.now(UTC)
        payload = scenario.model_dump_json(by_alias=True)
        response = scenario.response
        identity = "\n".join([
            scenario.request.method.upper(), scenario.request.url, scenario.request.body,
            str(response.status_code if response else ""), response.body_sha256 if response else "",
        ])
        fingerprint = hashlib.sha256(identity.encode("utf-8")).hexdigest()
        with sqlite3.connect(self.database_path) as connection:
            existing = connection.execute(
                "SELECT id, created_at, payload FROM http_scenarios WHERE fingerprint = ? ORDER BY id DESC LIMIT 1",
                (fingerprint,),
            ).fetchone()
            if existing is not None:
                stored = HttpScenarioCreate.model_validate(json.loads(existing[2]))
                return StoredHttpScenario(
                    scenario_id=int(existing[0]), created_at=datetime.fromisoformat(existing[1]),
                    **stored.model_dump(),
                )
            cursor = connection.execute(
                "INSERT INTO http_scenarios(created_at, name, source, payload, fingerprint) VALUES (?, ?, ?, ?, ?)",
                (created_at.isoformat(), scenario.name, scenario.source, payload, fingerprint),
            )
            scenario_id = int(cursor.lastrowid)
        return StoredHttpScenario(
            scenario_id=scenario_id,
            created_at=created_at,
            **scenario.model_dump(),
        )

    def list_http_scenarios(self, limit: int = 100) -> list[StoredHttpScenario]:
        with sqlite3.connect(self.database_path) as connection:
            rows = connection.execute(
                "SELECT id, created_at, payload FROM http_scenarios ORDER BY id DESC LIMIT ?",
                (limit,),
            ).fetchall()
        return [
            StoredHttpScenario(
                scenario_id=int(row[0]),
                created_at=datetime.fromisoformat(row[1]),
                **HttpScenarioCreate.model_validate(json.loads(row[2])).model_dump(),
            )
            for row in rows
        ]
