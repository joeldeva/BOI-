from __future__ import annotations

import ipaddress
import hashlib
import hmac
import json
import re
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Mapping
from urllib.parse import urlsplit

from fraudshield.core.database import Database
from fraudshield.core.errors import ConflictError, NotFoundError, ValidationError


SEVERITY_ORDER = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def new_id(prefix: str) -> str:
    return f"{prefix}_{uuid.uuid4().hex}"


def dumps(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=True)


def loads(value: str | None, default: Any = None) -> Any:
    if value is None:
        return default
    return json.loads(value)


def _analysis_from_row(row: Mapping[str, Any]) -> dict[str, Any]:
    item = dict(row)
    item["result"] = loads(item.pop("result_json"), None)
    return item


def _analysis_summary_from_row(row: Mapping[str, Any]) -> dict[str, Any]:
    item = dict(row)
    raw_result = item.pop("result_json", None)
    result = loads(raw_result, {}) if raw_result else {}
    item["analysis_id"] = item["id"]

    extraction = result.get("extraction", {}) if isinstance(result, dict) else {}
    app = extraction.get("app", {}) if isinstance(extraction, dict) else {}
    risk = result.get("risk", {}) if isinstance(result, dict) else {}
    coverage = extraction.get("coverage", {}) if isinstance(extraction, dict) else {}

    item["package_name"] = app.get("package_name")
    item["app_name"] = app.get("app_label") or app.get("app_name")
    item["static_score"] = risk.get("static_score")
    item["runtime_adjustment"] = risk.get("runtime_adjustment", 0)

    if coverage.get("dynamic") is True:
        item["dynamic_status"] = "completed"
    elif coverage.get("dynamic") is False:
        item["dynamic_status"] = "unavailable"
    else:
        item["dynamic_status"] = None

    return item


class AnalysisRepository:
    def __init__(self, db: Database) -> None:
        self.db = db

    def create(
        self,
        *,
        file_name: str,
        sha256: str,
        size_bytes: int,
        category: str,
        data_origin: str = "uploaded",
    ) -> dict[str, Any]:
        analysis_id = new_id("apk")
        now = utc_now()
        with self.db.transaction() as connection:
            connection.execute(
                """
                INSERT INTO analyses(
                    id,status,data_origin,file_name,sha256,size_bytes,category,created_at
                ) VALUES (?,?,?,?,?,?,?,?)
                """,
                (analysis_id, "pending", data_origin, file_name, sha256, size_bytes, category, now),
            )
        return self.get(analysis_id)

    def mark_running(self, analysis_id: str) -> None:
        with self.db.transaction() as connection:
            connection.execute(
                "UPDATE analyses SET status='running', started_at=? WHERE id=?",
                (utc_now(), analysis_id),
            )

    def complete(
        self,
        analysis_id: str,
        *,
        result: dict[str, Any],
        narrative: str,
        overall_score: int,
        severity: str,
        confidence: float,
        analysis_quality: str,
    ) -> dict[str, Any]:
        with self.db.transaction() as connection:
            cursor = connection.execute(
                """
                UPDATE analyses
                SET status='completed', completed_at=?, result_json=?, narrative=?, overall_score=?,
                    severity=?, confidence=?, analysis_quality=?, error_code=NULL, error_message=NULL
                WHERE id=?
                """,
                (
                    utc_now(),
                    dumps(result),
                    narrative,
                    int(overall_score),
                    severity,
                    float(confidence),
                    analysis_quality,
                    analysis_id,
                ),
            )
            if cursor.rowcount != 1:
                raise NotFoundError("analysis", analysis_id)
        return self.get(analysis_id)

    def fail(self, analysis_id: str, *, code: str, message: str) -> dict[str, Any]:
        with self.db.transaction() as connection:
            cursor = connection.execute(
                """
                UPDATE analyses
                SET status='failed', completed_at=?, error_code=?, error_message=?
                WHERE id=?
                """,
                (utc_now(), code, message[:1000], analysis_id),
            )
            if cursor.rowcount != 1:
                raise NotFoundError("analysis", analysis_id)
        return self.get(analysis_id)

    def get(self, analysis_id: str) -> dict[str, Any]:
        with self.db.connect() as connection:
            row = connection.execute("SELECT * FROM analyses WHERE id=?", (analysis_id,)).fetchone()
        if row is None:
            raise NotFoundError("analysis", analysis_id)
        return _analysis_from_row(row)

    def list(
        self,
        *,
        limit: int = 50,
        offset: int = 0,
        severity: str | None = None,
        status: str | None = None,
    ) -> tuple[list[dict[str, Any]], int]:
        clauses: list[str] = []
        values: list[Any] = []
        if severity:
            clauses.append("severity=?")
            values.append(severity)
        if status:
            clauses.append("status=?")
            values.append(status)
        where = f" WHERE {' AND '.join(clauses)}" if clauses else ""
        with self.db.connect() as connection:
            total_row = connection.execute(
                f"SELECT COUNT(*) AS total FROM analyses{where}", values
            ).fetchone()
            rows = connection.execute(
                f"""
                SELECT id,status,data_origin,file_name,sha256,size_bytes,category,created_at,started_at,
                       completed_at,overall_score,severity,confidence,analysis_quality,result_json,error_code,error_message
                FROM analyses{where} ORDER BY created_at DESC LIMIT ? OFFSET ?
                """,
                (*values, limit, offset),
            ).fetchall()
        return [_analysis_summary_from_row(row) for row in rows], int(total_row["total"])

    def summary(self) -> dict[str, int]:
        with self.db.connect() as connection:
            row = connection.execute(
                """
                SELECT
                    COUNT(*) AS total,
                    SUM(CASE WHEN status='completed' THEN 1 ELSE 0 END) AS completed,
                    SUM(CASE WHEN status='failed' THEN 1 ELSE 0 END) AS failed,
                    SUM(CASE WHEN severity='CRITICAL' THEN 1 ELSE 0 END) AS critical
                FROM analyses
                """
            ).fetchone()
        return {key: int(row[key] or 0) for key in row.keys()}

    def latest_completed(self) -> dict[str, Any]:
        with self.db.connect() as connection:
            row = connection.execute(
                "SELECT * FROM analyses WHERE status='completed' ORDER BY completed_at DESC LIMIT 1"
            ).fetchone()
        if row is None:
            raise NotFoundError("completed analysis", "latest")
        return _analysis_from_row(row)

    def cleanup_synthetic_records(self) -> dict[str, int]:
        """Safely cleans up any legacy synthetic records and orphaned indicators without touching uploaded analyses."""
        with self.db.transaction() as connection:
            rows = connection.execute("SELECT id FROM analyses WHERE data_origin = 'synthetic'").fetchall()
            synthetic_ids = [row["id"] for row in rows]

            deleted_sightings = 0
            deleted_indicators = 0
            deleted_analyses = 0

            if synthetic_ids:
                placeholders = ",".join("?" for _ in synthetic_ids)
                cursor = connection.execute(
                    f"DELETE FROM indicator_sightings WHERE source_analysis_id IN ({placeholders})",
                    synthetic_ids,
                )
                deleted_sightings = int(cursor.rowcount)

                cursor = connection.execute(
                    "DELETE FROM indicators WHERE id NOT IN (SELECT DISTINCT indicator_id FROM indicator_sightings)"
                )
                deleted_indicators = int(cursor.rowcount)

                cursor = connection.execute(
                    "DELETE FROM analyses WHERE data_origin = 'synthetic'"
                )
                deleted_analyses = int(cursor.rowcount)

            return {
                "deleted_sightings": deleted_sightings,
                "deleted_indicators": deleted_indicators,
                "deleted_analyses": deleted_analyses,
            }


def normalize_indicator(indicator_type: str, value: str) -> str:
    kind = indicator_type.strip().lower()
    raw = value.strip()
    if not raw:
        raise ValidationError("invalid_indicator", "Indicator value cannot be empty")
    if kind in {"domain", "hostname"}:
        candidate = raw
        if "://" in candidate:
            candidate = urlsplit(candidate).hostname or ""
        candidate = candidate.rstrip(".").lower()
        if not candidate or "." not in candidate:
            raise ValidationError("invalid_domain", "Domain indicator is invalid", value=raw)
        return candidate.encode("idna").decode("ascii")
    if kind == "url":
        parsed = urlsplit(raw)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            raise ValidationError("invalid_url", "URL indicator must be HTTP(S)", value=raw)
        return raw
    if kind == "ip":
        try:
            return str(ipaddress.ip_address(raw))
        except ValueError as exc:
            raise ValidationError("invalid_ip", "IP indicator is invalid", value=raw) from exc
    if kind in {"sha256", "apk_sha256", "certificate_sha256"}:
        compact = raw.lower().replace(":", "")
        if not re.fullmatch(r"[0-9a-f]{64}", compact):
            raise ValidationError("invalid_sha256", "SHA-256 indicator must contain 64 hex characters")
        return compact
    if kind in {"package", "package_name"}:
        normalized = raw.lower()
        if not re.fullmatch(r"[a-z0-9_]+(?:\.[a-z0-9_]+)+", normalized):
            raise ValidationError("invalid_package", "Android package name is invalid", value=raw)
        return normalized
    return raw.lower()


class IndicatorRepository:
    def __init__(self, db: Database) -> None:
        self.db = db

    def upsert(
        self,
        *,
        indicator_type: str,
        value: str,
        severity: str,
        confidence: float,
        description: str = "",
        source_analysis_id: str | None = None,
        metadata: dict[str, Any] | None = None,
        context: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        kind = indicator_type.strip().lower()
        normalized = normalize_indicator(kind, value)
        sev = severity.upper()
        if sev not in SEVERITY_ORDER:
            raise ValidationError("invalid_severity", "Severity must be LOW, MEDIUM, HIGH, or CRITICAL")
        confidence = min(1.0, max(0.0, float(confidence)))
        now = utc_now()
        with self.db.transaction() as connection:
            existing = connection.execute(
                "SELECT * FROM indicators WHERE type=? AND normalized_value=?",
                (kind, normalized),
            ).fetchone()
            if existing is None:
                indicator_id = new_id("ioc")
                connection.execute(
                    """
                    INSERT INTO indicators(
                        id,type,normalized_value,display_value,severity,confidence,first_seen,last_seen,
                        sightings_count,description,metadata_json
                    ) VALUES (?,?,?,?,?,?,?,?,?,?,?)
                    """,
                    (
                        indicator_id,
                        kind,
                        normalized,
                        value.strip(),
                        sev,
                        confidence,
                        now,
                        now,
                        1,
                        description[:1000],
                        dumps(metadata or {}),
                    ),
                )
            else:
                indicator_id = existing["id"]
                merged_severity = max((existing["severity"], sev), key=SEVERITY_ORDER.get)
                merged_confidence = max(float(existing["confidence"]), confidence)
                connection.execute(
                    """
                    UPDATE indicators
                    SET last_seen=?, severity=?, confidence=?, description=CASE WHEN ?<>'' THEN ? ELSE description END
                    WHERE id=?
                    """,
                    (now, merged_severity, merged_confidence, description, description[:1000], indicator_id),
                )
            sighting = connection.execute(
                """
                SELECT id FROM indicator_sightings
                WHERE indicator_id=?
                  AND (source_analysis_id=? OR (source_analysis_id IS NULL AND ? IS NULL))
                """,
                (indicator_id, source_analysis_id, source_analysis_id),
            ).fetchone()
            if sighting is None:
                connection.execute(
                    """
                    INSERT INTO indicator_sightings(id,indicator_id,source_analysis_id,seen_at,context_json)
                    VALUES (?,?,?,?,?)
                    """,
                    (new_id("sighting"), indicator_id, source_analysis_id, now, dumps(context or {})),
                )
                if existing is not None:
                    connection.execute(
                        "UPDATE indicators SET sightings_count=sightings_count+1 WHERE id=?",
                        (indicator_id,),
                    )
        return self.get(indicator_id)

    def get(self, indicator_id: str) -> dict[str, Any]:
        with self.db.connect() as connection:
            row = connection.execute("SELECT * FROM indicators WHERE id=?", (indicator_id,)).fetchone()
        if row is None:
            raise NotFoundError("indicator", indicator_id)
        item = dict(row)
        item["metadata"] = loads(item.pop("metadata_json"), {})
        return item

    def list(
        self,
        *,
        query: str | None = None,
        indicator_type: str | None = None,
        severity: str | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> tuple[list[dict[str, Any]], int]:
        clauses: list[str] = []
        values: list[Any] = []
        if query:
            clauses.append("(normalized_value LIKE ? OR display_value LIKE ? OR description LIKE ?)")
            match = f"%{query.strip()}%"
            values.extend((match, match, match))
        if indicator_type:
            clauses.append("type=?")
            values.append(indicator_type.lower())
        if severity:
            clauses.append("severity=?")
            values.append(severity.upper())
        where = f" WHERE {' AND '.join(clauses)}" if clauses else ""
        with self.db.connect() as connection:
            total_row = connection.execute(
                f"SELECT COUNT(*) AS total FROM indicators{where}", values
            ).fetchone()
            rows = connection.execute(
                f"SELECT * FROM indicators{where} ORDER BY last_seen DESC LIMIT ? OFFSET ?",
                (*values, limit, offset),
            ).fetchall()
        items = []
        for row in rows:
            item = dict(row)
            item["metadata"] = loads(item.pop("metadata_json"), {})
            items.append(item)
        return items, int(total_row["total"])

    def values_by_type(self) -> dict[str, set[str]]:
        result: dict[str, set[str]] = {}
        with self.db.connect() as connection:
            rows = connection.execute("SELECT type, normalized_value FROM indicators").fetchall()
        for row in rows:
            result.setdefault(row["type"], set()).add(row["normalized_value"])
        return result

    def count(self) -> int:
        with self.db.connect() as connection:
            row = connection.execute("SELECT COUNT(*) AS total FROM indicators").fetchone()
            return int(row["total"])


class AuditRepository:
    """Append-only, HMAC-chained security audit events.

    The chain makes accidental or unauthorized row edits detectable. Production
    deployments must also export these events to the bank's immutable/WORM log
    destination because a database administrator can rewrite both rows and state.
    """

    def __init__(
        self,
        db: Database,
        hmac_key: str,
        *,
        key_id: str = "v1",
        previous_keys: Mapping[str, str] | None = None,
    ) -> None:
        self.db = db
        self.key_id = key_id
        self._key = (hmac_key or "development-only-audit-integrity-key").encode("utf-8")
        self._keys = {
            key_id: self._key,
            **{
                previous_id: previous_secret.encode("utf-8")
                for previous_id, previous_secret in (previous_keys or {}).items()
                if previous_id != key_id
            },
        }

    @staticmethod
    def _hash_with(key: bytes, value: str) -> str:
        return hmac.new(key, value.encode("utf-8"), hashlib.sha256).hexdigest()

    def _hash(self, value: str) -> str:
        return self._hash_with(self._key, value)

    @staticmethod
    def _from_row(row: Mapping[str, Any]) -> dict[str, Any]:
        item = dict(row)
        item["roles"] = loads(item.pop("roles_json"), [])
        item["details"] = loads(item.pop("details_json"), {})
        return item

    def append(
        self,
        *,
        request_id: str,
        actor_id: str,
        auth_type: str,
        roles: list[str] | tuple[str, ...],
        action: str,
        resource_type: str,
        resource_id: str | None,
        method: str,
        path: str,
        status_code: int,
        client_address: str,
        user_agent: str,
        details: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        occurred_at = utc_now()
        event_id = new_id("audit")
        normalized_roles = sorted({str(role)[:64] for role in roles})
        safe_details = details or {}
        with self.db.transaction() as connection:
            lock_suffix = " FOR UPDATE" if self.db.backend == "postgresql" else ""
            state = connection.execute(
                f"SELECT sequence_number,event_hash FROM audit_chain_state WHERE id=1{lock_suffix}"
            ).fetchone()
            sequence_number = int(state["sequence_number"]) + 1
            previous_hash = str(state["event_hash"])
            integrity_payload = {
                "id": event_id,
                "sequence_number": sequence_number,
                "occurred_at": occurred_at,
                "request_id": request_id[:128],
                "actor_id": actor_id[:256],
                "auth_type": auth_type[:32],
                "roles": normalized_roles,
                "action": action[:128],
                "resource_type": resource_type[:128],
                "resource_id": resource_id[:256] if resource_id else None,
                "method": method[:16],
                "path": path[:1000],
                "status_code": int(status_code),
                "client_address_hash": self._hash(client_address or "unknown"),
                "user_agent_hash": self._hash(user_agent or "unknown"),
                "details": safe_details,
                "previous_hash": previous_hash,
                "audit_key_id": self.key_id,
            }
            event_hash = self._hash(dumps(integrity_payload))
            connection.execute(
                """
                INSERT INTO audit_events(
                    id,sequence_number,occurred_at,request_id,actor_id,auth_type,roles_json,
                    action,resource_type,resource_id,method,path,status_code,client_address_hash,
                    user_agent_hash,details_json,previous_hash,event_hash,audit_key_id
                ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                """,
                (
                    event_id,
                    sequence_number,
                    occurred_at,
                    request_id[:128],
                    actor_id[:256],
                    auth_type[:32],
                    dumps(normalized_roles),
                    action[:128],
                    resource_type[:128],
                    resource_id[:256] if resource_id else None,
                    method[:16],
                    path[:1000],
                    int(status_code),
                    integrity_payload["client_address_hash"],
                    integrity_payload["user_agent_hash"],
                    dumps(safe_details),
                    previous_hash,
                    event_hash,
                    self.key_id,
                ),
            )
            connection.execute(
                "UPDATE audit_chain_state SET sequence_number=?, event_hash=? WHERE id=1",
                (sequence_number, event_hash),
            )
        return self.get(event_id)

    def get(self, event_id: str) -> dict[str, Any]:
        with self.db.connect() as connection:
            row = connection.execute("SELECT * FROM audit_events WHERE id=?", (event_id,)).fetchone()
        if row is None:
            raise NotFoundError("audit event", event_id)
        return self._from_row(row)

    def list(
        self,
        *,
        limit: int = 100,
        offset: int = 0,
        actor_id: str | None = None,
        request_id: str | None = None,
    ) -> tuple[list[dict[str, Any]], int]:
        clauses: list[str] = []
        values: list[Any] = []
        if actor_id:
            clauses.append("actor_id=?")
            values.append(actor_id)
        if request_id:
            clauses.append("request_id=?")
            values.append(request_id)
        where = f" WHERE {' AND '.join(clauses)}" if clauses else ""
        with self.db.connect() as connection:
            total_row = connection.execute(
                f"SELECT COUNT(*) AS total FROM audit_events{where}", values
            ).fetchone()
            rows = connection.execute(
                f"SELECT * FROM audit_events{where} "
                "ORDER BY sequence_number DESC LIMIT ? OFFSET ?",
                (*values, limit, offset),
            ).fetchall()
        return [self._from_row(row) for row in rows], int(total_row["total"])

    def verify_chain(self) -> dict[str, Any]:
        with self.db.connect() as connection:
            state = connection.execute(
                "SELECT sequence_number,event_hash FROM audit_chain_state WHERE id=1"
            ).fetchone()
            target_sequence = int(state["sequence_number"])
            cursor = connection.execute(
                "SELECT * FROM audit_events WHERE sequence_number<=? ORDER BY sequence_number ASC",
                (target_sequence,),
            )
            previous_hash = ""
            expected_sequence = 1
            verified_count = 0
            while rows := cursor.fetchmany(1000):
                for row in rows:
                    item = self._from_row(row)
                    audit_key_id = str(item.get("audit_key_id") or "legacy")
                    verification_key = self._keys.get(audit_key_id)
                    if verification_key is None and audit_key_id == "legacy":
                        verification_key = self._key
                    if verification_key is None:
                        return {
                            "valid": False,
                            "event_count": target_sequence,
                            "verified_count": verified_count,
                            "first_invalid_sequence": item["sequence_number"],
                            "reason": "audit_key_unavailable",
                            "audit_key_id": audit_key_id,
                        }
                    integrity_payload = {
                        "id": item["id"],
                        "sequence_number": item["sequence_number"],
                        "occurred_at": item["occurred_at"],
                        "request_id": item["request_id"],
                        "actor_id": item["actor_id"],
                        "auth_type": item["auth_type"],
                        "roles": item["roles"],
                        "action": item["action"],
                        "resource_type": item["resource_type"],
                        "resource_id": item["resource_id"],
                        "method": item["method"],
                        "path": item["path"],
                        "status_code": item["status_code"],
                        "client_address_hash": item["client_address_hash"],
                        "user_agent_hash": item["user_agent_hash"],
                        "details": item["details"],
                        "previous_hash": previous_hash,
                    }
                    if audit_key_id != "legacy":
                        integrity_payload["audit_key_id"] = audit_key_id
                    calculated = self._hash_with(verification_key, dumps(integrity_payload))
                    if (
                        int(item["sequence_number"]) != expected_sequence
                        or item["previous_hash"] != previous_hash
                        or not hmac.compare_digest(item["event_hash"], calculated)
                    ):
                        return {
                            "valid": False,
                            "event_count": target_sequence,
                            "verified_count": verified_count,
                            "first_invalid_sequence": item["sequence_number"],
                            "reason": "chain_mismatch",
                        }
                    previous_hash = item["event_hash"]
                    expected_sequence += 1
                    verified_count += 1
        state_valid = target_sequence == verified_count and hmac.compare_digest(
            str(state["event_hash"]), previous_hash
        )
        return {
            "valid": state_valid,
            "event_count": verified_count,
            "verified_count": verified_count,
            "first_invalid_sequence": None if state_valid else expected_sequence,
            "head_hash": previous_hash,
        }


class JobRepository:
    """Durable database queue used by stateless worker processes."""

    def __init__(self, db: Database) -> None:
        self.db = db

    @staticmethod
    def _from_row(row: Mapping[str, Any]) -> dict[str, Any]:
        item = dict(row)
        item["payload"] = loads(item.pop("payload_json"), {})
        item["result"] = loads(item.pop("result_json"), None)
        return item

    def enqueue(
        self,
        *,
        kind: str,
        payload: dict[str, Any],
        created_by: str,
        priority: int = 100,
        max_attempts: int = 3,
        idempotency_key: str | None = None,
    ) -> tuple[dict[str, Any], bool]:
        if kind != "apk_analysis":
            raise ValidationError("invalid_job_kind", "Unsupported job kind")
        if idempotency_key:
            with self.db.connect() as connection:
                existing = connection.execute(
                    "SELECT * FROM jobs WHERE idempotency_key=?", (idempotency_key,)
                ).fetchone()
            if existing is not None:
                return self._idempotent_result(existing, kind=kind, payload=payload), False
        job_id = new_id("job")
        now = utc_now()
        try:
            with self.db.transaction() as connection:
                connection.execute(
                    """
                    INSERT INTO jobs(
                        id,kind,status,payload_json,priority,attempts,max_attempts,available_at,
                        created_by,created_at,idempotency_key
                    ) VALUES (?,?,?,?,?,?,?,?,?,?,?)
                    """,
                    (
                        job_id,
                        kind,
                        "queued",
                        dumps(payload),
                        max(0, min(1000, int(priority))),
                        0,
                        max(1, min(20, int(max_attempts))),
                        now,
                        created_by[:256],
                        now,
                        idempotency_key[:256] if idempotency_key else None,
                    ),
                )
        except Exception:
            if idempotency_key:
                existing = self.find_by_idempotency_key(idempotency_key)
                if existing is not None:
                    return self._idempotent_result(
                        existing, kind=kind, payload=payload
                    ), False
            raise
        return self.get(job_id), True

    def _idempotent_result(
        self,
        existing: Mapping[str, Any],
        *,
        kind: str,
        payload: dict[str, Any],
    ) -> dict[str, Any]:
        item = (
            self._from_row(existing)
            if "payload_json" in existing.keys()
            else dict(existing)
        )
        if item["kind"] != kind or dumps(item["payload"]) != dumps(payload):
            raise ConflictError(
                "idempotency_conflict",
                "Idempotency-Key was already used for a different request",
            )
        return item

    def get(self, job_id: str) -> dict[str, Any]:
        with self.db.connect() as connection:
            row = connection.execute("SELECT * FROM jobs WHERE id=?", (job_id,)).fetchone()
        if row is None:
            raise NotFoundError("job", job_id)
        return self._from_row(row)

    def find_by_idempotency_key(self, idempotency_key: str) -> dict[str, Any] | None:
        with self.db.connect() as connection:
            row = connection.execute(
                "SELECT * FROM jobs WHERE idempotency_key=?", (idempotency_key,)
            ).fetchone()
        return self._from_row(row) if row is not None else None

    def list(
        self,
        *,
        status: str | None = None,
        created_by: str | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> tuple[list[dict[str, Any]], int]:
        clauses: list[str] = []
        values: list[Any] = []
        if status:
            clauses.append("status=?")
            values.append(status)
        if created_by:
            clauses.append("created_by=?")
            values.append(created_by)
        where = f" WHERE {' AND '.join(clauses)}" if clauses else ""
        with self.db.connect() as connection:
            total_row = connection.execute(
                f"SELECT COUNT(*) AS total FROM jobs{where}", values
            ).fetchone()
            rows = connection.execute(
                f"SELECT * FROM jobs{where} ORDER BY created_at DESC LIMIT ? OFFSET ?",
                (*values, limit, offset),
            ).fetchall()
        return [self._from_row(row) for row in rows], int(total_row["total"])

    def summary(self) -> dict[str, Any]:
        with self.db.connect() as connection:
            row = connection.execute(
                """
                SELECT COUNT(*) AS total,
                       SUM(CASE WHEN status='queued' THEN 1 ELSE 0 END) AS queued,
                       SUM(CASE WHEN status='running' THEN 1 ELSE 0 END) AS running,
                       SUM(CASE WHEN status='completed' THEN 1 ELSE 0 END) AS completed,
                       SUM(CASE WHEN status='failed' THEN 1 ELSE 0 END) AS failed,
                       SUM(CASE WHEN status='cancelled' THEN 1 ELSE 0 END) AS cancelled,
                       MIN(CASE WHEN status='queued' THEN created_at ELSE NULL END) AS oldest_queued_at
                FROM jobs
                """
            ).fetchone()
        oldest = row["oldest_queued_at"]
        oldest_age = 0.0
        if oldest:
            oldest_age = max(
                0.0,
                (datetime.now(timezone.utc) - datetime.fromisoformat(str(oldest))).total_seconds(),
            )
        return {
            "total": int(row["total"] or 0),
            "queued": int(row["queued"] or 0),
            "running": int(row["running"] or 0),
            "completed": int(row["completed"] or 0),
            "failed": int(row["failed"] or 0),
            "cancelled": int(row["cancelled"] or 0),
            "oldest_queued_age_seconds": round(oldest_age, 3),
        }

    def claim(self, *, worker_id: str, lease_seconds: int = 300) -> dict[str, Any] | None:
        now = utc_now()
        lease_expires = (datetime.now(timezone.utc) + timedelta(seconds=lease_seconds)).isoformat()
        with self.db.transaction() as connection:
            lock_clause = " FOR UPDATE SKIP LOCKED" if self.db.backend == "postgresql" else ""
            row = connection.execute(
                """
                SELECT * FROM jobs
                WHERE attempts < max_attempts
                  AND available_at <= ?
                  AND (status='queued' OR (status='running' AND lease_expires_at < ?))
                ORDER BY priority ASC, created_at ASC
                LIMIT 1
                """ + lock_clause,
                (now, now),
            ).fetchone()
            if row is None:
                return None
            connection.execute(
                """
                UPDATE jobs
                SET status='running', lease_owner=?, lease_expires_at=?, attempts=attempts+1,
                    started_at=COALESCE(started_at, ?), error_code=NULL, error_message=NULL
                WHERE id=?
                """,
                (worker_id[:256], lease_expires, now, row["id"]),
            )
            job_id = str(row["id"])
        return self.get(job_id)

    def renew_lease(self, job_id: str, *, worker_id: str, lease_seconds: int) -> bool:
        lease_expires = (
            datetime.now(timezone.utc) + timedelta(seconds=max(5, lease_seconds))
        ).isoformat()
        with self.db.transaction() as connection:
            cursor = connection.execute(
                """
                UPDATE jobs SET lease_expires_at=?
                WHERE id=? AND status='running' AND lease_owner=?
                """,
                (lease_expires, job_id, worker_id[:256]),
            )
        return cursor.rowcount == 1

    def complete(
        self,
        job_id: str,
        *,
        result: dict[str, Any],
        worker_id: str | None = None,
    ) -> dict[str, Any]:
        owner_clause = " AND lease_owner=?" if worker_id else ""
        values: tuple[Any, ...] = (
            dumps(result),
            utc_now(),
            job_id,
            *((worker_id[:256],) if worker_id else ()),
        )
        with self.db.transaction() as connection:
            cursor = connection.execute(
                f"""
                UPDATE jobs SET status='completed', result_json=?, completed_at=?,
                    lease_owner=NULL, lease_expires_at=NULL
                WHERE id=? AND status='running'{owner_clause}
                """,
                values,
            )
            if cursor.rowcount != 1:
                raise ValidationError("job_not_running", "Only a running job can be completed")
        return self.get(job_id)

    def fail(
        self,
        job_id: str,
        *,
        code: str,
        message: str,
        retry_delay_seconds: int = 30,
        worker_id: str | None = None,
    ) -> dict[str, Any]:
        current = self.get(job_id)
        retry = int(current["attempts"]) < int(current["max_attempts"])
        next_status = "queued" if retry else "failed"
        available_at = (
            datetime.now(timezone.utc) + timedelta(seconds=max(0, retry_delay_seconds))
        ).isoformat()
        with self.db.transaction() as connection:
            owner_clause = " AND lease_owner=?" if worker_id else ""
            cursor = connection.execute(
                f"""
                UPDATE jobs SET status=?, available_at=?, completed_at=?, error_code=?,
                    error_message=?, lease_owner=NULL, lease_expires_at=NULL
                WHERE id=?{owner_clause}
                """,
                (
                    next_status,
                    available_at,
                    None if retry else utc_now(),
                    code[:128],
                    message[:1000],
                    job_id,
                    *((worker_id[:256],) if worker_id else ()),
                ),
            )
            if cursor.rowcount != 1:
                raise ValidationError("job_lease_lost", "Worker no longer owns the job lease")
        return self.get(job_id)

    def cancel(self, job_id: str) -> dict[str, Any]:
        with self.db.transaction() as connection:
            cursor = connection.execute(
                """
                UPDATE jobs SET status='cancelled', completed_at=?
                WHERE id=? AND status='queued'
                """,
                (utc_now(), job_id),
            )
            if cursor.rowcount != 1:
                raise ValidationError("job_not_cancellable", "Only a queued job can be cancelled")
        return self.get(job_id)

    def retry(self, job_id: str) -> dict[str, Any]:
        with self.db.transaction() as connection:
            cursor = connection.execute(
                """
                UPDATE jobs SET status='queued', attempts=0, available_at=?, completed_at=NULL,
                    lease_owner=NULL, lease_expires_at=NULL, error_code=NULL, error_message=NULL
                WHERE id=? AND status IN ('failed','cancelled')
                """,
                (utc_now(), job_id),
            )
            if cursor.rowcount != 1:
                raise ValidationError(
                    "job_not_retryable", "Only a failed or cancelled job can be retried"
                )
        return self.get(job_id)
