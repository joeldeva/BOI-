from __future__ import annotations

import sqlite3
import threading
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Iterator, Sequence


MIGRATIONS: tuple[tuple[int, str], ...] = (
    (
        1,
        """
        CREATE TABLE IF NOT EXISTS analyses (
            id TEXT PRIMARY KEY,
            status TEXT NOT NULL CHECK (status IN ('pending','running','completed','failed')),
            data_origin TEXT NOT NULL CHECK (data_origin IN ('uploaded','synthetic')),
            file_name TEXT NOT NULL,
            sha256 TEXT NOT NULL,
            size_bytes INTEGER NOT NULL,
            category TEXT NOT NULL,
            created_at TEXT NOT NULL,
            started_at TEXT,
            completed_at TEXT,
            overall_score INTEGER,
            severity TEXT,
            confidence REAL,
            analysis_quality TEXT,
            result_json TEXT,
            narrative TEXT,
            error_code TEXT,
            error_message TEXT
        );
        CREATE INDEX IF NOT EXISTS idx_analyses_created_at ON analyses(created_at DESC);
        CREATE INDEX IF NOT EXISTS idx_analyses_sha256 ON analyses(sha256);
        CREATE INDEX IF NOT EXISTS idx_analyses_severity ON analyses(severity);

        CREATE TABLE IF NOT EXISTS indicators (
            id TEXT PRIMARY KEY,
            type TEXT NOT NULL,
            normalized_value TEXT NOT NULL,
            display_value TEXT NOT NULL,
            severity TEXT NOT NULL,
            confidence REAL NOT NULL,
            first_seen TEXT NOT NULL,
            last_seen TEXT NOT NULL,
            sightings_count INTEGER NOT NULL DEFAULT 1,
            description TEXT NOT NULL DEFAULT '',
            metadata_json TEXT NOT NULL DEFAULT '{}',
            UNIQUE(type, normalized_value)
        );
        CREATE INDEX IF NOT EXISTS idx_indicators_type ON indicators(type);
        CREATE INDEX IF NOT EXISTS idx_indicators_last_seen ON indicators(last_seen DESC);

        CREATE TABLE IF NOT EXISTS indicator_sightings (
            id TEXT PRIMARY KEY,
            indicator_id TEXT NOT NULL REFERENCES indicators(id) ON DELETE CASCADE,
            source_analysis_id TEXT REFERENCES analyses(id) ON DELETE SET NULL,
            seen_at TEXT NOT NULL,
            context_json TEXT NOT NULL DEFAULT '{}',
            UNIQUE(indicator_id, source_analysis_id)
        );

        """,
    ),
    (
        2,
        """
        CREATE TABLE IF NOT EXISTS audit_chain_state (
            id INTEGER PRIMARY KEY CHECK (id = 1),
            sequence_number BIGINT NOT NULL,
            event_hash TEXT NOT NULL
        );
        INSERT INTO audit_chain_state(id, sequence_number, event_hash)
        VALUES (1, 0, '') ON CONFLICT (id) DO NOTHING;

        CREATE TABLE IF NOT EXISTS audit_events (
            id TEXT PRIMARY KEY,
            sequence_number BIGINT NOT NULL UNIQUE,
            occurred_at TEXT NOT NULL,
            request_id TEXT NOT NULL,
            actor_id TEXT NOT NULL,
            auth_type TEXT NOT NULL,
            roles_json TEXT NOT NULL,
            action TEXT NOT NULL,
            resource_type TEXT NOT NULL,
            resource_id TEXT,
            method TEXT NOT NULL,
            path TEXT NOT NULL,
            status_code INTEGER NOT NULL,
            client_address_hash TEXT NOT NULL,
            user_agent_hash TEXT NOT NULL,
            details_json TEXT NOT NULL,
            previous_hash TEXT NOT NULL,
            event_hash TEXT NOT NULL UNIQUE
        );
        CREATE INDEX IF NOT EXISTS idx_audit_events_occurred_at ON audit_events(occurred_at DESC);
        CREATE INDEX IF NOT EXISTS idx_audit_events_actor ON audit_events(actor_id, occurred_at DESC);
        CREATE INDEX IF NOT EXISTS idx_audit_events_request ON audit_events(request_id);
        """,
    ),
    (
        3,
        """
        CREATE TABLE IF NOT EXISTS jobs (
            id TEXT PRIMARY KEY,
            kind TEXT NOT NULL CHECK (kind = 'apk_analysis'),
            status TEXT NOT NULL CHECK (status IN ('queued','running','completed','failed','cancelled')),
            payload_json TEXT NOT NULL,
            result_json TEXT,
            priority INTEGER NOT NULL DEFAULT 100,
            attempts INTEGER NOT NULL DEFAULT 0,
            max_attempts INTEGER NOT NULL DEFAULT 3,
            available_at TEXT NOT NULL,
            lease_owner TEXT,
            lease_expires_at TEXT,
            created_by TEXT NOT NULL,
            created_at TEXT NOT NULL,
            started_at TEXT,
            completed_at TEXT,
            error_code TEXT,
            error_message TEXT,
            idempotency_key TEXT UNIQUE
        );
        CREATE INDEX IF NOT EXISTS idx_jobs_claim
        ON jobs(status, available_at, priority, created_at);
        CREATE INDEX IF NOT EXISTS idx_jobs_created_by ON jobs(created_by, created_at DESC);
        """,
    ),
    (
        5,
        """
        ALTER TABLE audit_events ADD COLUMN audit_key_id TEXT NOT NULL DEFAULT 'legacy';
        CREATE INDEX IF NOT EXISTS idx_audit_events_key_id ON audit_events(audit_key_id);
        """,
    ),
    (
        6,
        """
        DELETE FROM indicator_sightings
        WHERE source_analysis_id IN (
            SELECT id FROM analyses WHERE data_origin = 'synthetic'
        );

        DELETE FROM indicators
        WHERE id NOT IN (
            SELECT DISTINCT indicator_id FROM indicator_sightings
        );

        DELETE FROM analyses WHERE data_origin = 'synthetic';
        """,
    ),
)


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


class Connection:
    """Small DB-API compatibility layer for sqlite3 and psycopg 3."""

    def __init__(
        self,
        raw: Any,
        *,
        backend: str,
        release: Callable[[Any], None] | None = None,
    ) -> None:
        self.raw = raw
        self.backend = backend
        self._release = release
        self._closed = False

    def execute(self, sql: str, params: Sequence[Any] | None = None) -> Any:
        statement = sql.replace("?", "%s") if self.backend == "postgresql" else sql
        return self.raw.execute(statement, tuple(params or ()))

    def executescript(self, sql: str) -> None:
        if self.backend == "sqlite":
            self.raw.executescript(sql)
            return
        for statement in (part.strip() for part in sql.split(";")):
            if statement:
                self.raw.execute(statement)

    def commit(self) -> None:
        self.raw.commit()

    def rollback(self) -> None:
        self.raw.rollback()

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        if self._release is not None:
            self._release(self.raw)
        else:
            self.raw.close()

    def __enter__(self) -> "Connection":
        return self

    def __exit__(self, exc_type: Any, exc: BaseException | None, traceback: Any) -> None:
        try:
            if exc_type is None:
                self.commit()
            else:
                self.rollback()
        finally:
            self.close()


class Database:
    def __init__(
        self,
        target: str | Path,
        *,
        pool_min_size: int = 2,
        pool_max_size: int = 10,
    ) -> None:
        raw_target = str(target)
        self.pool_min_size = pool_min_size
        self.pool_max_size = pool_max_size
        self._pool: Any = None
        self._pool_lock = threading.Lock()
        if raw_target.startswith(("postgresql://", "postgres://")):
            self.backend = "postgresql"
            self.url = raw_target.replace("postgres://", "postgresql://", 1)
            self.path: str | None = None
        else:
            self.backend = "sqlite"
            self.url = raw_target if raw_target.startswith("sqlite:///") else f"sqlite:///{raw_target}"
            self.path = self.url.removeprefix("sqlite:///")

    def _postgres_pool(self) -> Any:
        if self._pool is not None:
            return self._pool
        with self._pool_lock:
            if self._pool is not None:
                return self._pool
            try:
                from psycopg.rows import dict_row
                from psycopg_pool import ConnectionPool
            except ImportError as exc:
                raise RuntimeError(
                    "PostgreSQL support requires the 'production' package extra "
                    "(psycopg and psycopg-pool)."
                ) from exc
            self._pool = ConnectionPool(
                conninfo=self.url,
                min_size=self.pool_min_size,
                max_size=self.pool_max_size,
                kwargs={"row_factory": dict_row, "autocommit": False},
                open=True,
            )
        return self._pool

    def connect(self) -> Connection:
        if self.backend == "sqlite":
            assert self.path is not None
            raw = sqlite3.connect(self.path, timeout=15, check_same_thread=False)
            raw.row_factory = sqlite3.Row
            raw.execute("PRAGMA foreign_keys = ON")
            raw.execute("PRAGMA busy_timeout = 15000")
            if self.path != ":memory:":
                raw.execute("PRAGMA journal_mode = WAL")
            return Connection(raw, backend="sqlite")
        pool = self._postgres_pool()
        raw = pool.getconn()
        return Connection(raw, backend="postgresql", release=pool.putconn)

    def initialize(self) -> None:
        with self.transaction() as connection:
            if self.backend == "postgresql":
                connection.execute("SELECT pg_advisory_xact_lock(?)", (734_338_921,))
            connection.execute(
                "CREATE TABLE IF NOT EXISTS schema_migrations "
                "(version INTEGER PRIMARY KEY, applied_at TEXT NOT NULL)"
            )
            applied = {
                int(row["version"])
                for row in connection.execute("SELECT version FROM schema_migrations").fetchall()
            }
            for version, sql in MIGRATIONS:
                if version in applied:
                    continue
                connection.executescript(sql)
                connection.execute(
                    "INSERT INTO schema_migrations(version, applied_at) VALUES (?, ?)",
                    (version, _utc_now()),
                )

    @contextmanager
    def transaction(self) -> Iterator[Connection]:
        connection = self.connect()
        try:
            connection.execute("BEGIN IMMEDIATE" if self.backend == "sqlite" else "BEGIN")
            yield connection
            connection.commit()
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()

    def ping(self) -> bool:
        try:
            with self.connect() as connection:
                row = connection.execute("SELECT 1 AS ok").fetchone()
                return bool(row and row["ok"] == 1)
        except Exception:
            return False

    def close(self) -> None:
        if self._pool is not None:
            self._pool.close()
            self._pool = None
