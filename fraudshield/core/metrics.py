from __future__ import annotations

from typing import Any


class Metrics:
    def __init__(self, enabled: bool) -> None:
        self.enabled = enabled
        self.registry: Any = None
        self._requests: Any = None
        self._duration: Any = None
        self._audit_failures: Any = None
        if not enabled:
            return
        try:
            from prometheus_client import CollectorRegistry, Counter, Gauge, Histogram
        except ImportError as exc:
            raise RuntimeError(
                "Metrics are enabled but prometheus-client is not installed; "
                "install the production package extra."
            ) from exc
        self.registry = CollectorRegistry(auto_describe=True)
        self._requests = Counter(
            "fraudshield_http_requests_total",
            "HTTP requests handled by FraudShield",
            ("method", "route", "status"),
            registry=self.registry,
        )
        self._duration = Histogram(
            "fraudshield_http_request_duration_seconds",
            "FraudShield HTTP request duration",
            ("method", "route"),
            buckets=(0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10, 30, 60),
            registry=self.registry,
        )
        self._audit_failures = Counter(
            "fraudshield_audit_persistence_failures_total",
            "Security audit events that could not be persisted",
            registry=self.registry,
        )
        self._jobs = Gauge(
            "fraudshield_jobs",
            "Durable jobs by status",
            ("status",),
            registry=self.registry,
        )
        self._oldest_queued = Gauge(
            "fraudshield_oldest_queued_job_age_seconds",
            "Age of the oldest queued FraudShield job",
            registry=self.registry,
        )

    def observe_request(self, *, method: str, route: str, status_code: int, seconds: float) -> None:
        if not self.enabled:
            return
        self._requests.labels(method=method, route=route, status=str(status_code)).inc()
        self._duration.labels(method=method, route=route).observe(seconds)

    def audit_failure(self) -> None:
        if self.enabled:
            self._audit_failures.inc()

    def set_job_summary(self, summary: dict[str, Any]) -> None:
        if not self.enabled:
            return
        for status in ("queued", "running", "completed", "failed", "cancelled"):
            self._jobs.labels(status=status).set(int(summary.get(status, 0)))
        self._oldest_queued.set(float(summary.get("oldest_queued_age_seconds", 0)))

    def render(self) -> tuple[bytes, str]:
        if not self.enabled:
            raise RuntimeError("Metrics are disabled")
        from prometheus_client import CONTENT_TYPE_LATEST, generate_latest

        return generate_latest(self.registry), CONTENT_TYPE_LATEST
