from __future__ import annotations

import logging
import os
import socket
import time
from contextlib import contextmanager
from threading import Event, Thread
from typing import Iterator

from fraudshield.core.errors import FraudShieldError, ValidationError
from fraudshield.core.security import sha256_file
from fraudshield.services.container import ServiceContainer


logger = logging.getLogger(__name__)


class DurableWorker:
    def __init__(self, services: ServiceContainer, worker_id: str | None = None) -> None:
        self.services = services
        self.worker_id = worker_id or f"{socket.gethostname()}:{os.getpid()}"

    def _validated_artifact_uri(self, uri: str) -> str:
        if not uri or not self.services.artifacts.exists(uri):
            raise ValidationError("missing_job_artifact", "Queued APK artifact is unavailable")
        return uri

    def _process_apk(self, job: dict) -> dict:
        payload = job["payload"]
        artifact_uri = self._validated_artifact_uri(str(payload.get("artifact_uri", "")))
        with self.services.artifacts.materialize(artifact_uri) as attempt:
            if sha256_file(attempt) != str(payload["sha256"]):
                raise ValidationError(
                    "artifact_integrity_failed",
                    "Queued APK hash does not match the registered evidence hash",
                )
            analysis = self.services.apk_pipeline.analyze_uploaded(
                path=attempt,
                original_name=str(payload["original_name"]),
                sha256=str(payload["sha256"]),
                size_bytes=int(payload["size_bytes"]),
                category=str(payload["category"]),
                dynamic=bool(payload.get("dynamic", False)),
            )
        if not self.services.settings.retain_uploads:
            self.services.artifacts.delete(artifact_uri)
        return {
            "analysis_id": analysis["id"],
            "status": analysis["status"],
            "resource": f"/api/v1/apk-analyses/{analysis['id']}",
        }

    @contextmanager
    def _lease_heartbeat(self, job_id: str) -> Iterator[None]:
        stopped = Event()
        interval = min(60.0, max(2.0, self.services.settings.job_lease_seconds / 3))

        def heartbeat() -> None:
            while not stopped.wait(interval):
                try:
                    renewed = self.services.jobs.renew_lease(
                        job_id,
                        worker_id=self.worker_id,
                        lease_seconds=self.services.settings.job_lease_seconds,
                    )
                    if not renewed:
                        logger.error("Worker %s lost lease for job %s", self.worker_id, job_id)
                        return
                except Exception:
                    logger.exception("Worker %s could not renew lease for job %s", self.worker_id, job_id)

        thread = Thread(target=heartbeat, name=f"job-heartbeat-{job_id}", daemon=True)
        thread.start()
        try:
            yield
        finally:
            stopped.set()
            thread.join(timeout=2)

    def process_next(self) -> bool:
        job = self.services.jobs.claim(
            worker_id=self.worker_id,
            lease_seconds=self.services.settings.job_lease_seconds,
        )
        if job is None:
            return False
        logger.info("Worker %s claimed %s (%s)", self.worker_id, job["id"], job["kind"])
        try:
            with self._lease_heartbeat(job["id"]):
                if job["kind"] == "apk_analysis":
                    result = self._process_apk(job)
                else:
                    raise ValidationError("invalid_job_kind", "Worker cannot process this job kind")
            self.services.jobs.complete(job["id"], result=result, worker_id=self.worker_id)
            return True
        except FraudShieldError as exc:
            try:
                updated = self.services.jobs.fail(
                    job["id"],
                    code=exc.code,
                    message=exc.message,
                    worker_id=self.worker_id,
                )
            except FraudShieldError:
                logger.error("Worker %s no longer owns job %s", self.worker_id, job["id"])
                return True
            self._cleanup_terminal_apk(job, updated)
            logger.warning("Job %s failed: %s", job["id"], exc.code)
            return True
        except Exception:
            logger.exception("Job %s failed unexpectedly", job["id"])
            try:
                updated = self.services.jobs.fail(
                    job["id"],
                    code="worker_execution_failed",
                    message="Worker execution failed; inspect restricted server logs using the job ID.",
                    worker_id=self.worker_id,
                )
            except FraudShieldError:
                logger.error("Worker %s no longer owns job %s", self.worker_id, job["id"])
                return True
            self._cleanup_terminal_apk(job, updated)
            return True

    def _cleanup_terminal_apk(self, job: dict, updated: dict) -> None:
        if (
            job["kind"] == "apk_analysis"
            and updated["status"] == "failed"
            and not self.services.settings.retain_uploads
        ):
            try:
                artifact_uri = str(job["payload"].get("artifact_uri", ""))
                if artifact_uri:
                    self.services.artifacts.delete(artifact_uri)
            except Exception:
                logger.exception("Terminal APK artifact cleanup failed for job %s", job["id"])

    def run_forever(self) -> None:
        logger.info("FraudShield worker %s started", self.worker_id)
        while True:
            processed = self.process_next()
            if not processed:
                time.sleep(self.services.settings.worker_poll_seconds)
