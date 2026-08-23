from __future__ import annotations

import hashlib
import os
import shutil
import tempfile
import uuid
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import ContextManager, Iterator, Protocol
from urllib.parse import urlsplit

from fraudshield.core.config import Settings
from fraudshield.core.security import safe_filename


@dataclass(frozen=True, slots=True)
class Artifact:
    uri: str
    sha256: str
    size_bytes: int


class ArtifactStore(Protocol):
    backend: str

    def put_file(
        self,
        source: Path,
        *,
        namespace: str,
        object_name: str,
        sha256: str,
        content_type: str,
    ) -> Artifact: ...

    def materialize(self, uri: str) -> ContextManager[Path]: ...

    def exists(self, uri: str) -> bool: ...

    def delete(self, uri: str) -> None: ...

    def ping(self) -> bool: ...


class LocalArtifactStore:
    backend = "local"

    def __init__(self, settings: Settings) -> None:
        self.root = (settings.data_dir / "artifacts").resolve()
        self.materialized = (settings.data_dir / "materialized").resolve()
        self.root.mkdir(parents=True, exist_ok=True)
        self.materialized.mkdir(parents=True, exist_ok=True)

    def _path(self, uri: str) -> Path:
        parsed = urlsplit(uri)
        if parsed.scheme != "local" or not parsed.netloc:
            raise ValueError("Invalid local artifact URI")
        candidate = (self.root / parsed.netloc / parsed.path.lstrip("/")).resolve()
        try:
            candidate.relative_to(self.root)
        except ValueError as exc:
            raise ValueError("Artifact URI escapes the local store") from exc
        return candidate

    def put_file(
        self,
        source: Path,
        *,
        namespace: str,
        object_name: str,
        sha256: str,
        content_type: str,
    ) -> Artifact:
        del content_type
        safe_namespace = safe_filename(namespace, "artifacts")
        safe_name = safe_filename(object_name, sha256)
        destination = (self.root / safe_namespace / safe_name).resolve()
        destination.parent.mkdir(parents=True, exist_ok=True)
        existing_hash = ""
        if destination.is_file():
            digest = hashlib.sha256()
            with destination.open("rb") as handle:
                while chunk := handle.read(1024 * 1024):
                    digest.update(chunk)
            existing_hash = digest.hexdigest()
        if existing_hash != sha256:
            temporary = destination.with_name(f".{destination.name}.{uuid.uuid4().hex}.part")
            try:
                shutil.copyfile(source, temporary)
                temporary.chmod(0o600)
                os.replace(temporary, destination)
            finally:
                temporary.unlink(missing_ok=True)
        return Artifact(
            uri=f"local://{safe_namespace}/{safe_name}",
            sha256=sha256,
            size_bytes=destination.stat().st_size,
        )

    @contextmanager
    def materialize(self, uri: str) -> Iterator[Path]:
        source = self._path(uri)
        if not source.is_file():
            raise FileNotFoundError(uri)
        with tempfile.TemporaryDirectory(prefix="artifact-", dir=self.materialized) as temp_dir:
            target = Path(temp_dir) / source.name
            shutil.copyfile(source, target)
            target.chmod(0o600)
            yield target

    def exists(self, uri: str) -> bool:
        try:
            return self._path(uri).is_file()
        except ValueError:
            return False

    def delete(self, uri: str) -> None:
        self._path(uri).unlink(missing_ok=True)

    def ping(self) -> bool:
        return self.root.is_dir() and os.access(self.root, os.R_OK | os.W_OK)


class S3ArtifactStore:
    backend = "s3"

    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        self.bucket = settings.s3_bucket
        self.prefix = settings.s3_prefix
        self.materialized = (settings.data_dir / "materialized").resolve()
        self.materialized.mkdir(parents=True, exist_ok=True)
        try:
            import boto3
            from botocore.config import Config
        except ImportError as exc:
            raise RuntimeError(
                "S3 storage requires the 'production' package extra (boto3)."
            ) from exc
        kwargs: dict[str, object] = {
            "service_name": "s3",
            "region_name": settings.s3_region,
            "config": Config(
                signature_version="s3v4",
                connect_timeout=5,
                read_timeout=60,
                retries={"max_attempts": 4, "mode": "standard"},
            ),
        }
        if settings.s3_endpoint_url:
            kwargs["endpoint_url"] = settings.s3_endpoint_url
        self.client = boto3.client(**kwargs)

    def _key(self, namespace: str, object_name: str) -> str:
        parts = [
            part
            for part in (
                self.prefix,
                safe_filename(namespace, "artifacts"),
                safe_filename(object_name, "artifact"),
            )
            if part
        ]
        return "/".join(parts)

    def _parse(self, uri: str) -> str:
        parsed = urlsplit(uri)
        key = parsed.path.lstrip("/")
        if parsed.scheme != "s3" or parsed.netloc != self.bucket or not key:
            raise ValueError("Artifact URI is not in the configured S3 bucket")
        if self.prefix and not key.startswith(f"{self.prefix}/"):
            raise ValueError("Artifact URI is outside the configured S3 prefix")
        return key

    def put_file(
        self,
        source: Path,
        *,
        namespace: str,
        object_name: str,
        sha256: str,
        content_type: str,
    ) -> Artifact:
        key = self._key(namespace, object_name)
        extra: dict[str, object] = {
            "ContentType": content_type,
            "Metadata": {"sha256": sha256},
        }
        if self.settings.s3_kms_key_id:
            extra.update(
                {
                    "ServerSideEncryption": "aws:kms",
                    "SSEKMSKeyId": self.settings.s3_kms_key_id,
                }
            )
        else:
            extra["ServerSideEncryption"] = "AES256"
        self.client.upload_file(str(source), self.bucket, key, ExtraArgs=extra)
        return Artifact(
            uri=f"s3://{self.bucket}/{key}",
            sha256=sha256,
            size_bytes=source.stat().st_size,
        )

    @contextmanager
    def materialize(self, uri: str) -> Iterator[Path]:
        key = self._parse(uri)
        with tempfile.TemporaryDirectory(prefix="artifact-", dir=self.materialized) as temp_dir:
            target = Path(temp_dir) / safe_filename(Path(key).name, "artifact.bin")
            self.client.download_file(self.bucket, key, str(target))
            target.chmod(0o600)
            yield target

    def exists(self, uri: str) -> bool:
        try:
            self.client.head_object(Bucket=self.bucket, Key=self._parse(uri))
            return True
        except Exception:
            return False

    def delete(self, uri: str) -> None:
        self.client.delete_object(Bucket=self.bucket, Key=self._parse(uri))

    def ping(self) -> bool:
        try:
            self.client.head_bucket(Bucket=self.bucket)
            return True
        except Exception:
            return False


def build_artifact_store(settings: Settings) -> ArtifactStore:
    if settings.storage_backend == "s3":
        return S3ArtifactStore(settings)
    return LocalArtifactStore(settings)
