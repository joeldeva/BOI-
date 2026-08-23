from __future__ import annotations

import hashlib
import os
import stat
import uuid
import zipfile
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any

from fastapi import UploadFile

from fraudshield.core.config import Settings
from fraudshield.core.errors import ValidationError
from fraudshield.core.security import safe_filename


ZIP_MAGICS = (b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08")


@dataclass(frozen=True, slots=True)
class StoredUpload:
    path: Path
    original_name: str
    sha256: str
    size_bytes: int


async def store_apk_upload(upload: UploadFile, settings: Settings) -> StoredUpload:
    original_name = safe_filename(upload.filename or "sample.apk", "sample.apk")
    if Path(original_name).suffix.lower() != ".apk":
        raise ValidationError("invalid_apk_extension", "Uploaded file must use the .apk extension")

    settings.upload_dir.mkdir(parents=True, exist_ok=True)
    target = settings.upload_dir / f"apk_{uuid.uuid4().hex}.apk.part"
    digest = hashlib.sha256()
    size = 0
    try:
        with target.open("xb") as handle:
            target.chmod(0o600)
            while True:
                chunk = await upload.read(1024 * 1024)
                if not chunk:
                    break
                size += len(chunk)
                if size > settings.max_apk_bytes:
                    raise ValidationError(
                        "apk_too_large",
                        "APK exceeds the configured upload limit",
                        maximum_bytes=settings.max_apk_bytes,
                    )
                digest.update(chunk)
                handle.write(chunk)
        if size == 0:
            raise ValidationError("empty_apk", "Uploaded APK is empty")
        final_path = target.with_suffix("")
        os.replace(target, final_path)
        return StoredUpload(final_path, original_name, digest.hexdigest(), size)
    except Exception:
        target.unlink(missing_ok=True)
        raise
    finally:
        await upload.close()


def validate_apk_archive(path: Path, settings: Settings) -> dict[str, Any]:
    if not path.is_file():
        raise ValidationError("apk_missing", "APK file is unavailable")
    size = path.stat().st_size
    if size <= 0:
        raise ValidationError("empty_apk", "APK file is empty")
    if size > settings.max_apk_bytes:
        raise ValidationError(
            "apk_too_large",
            "APK exceeds the configured upload limit",
            maximum_bytes=settings.max_apk_bytes,
        )
    with path.open("rb") as handle:
        magic = handle.read(4)
    if not any(magic.startswith(prefix) for prefix in ZIP_MAGICS):
        raise ValidationError("invalid_apk_magic", "APK is not a ZIP-based Android package")

    try:
        with zipfile.ZipFile(path) as archive:
            entries = archive.infolist()
            if len(entries) > settings.max_zip_entries:
                raise ValidationError(
                    "apk_too_many_entries",
                    "APK contains too many archive entries",
                    maximum_entries=settings.max_zip_entries,
                )
            total_uncompressed = 0
            total_compressed = 0
            names: set[str] = set()
            for entry in entries:
                if not entry.filename or "\x00" in entry.filename or "\\" in entry.filename:
                    raise ValidationError(
                        "unsafe_apk_path",
                        "APK contains an invalid archive path",
                        entry=entry.filename,
                    )
                posix = PurePosixPath(entry.filename)
                if posix.is_absolute() or ".." in posix.parts:
                    raise ValidationError(
                        "unsafe_apk_path",
                        "APK contains an unsafe archive path",
                        entry=entry.filename,
                    )
                if entry.filename in names:
                    raise ValidationError(
                        "duplicate_apk_entry",
                        "APK contains duplicate archive entries",
                        entry=entry.filename,
                    )
                if entry.flag_bits & 0x1:
                    raise ValidationError(
                        "encrypted_apk_entry",
                        "Encrypted APK archive entries are not supported",
                        entry=entry.filename,
                    )
                mode = (entry.external_attr >> 16) & 0xFFFF
                if mode and stat.S_ISLNK(mode):
                    raise ValidationError(
                        "unsafe_apk_symlink",
                        "APK contains a symbolic link entry",
                        entry=entry.filename,
                    )
                total_uncompressed += max(0, entry.file_size)
                total_compressed += max(0, entry.compress_size)
                names.add(entry.filename)
            if total_uncompressed > settings.max_zip_uncompressed_bytes:
                raise ValidationError(
                    "apk_uncompressed_too_large",
                    "APK expands beyond the configured safe limit",
                    maximum_bytes=settings.max_zip_uncompressed_bytes,
                )
            if "AndroidManifest.xml" not in names:
                raise ValidationError("missing_manifest", "APK does not contain AndroidManifest.xml")
            dex_files = sorted(name for name in names if name.startswith("classes") and name.endswith(".dex"))
            warnings = []
            if not dex_files:
                warnings.append("No classes*.dex entry was found; this may be a split/resource-only APK.")
            ratio = total_uncompressed / max(total_compressed, 1)
            if ratio > 250 and total_uncompressed > 50 * 1024 * 1024:
                raise ValidationError(
                    "suspicious_compression_ratio",
                    "APK archive compression ratio exceeds the safe threshold",
                    ratio=round(ratio, 2),
                )
            return {
                "entry_count": len(entries),
                "compressed_bytes": total_compressed,
                "uncompressed_bytes": total_uncompressed,
                "compression_ratio": round(ratio, 3),
                "dex_files": dex_files,
                "warnings": warnings,
            }
    except zipfile.BadZipFile as exc:
        raise ValidationError("invalid_apk_zip", "APK archive is corrupt or truncated") from exc
