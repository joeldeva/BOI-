from __future__ import annotations

import json
import logging
import re
import zipfile
from pathlib import Path
from typing import Any
from pydantic import BaseModel, ConfigDict, Field


logger = logging.getLogger(__name__)


class FirebaseInfrastructure(BaseModel):
    """Extracted Firebase backend infrastructure identifiers."""

    model_config = ConfigDict(extra="forbid")

    project_id: str | None = None
    mobilesdk_app_id: str | None = None
    firebase_url: str | None = None
    storage_bucket: str | None = None
    gcm_defaultSenderId: str | None = None
    api_key: str | None = None
    database_urls: list[str] = Field(default_factory=list)
    firestore_collections: list[str] = Field(default_factory=list)
    raw_config_detected: bool = False
    source: str = "STATIC_EXTRACTION"


class FirebaseExtractor:
    """Safely extracts Firebase configuration from APK resources, assets, and network strings."""

    FIREBASE_URL_REGEX = re.compile(r"https?://([a-zA-Z0-9_-]+)\.firebaseio\.com/?", re.IGNORECASE)
    STORAGE_BUCKET_REGEX = re.compile(r"([a-zA-Z0-9_-]+)\.appspot\.com", re.IGNORECASE)

    @classmethod
    def extract_from_findings(
        cls,
        extraction: dict[str, Any],
        apk_path: Path | None = None,
    ) -> FirebaseInfrastructure:
        """Extracts Firebase configuration from extraction dictionary and optional APK zipfile."""
        project_id: str | None = None
        app_id: str | None = None
        firebase_url: str | None = None
        storage_bucket: str | None = None
        sender_id: str | None = None
        api_key: str | None = None
        database_urls: set[str] = set()
        raw_config = False

        # 1. Inspect URLs and Domains in Network Indicators
        network_info = extraction.get("network_indicators", {})
        all_urls = network_info.get("urls", []) + extraction.get("urls", [])
        all_domains = network_info.get("domains", [])

        for u in all_urls:
            m = cls.FIREBASE_URL_REGEX.search(u)
            if m:
                p_id = m.group(1).lower()
                if not project_id:
                    project_id = p_id
                database_urls.add(u)
            m_bucket = cls.STORAGE_BUCKET_REGEX.search(u)
            if m_bucket and not storage_bucket:
                storage_bucket = f"{m_bucket.group(1).lower()}.appspot.com"

        for d in all_domains:
            m = cls.FIREBASE_URL_REGEX.search(f"https://{d}")
            if m and not project_id:
                project_id = m.group(1).lower()
                database_urls.add(f"https://{d}")

        # 2. Inspect APK Archive directly if file exists
        if apk_path and apk_path.exists() and apk_path.is_file():
            try:
                with zipfile.ZipFile(apk_path, "r") as zf:
                    for name in zf.namelist():
                        # Check google-services.json
                        if name.endswith("google-services.json") or "google-services" in name:
                            raw_config = True
                            try:
                                content = zf.read(name).decode("utf-8", errors="ignore")
                                data = json.loads(content)
                                p_info = data.get("project_info", {})
                                if p_info.get("project_id"):
                                    project_id = p_info.get("project_id")
                                if p_info.get("firebase_url"):
                                    firebase_url = p_info.get("firebase_url")
                                    database_urls.add(firebase_url)
                                if p_info.get("storage_bucket"):
                                    storage_bucket = p_info.get("storage_bucket")
                                if p_info.get("project_number"):
                                    sender_id = str(p_info.get("project_number"))
                            except Exception:
                                pass
            except Exception as exc:
                logger.debug("Failed reading zip archive for Firebase extraction: %s", exc)

        if not firebase_url and project_id:
            firebase_url = f"https://{project_id}.firebaseio.com"
            database_urls.add(firebase_url)

        return FirebaseInfrastructure(
            project_id=project_id,
            mobilesdk_app_id=app_id,
            firebase_url=firebase_url,
            storage_bucket=storage_bucket,
            gcm_defaultSenderId=sender_id,
            api_key=api_key,
            database_urls=sorted(database_urls),
            raw_config_detected=raw_config,
            source="STATIC_EXTRACTION",
        )
