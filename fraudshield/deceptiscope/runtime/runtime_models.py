from __future__ import annotations

from enum import Enum
from typing import Any
from pydantic import BaseModel, ConfigDict, Field


class EvidenceTrustLevel(str, Enum):
    INFERRED = "INFERRED"
    LOG_OBSERVED = "LOG_OBSERVED"
    SYSTEM_OBSERVED = "SYSTEM_OBSERVED"
    INSTRUMENTED = "INSTRUMENTED"
    PAYLOAD_CORRELATED = "PAYLOAD_CORRELATED"


class RuntimeObserverStatus(str, Enum):
    COMPLETED = "COMPLETED"
    UNAVAILABLE = "UNAVAILABLE"
    FAILED = "FAILED"
    TIMED_OUT = "TIMED_OUT"
    UNSUPPORTED = "UNSUPPORTED"
    BLOCKED_BY_POLICY = "BLOCKED_BY_POLICY"


VALID_OBSERVERS: set[str] = {
    "sms",
    "notification",
    "accessibility",
    "network",
    "dynamic_dex",
    "webview",
}

VALID_EVENT_TYPES: set[str] = {
    # SMS
    "SMS_PDU_PARSED",
    "SMS_SEND_ATTEMPT",
    "SMS_MULTIPART_SEND",
    "SMS_ABORT_BROADCAST",
    # Notification
    "NOTIFICATION_TEXT_READ",
    "NOTIFICATION_TITLE_READ",
    "NOTIFICATION_PACKAGE_READ",
    # Accessibility
    "ACCESSIBILITY_TEXT_READ",
    "ACCESSIBILITY_VIEW_INSPECTED",
    "ACCESSIBILITY_ACTION_PERFORMED",
    "ACCESSIBILITY_GESTURE_DISPATCHED",
    # Network
    "HTTP_REQUEST_OBSERVED",
    "SOCKET_CONNECT_OBSERVED",
    "URL_OPENED",
    # Dynamic DEX
    "DEX_CLASS_LOADER_INIT",
    "PATH_CLASS_LOADER_INIT",
    "IN_MEMORY_DEX_LOADED",
    "DEX_FILE_LOADED",
    # WebView
    "WEBVIEW_INTERFACE_ADDED",
    "WEBVIEW_URL_LOADED",
    "WEBVIEW_JS_EXECUTED",
}


class FridaRuntimeEvent(BaseModel):
    """Structured runtime event emitted by an isolated Android Frida observer."""

    model_config = ConfigDict(extra="forbid", protected_namespaces=(), populate_by_name=True)

    schema_version: str = Field(default="deceptiscope.runtime.v1", alias="schema", pattern=r"^deceptiscope\.runtime\.v1$")
    observer: str = Field(min_length=1, max_length=50)
    event_type: str = Field(min_length=1, max_length=60)
    timestamp_ms: int = Field(ge=0)
    api: str = Field(min_length=1, max_length=200)
    target_package: str = Field(min_length=1, max_length=200)
    metadata: dict[str, Any] = Field(default_factory=dict)

    def is_valid_event(self) -> bool:
        return self.observer in VALID_OBSERVERS and self.event_type in VALID_EVENT_TYPES
