from __future__ import annotations

from typing import Any


class FraudShieldError(Exception):
    def __init__(
        self,
        code: str,
        message: str,
        *,
        status_code: int = 400,
        details: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.status_code = status_code
        self.details = details or {}


class NotFoundError(FraudShieldError):
    def __init__(self, resource: str, identifier: str) -> None:
        super().__init__(
            "not_found",
            f"{resource} '{identifier}' was not found",
            status_code=404,
            details={"resource": resource, "identifier": identifier},
        )


class ValidationError(FraudShieldError):
    def __init__(self, code: str, message: str, **details: Any) -> None:
        super().__init__(code, message, status_code=422, details=details)


class ConflictError(FraudShieldError):
    def __init__(self, code: str, message: str, **details: Any) -> None:
        super().__init__(code, message, status_code=409, details=details)


class ConfigurationError(FraudShieldError):
    def __init__(self, message: str, **details: Any) -> None:
        super().__init__("configuration_error", message, status_code=503, details=details)
