"""Structured, privacy-aware security audit middleware."""

from __future__ import annotations

import json
import logging
import math
import re
import time
import uuid
from collections.abc import Mapping
from enum import Enum

from django.http.response import HttpResponseBase

from .exceptions import AuditEmissionError, SessionConfigurationError
from .utils import get_client_ip, hash_ip, is_authenticated, path_is_exempt, sanitize_for_log

_FIELD_RE = re.compile(r"[A-Za-z][A-Za-z0-9_.:-]{0,127}\Z")
_RESERVED = frozenset(
    {"event", "rid", "method", "path", "status", "ip_hash", "ua", "duration_ms"}
)


class AuditErrorMode(str, Enum):
    """Whether an audit-construction failure blocks the request."""

    RAISE = "raise"
    SUPPRESS = "suppress"


def _safe_value(value: object, *, depth: int = 0) -> object:
    if depth > 8:
        raise AuditEmissionError("audit data exceeds the maximum nesting depth.")
    if value is None or isinstance(value, bool | int):
        return value
    if isinstance(value, float):
        if not math.isfinite(value):
            raise AuditEmissionError("audit numbers must be finite.")
        return value
    if isinstance(value, str):
        return sanitize_for_log(value, max_length=500)
    if isinstance(value, Mapping):
        if len(value) > 128:
            raise AuditEmissionError("audit mappings contain too many fields.")
        result: dict[str, object] = {}
        for key, child in value.items():
            if not isinstance(key, str) or _FIELD_RE.fullmatch(key) is None:
                raise AuditEmissionError("audit field names must be bounded safe identifiers.")
            result[key] = _safe_value(child, depth=depth + 1)
        return result
    if isinstance(value, list | tuple):
        if len(value) > 256:
            raise AuditEmissionError("audit collections contain too many values.")
        return [_safe_value(child, depth=depth + 1) for child in value]
    raise AuditEmissionError(f"unsupported audit value type: {type(value).__name__}")


class AuditMiddleware:
    """Emit one structured event for every authenticated request outcome."""

    logger_name: str = "security.audit"
    exempt_paths: tuple[str, ...] = ()
    allow_suppression: bool = False
    error_mode: AuditErrorMode = AuditErrorMode.RAISE

    def __init__(self, get_response):
        if not callable(get_response):
            raise TypeError("get_response must be callable.")
        if not isinstance(self.logger_name, str) or not self.logger_name:
            raise SessionConfigurationError("logger_name must be a non-empty string.")
        if not isinstance(self.allow_suppression, bool):
            raise SessionConfigurationError("allow_suppression must be a boolean.")
        if not isinstance(self.error_mode, AuditErrorMode):
            raise SessionConfigurationError("error_mode must be an AuditErrorMode value.")
        path_is_exempt("/", self.exempt_paths)
        self.get_response = get_response
        self._logger = logging.getLogger(self.logger_name)

    def __call__(self, request):
        if self._is_exempt(request):
            return self.get_response(request)

        request_id = uuid.uuid4().hex
        request.META["X_REQUEST_ID"] = request_id
        start = time.perf_counter()
        try:
            response = self.get_response(request)
        except Exception as original:
            if is_authenticated(request):
                try:
                    self._emit(
                        request,
                        event="request.failed",
                        request_id=request_id,
                        duration_ms=round((time.perf_counter() - start) * 1000),
                        status=500,
                        response=None,
                        error_type=type(original).__name__,
                    )
                except Exception:
                    self._logger.critical("Security audit failed while recording an exception", exc_info=True)
            raise

        if not isinstance(response, HttpResponseBase):
            raise TypeError("get_response must return an HttpResponse.")
        response.headers.setdefault("X-Request-ID", request_id)
        if is_authenticated(request):
            try:
                self._emit(
                    request,
                    event="request.completed",
                    request_id=request_id,
                    duration_ms=round((time.perf_counter() - start) * 1000),
                    status=response.status_code,
                    response=response,
                )
            except Exception as error:
                if self.error_mode is AuditErrorMode.RAISE:
                    raise AuditEmissionError("required security audit emission failed.") from error
                self._logger.critical("Security audit event suppressed after failure", exc_info=True)
        return response

    def get_user_identity(self, request) -> Mapping[str, object]:
        user = request.user
        return {"uid": getattr(user, "sub", None) or str(getattr(user, "pk", ""))}

    def get_extra_fields(self, request, response) -> Mapping[str, object]:
        return {}

    def before_log(self, request, response, entry: Mapping[str, object]):
        return entry

    def get_log_level(self, status_code: int) -> int:
        if status_code >= 500:
            return logging.ERROR
        if status_code in (401, 403):
            return logging.WARNING
        if status_code >= 400:
            return logging.INFO
        return logging.DEBUG

    def format_entry(self, entry: Mapping[str, object]) -> str:
        return json.dumps(entry, ensure_ascii=True, separators=(",", ":"), sort_keys=True)

    def _emit(
        self,
        request,
        *,
        event: str,
        request_id: str,
        duration_ms: int,
        status: int,
        response,
        error_type: str | None = None,
    ) -> None:
        identity = self.get_user_identity(request)
        extra = self.get_extra_fields(request, response)
        for label, fields in (("identity", identity), ("extra", extra)):
            if not isinstance(fields, Mapping):
                raise AuditEmissionError(f"{label} audit fields must be a mapping.")
            conflict = _RESERVED & set(fields)
            if conflict:
                raise AuditEmissionError(f"custom audit fields override reserved fields: {sorted(conflict)}")

        entry: dict[str, object] = {
            "event": event,
            "rid": request_id,
            **identity,
            "method": getattr(request, "method", ""),
            "path": getattr(request, "path", ""),
            "status": status,
            "ip_hash": hash_ip(get_client_ip(request), length=32),
            "ua": request.META.get("HTTP_USER_AGENT", ""),
            "duration_ms": duration_ms,
            **extra,
        }
        if error_type is not None:
            entry["error_type"] = error_type
        safe_entry = _safe_value(entry)
        if not isinstance(safe_entry, Mapping):  # pragma: no cover
            raise AuditEmissionError("audit entry was not a mapping.")
        prepared = self.before_log(request, response, safe_entry)
        if prepared is None:
            if not self.allow_suppression:
                raise AuditEmissionError("before_log() suppressed a required audit event.")
            return
        prepared = _safe_value(prepared)
        if not isinstance(prepared, Mapping):
            raise AuditEmissionError("before_log() must return a mapping or None.")
        message = self.format_entry(prepared)
        if not isinstance(message, str):
            raise AuditEmissionError("format_entry() must return a string.")
        message = sanitize_for_log(message, max_length=16_384)
        prefix = "AUDIT_DENIED" if status in (401, 403) else "AUDIT"
        self._logger.log(self.get_log_level(status), "%s %s", prefix, message)

    def _is_exempt(self, request) -> bool:
        return path_is_exempt(request.path, self.exempt_paths)
