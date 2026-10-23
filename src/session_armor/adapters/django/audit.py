"""Structured, privacy-aware security audit middleware."""

from __future__ import annotations

import json
import logging
import math
import re
import time
import uuid
from collections.abc import Callable, Iterator, Mapping
from contextlib import contextmanager
from enum import Enum

from django.http.response import HttpResponseBase

from ...exceptions import AuditEmissionError, SessionConfigurationError
from .utils import get_client_ip, hash_ip, is_authenticated, path_is_exempt, sanitize_for_log

_FIELD_RE = re.compile(r"[A-Za-z][A-Za-z0-9_.:-]{0,127}\Z")
# error_type is library evidence on request.failed events: hooks may neither
# supply it nor alter it.
_RESERVED = frozenset(
    {"event", "rid", "method", "path", "status", "ip_hash", "ua", "duration_ms", "error_type"}
)
_MAX_MESSAGE_LENGTH = 16_384


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


def _is_default(middleware: AuditMiddleware, hook: str) -> bool:
    return getattr(getattr(middleware, hook), "__func__", None) is getattr(AuditMiddleware, hook)


@contextmanager
def _audit_subject(request, entry_user) -> Iterator[bool]:
    """Yield whether to record the request, attributed to the user who made it.

    A view that ends the authentication (``django.contrib.auth.logout``)
    replaces ``request.user``; the event is then recorded for the user the
    request arrived with, and the replacement is put back afterwards.
    """
    current = getattr(request, "user", None)
    if is_authenticated(request):
        yield True
    elif current is entry_user or not getattr(entry_user, "is_authenticated", False):
        yield False
    else:
        request.user = entry_user
        try:
            yield True
        finally:
            request.user = current


class AuditMiddleware:
    """Emit one structured event for every authenticated request outcome."""

    logger_name: str = "security.audit"
    exempt_paths: tuple[str, ...] = ()
    allow_suppression: bool = False
    error_mode: AuditErrorMode = AuditErrorMode.RAISE

    def __init__(self, get_response: Callable[..., HttpResponseBase]) -> None:
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

    def __call__(self, request) -> HttpResponseBase:
        if self._is_exempt(request):
            return self.get_response(request)

        request_id = uuid.uuid4().hex
        request.META["X_REQUEST_ID"] = request_id
        entry_user = getattr(request, "user", None)
        start = time.perf_counter()
        try:
            response = self.get_response(request)
        except Exception as original:
            with _audit_subject(request, entry_user) as audited:
                if audited:
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
        with _audit_subject(request, entry_user) as audited:
            if audited:
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

    def get_audit_path(self, request) -> str:
        """Return the path recorded as evidence. Override to keep secrets carried
        in URL paths (invitation tokens, one-time codes) out of the audit trail."""
        return getattr(request, "path", "")

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
        shadowed = set(identity) & set(extra)
        if shadowed:
            raise AuditEmissionError(f"extra audit fields override identity fields: {sorted(shadowed)}")

        path = self.get_audit_path(request)
        if not isinstance(path, str):
            raise AuditEmissionError("get_audit_path() must return a string.")
        ip = get_client_ip(request)
        entry: dict[str, object] = {
            "event": event,
            "rid": request_id,
            **identity,
            "method": getattr(request, "method", ""),
            "path": path,
            "status": status,
            # An address that cannot be validated (such as a malformed forwarded
            # chain, which the client can send) is recorded as null rather than
            # losing the whole event.
            "ip_hash": hash_ip(ip, length=32) if ip else None,
            "ua": request.META.get("HTTP_USER_AGENT", ""),
            "duration_ms": duration_ms,
            **extra,
        }
        if error_type is not None:
            entry["error_type"] = error_type
        safe_entry = _safe_value(entry)
        if not isinstance(safe_entry, Mapping):  # pragma: no cover
            raise AuditEmissionError("audit entry was not a mapping.")
        if not _is_default(self, "before_log"):
            # Snapshot the evidence: the hook may edit the entry in place.
            evidence = {key: safe_entry.get(key) for key in _RESERVED}
            prepared = self.before_log(request, response, safe_entry)
            if prepared is None:
                if not self.allow_suppression:
                    raise AuditEmissionError("before_log() suppressed a required audit event.")
                return
            prepared = _safe_value(prepared)
            if not isinstance(prepared, Mapping):
                raise AuditEmissionError("before_log() must return a mapping or None.")
            if any(prepared.get(key) != evidence[key] for key in _RESERVED):
                raise AuditEmissionError("before_log() altered reserved audit evidence.")
        else:
            # The default hook returns the entry unchanged and _safe_value() is
            # idempotent, so the second pass and the evidence check are no-ops.
            prepared = safe_entry
        level = self.get_log_level(status)
        if _is_default(self, "format_entry") and type(level) is int and not self._logger.isEnabledFor(level):
            # Every check on the hooks' output has run, and the default formatter
            # cannot fail on a sanitized mapping: skip rendering a line that is
            # dropped (the length limit below only concerns a written line).
            return
        message = self._render(prepared)
        if len(message) > _MAX_MESSAGE_LENGTH:
            # Never slice structured output: keep the reserved evidence and the
            # actor, and mark the line as reduced.
            reduced = {
                key: value for key, value in prepared.items() if key in _RESERVED or key in identity
            }
            message = self._render({**reduced, "truncated": True})
            if len(message) > _MAX_MESSAGE_LENGTH:
                raise AuditEmissionError("audit entry exceeds the maximum message length.")
        prefix = "AUDIT_DENIED" if status in (401, 403) else "AUDIT"
        self._logger.log(level, "%s %s", prefix, message)

    def _render(self, entry: Mapping[str, object]) -> str:
        message = self.format_entry(entry)
        if not isinstance(message, str):
            raise AuditEmissionError("format_entry() must return a string.")
        return sanitize_for_log(message, max_length=len(message))

    def _is_exempt(self, request) -> bool:
        # Match the path Django routes on. request.path also carries SCRIPT_NAME,
        # which a server may take from a forwarded request header.
        return path_is_exempt(request.path_info, self.exempt_paths)
