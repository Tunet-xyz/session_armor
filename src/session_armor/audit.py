"""
AuditMiddleware — security audit trail for Django requests.

Logs every authenticated request with security-relevant context for
forensic analysis, anomaly detection, and compliance reporting.

Every log entry captures **WHO** did **WHAT** from **WHERE**, enabling:
- Post-incident forensics
- Real-time anomaly detection (via log aggregation / SIEM)
- Compliance reporting (NIST 800-53 AU-3, AU-12; SOC 2)

Never logs request bodies, tokens, or credentials.

Hooks (override in subclass)::

    get_user_identity(request)              → dict
    get_extra_fields(request, response)     → dict
    before_log(request, response, entry)    → dict | None
    get_log_level(status_code)              → int
    format_entry(entry)                     → str

Usage::

    # Generic
    MIDDLEWARE = [..., 'session_armor.audit.AuditMiddleware', ...]

    # Customized (e.g. Auth0-aware)
    class MyAudit(AuditMiddleware):
        def get_user_identity(self, request):
            return {
                'uid': request.user.sub,
                'tenant': request.user.organization_uuid,
            }
"""

import logging
import time
import uuid

from .utils import (
    get_client_ip,
    hash_ip,
    is_authenticated,
    path_is_exempt,
    sanitize_for_log,
)

logger = logging.getLogger("security.audit")


class AuditMiddleware:
    """
    Audit logging for authenticated requests.

    Captures:
        Request ID, user identity, method, path, status, hashed IP,
        truncated user-agent, and request duration.

    Does NOT capture:
        Request/response bodies, tokens, passwords, query parameters.
    """

    # ── Configuration ────────────────────────────────────────────────────
    logger_name: str = "security.audit"
    exempt_paths: tuple[str, ...] = ()

    # ── Django middleware protocol ────────────────────────────────────────

    def __init__(self, get_response):
        self.get_response = get_response
        self._logger = logging.getLogger(self.logger_name)

    def __call__(self, request):
        if self._is_exempt(request):
            return self.get_response(request)

        # Attach request ID for correlation
        request_id = str(uuid.uuid4())[:8]
        request.META["X_REQUEST_ID"] = request_id
        start = time.time()

        response = self.get_response(request)

        duration_ms = round((time.time() - start) * 1000)

        # Only audit authenticated requests
        if is_authenticated(request):
            self._emit(request, response, request_id, duration_ms)

        return response

    # ── HOOKS (override in subclass) ─────────────────────────────────────

    def get_user_identity(self, request) -> dict:
        """
        Extract user identity fields for the audit log entry.

        Override to match your auth system's user model.
        Default returns ``{'uid': user.pk}``.
        """
        user = request.user
        return {
            "uid": getattr(user, "sub", None) or str(getattr(user, "pk", "")),
        }

    def get_extra_fields(self, request, response) -> dict:
        """Return additional fields to include in the audit entry."""
        return {}

    def before_log(self, request, response, entry: dict) -> dict | None:
        """
        Called before the entry is logged.

        Return the (optionally modified) entry, or ``None`` to suppress
        logging for this request.
        """
        return entry

    def get_log_level(self, status_code: int) -> int:
        """Return the ``logging`` level for a given response status code."""
        if status_code >= 500:
            return logging.ERROR
        if status_code in (401, 403):
            return logging.WARNING
        if status_code >= 400:
            return logging.INFO
        return logging.DEBUG

    def format_entry(self, entry: dict) -> str:
        """
        Format the audit entry for the log message.

        Override to produce structured JSON, CEF, or other formats.
        """
        return f"AUDIT {entry}"

    # ── INTERNALS ────────────────────────────────────────────────────────

    def _emit(self, request, response, request_id: str, duration_ms: int):
        ip = get_client_ip(request)

        entry = {
            "rid": request_id,
            **self.get_user_identity(request),
            "method": request.method,
            "path": sanitize_for_log(request.path, max_length=500),
            "status": response.status_code,
            "ip_hash": hash_ip(ip, length=16),
            "ua": sanitize_for_log(request.META.get("HTTP_USER_AGENT", ""), max_length=80),
            "ms": duration_ms,
            **self.get_extra_fields(request, response),
        }

        entry = self.before_log(request, response, entry)
        if entry is None:
            return

        # Defense-in-depth: sanitize *every* string value, not just path/ua.
        # Custom identity and extra fields (e.g. a JWT ``sub`` claim) are
        # otherwise attacker-influenced and could forge log lines via embedded
        # newlines/control characters.
        entry = {
            key: sanitize_for_log(value, max_length=500) if isinstance(value, str) else value
            for key, value in entry.items()
        }

        level = self.get_log_level(response.status_code)
        message = self.format_entry(entry)

        if response.status_code in (401, 403):
            self._logger.log(level, message.replace("AUDIT", "AUDIT_DENIED", 1))
        else:
            self._logger.log(level, message)

    def _is_exempt(self, request) -> bool:
        return path_is_exempt(request.path, self.exempt_paths)
