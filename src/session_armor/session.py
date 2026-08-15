"""Fail-closed Django session integrity and assurance middleware."""

from __future__ import annotations

import hashlib
import hmac
import math
import secrets
import time
from collections.abc import Mapping, Sequence

from django.conf import settings
from django.http.response import HttpResponseBase
from django.shortcuts import redirect

from .assurance import AssuranceStatus, SessionAssurance
from .exceptions import SessionConfigurationError
from .utils import get_client_ip, is_authenticated, path_is_exempt

_STATE_VERSION = 1
_PREFIX = "_sa_"
_STATE_KEYS = frozenset(
    {
        "_sa_version",
        "_sa_nonce",
        "_sa_started_at",
        "_sa_seen_at",
        "_sa_binding_mac",
        "_sa_claims_mac",
    }
)


def _seconds(name: str, default: int, *, allow_zero: bool = False) -> int:
    value = getattr(settings, name, default)
    minimum = 0 if allow_zero else 1
    if isinstance(value, bool) or not isinstance(value, int) or not minimum <= value <= 31_536_000:
        qualifier = "non-negative" if allow_zero else "positive"
        raise SessionConfigurationError(
            f"{name} must be a {qualifier} integer no greater than one year."
        )
    return value


def _boolean(name: str, default: bool) -> bool:
    value = getattr(settings, name, default)
    if not isinstance(value, bool):
        raise SessionConfigurationError(f"{name} must be a boolean.")
    return value


def _key() -> bytes:
    value = getattr(settings, "SESSION_ARMOR_STATE_KEY", "") or getattr(
        settings, "SECRET_KEY", ""
    )
    try:
        encoded = value.encode("utf-8") if isinstance(value, str) else bytes(value)
    except (TypeError, ValueError) as error:
        raise SessionConfigurationError(
            "SESSION_ARMOR_STATE_KEY must be bytes or a string."
        ) from error
    if len(encoded) < 16:
        raise SessionConfigurationError(
            "SESSION_ARMOR_STATE_KEY (or SECRET_KEY) must contain at least 16 bytes."
        )
    return encoded


def _frame(values: Sequence[str]) -> bytes:
    if isinstance(values, str) or not isinstance(values, Sequence):
        raise TypeError("security inputs must be a sequence of strings.")
    if len(values) > 128:
        raise ValueError("security inputs exceed the maximum item count.")
    framed = bytearray(len(values).to_bytes(4, "big"))
    for value in values:
        if not isinstance(value, str):
            raise TypeError("security inputs must contain only strings.")
        encoded = value.encode("utf-8")
        if len(encoded) > 16_384:
            raise ValueError("a security input exceeds the maximum encoded length.")
        framed.extend(len(encoded).to_bytes(4, "big"))
        framed.extend(encoded)
    return bytes(framed)


def _mac(purpose: str, values: Sequence[str]) -> str:
    derived = hmac.new(_key(), purpose.encode("ascii"), hashlib.sha256).digest()
    return hmac.new(derived, _frame(values), hashlib.sha256).hexdigest()


def _stored_timestamp(value: object) -> float | None:
    if isinstance(value, bool) or not isinstance(value, int | float):
        return None
    result = float(value)
    if not math.isfinite(result) or result < 0:
        return None
    return result


class SessionSecurityMiddleware:
    """Continuously evaluate authenticated Django sessions and publish evidence."""

    exempt_paths: tuple[str, ...] = ()
    last_active_resolution: int | None = None

    def __init__(self, get_response):
        if not callable(get_response):
            raise TypeError("get_response must be callable.")
        self.get_response = get_response

    def __call__(self, request):
        request.session_assurance = SessionAssurance.unverified("not_evaluated")
        if self._is_exempt(request):
            request.session_assurance = SessionAssurance.unverified("exempt_path")
            return self.get_response(request)
        if not is_authenticated(request):
            request.session_assurance = SessionAssurance.unverified("unauthenticated")
            return self.get_response(request)
        if not hasattr(request, "session"):
            raise SessionConfigurationError(
                "SessionSecurityMiddleware must run after Django SessionMiddleware."
            )

        try:
            now = time.time()
            absolute_timeout = _seconds("SESSION_ARMOR_ABSOLUTE_TIMEOUT", 28_800)
            idle_timeout = _seconds("SESSION_ARMOR_IDLE_TIMEOUT", 1_800)
            clock_skew = _seconds("SESSION_ARMOR_CLOCK_SKEW", 60, allow_zero=True)
            resolution = (
                _seconds("SESSION_ARMOR_LAST_ACTIVE_RESOLUTION", 0, allow_zero=True)
                if self.last_active_resolution is None
                else self.last_active_resolution
            )
            if isinstance(resolution, bool) or not isinstance(resolution, int) or resolution < 0:
                raise SessionConfigurationError(
                    "last_active_resolution must be a non-negative integer."
                )
            if resolution >= idle_timeout:
                raise SessionConfigurationError(
                    "last-active resolution must be smaller than the idle timeout."
                )

            if "_sa_version" not in request.session:
                if any(str(key).startswith(_PREFIX) for key in request.session):
                    return self._terminate(request, "partial_security_state")
                self._init_session(request, now)

            violation = self._validate_state(
                request,
                now=now,
                absolute_timeout=absolute_timeout,
                idle_timeout=idle_timeout,
                clock_skew=clock_skew,
            )
            if violation is not None:
                if violation in {"absolute_timeout", "idle_timeout"}:
                    self.on_timeout(request, violation.removesuffix("_timeout"))
                return self._terminate(request, violation)

            previous = float(request.session["_sa_seen_at"])
            if now - previous >= resolution:
                request.session["_sa_seen_at"] = now
            request.session_assurance = self._assurance(request, now)
            response = self.get_response(request)
            if _boolean("SESSION_ARMOR_NO_STORE", True):
                response.headers.setdefault("Cache-Control", "private, no-store")
            return response
        except SessionConfigurationError:
            raise
        except Exception:
            return self._terminate(request, "session_evaluation_error")

    def get_fingerprint_factors(self, request) -> Mapping[str, str]:
        """Return named continuity signals; override to add device or mTLS signals."""

        factors: dict[str, str] = {}
        if _boolean("SESSION_ARMOR_BIND_IP", True):
            factors["ip"] = get_client_ip(request)
        if _boolean("SESSION_ARMOR_BIND_USER_AGENT", True):
            factors["user_agent"] = request.META.get("HTTP_USER_AGENT", "")
        return factors

    def get_critical_claims(self, user) -> Sequence[str]:
        """Return identity claims that must remain stable for the session."""

        return (
            str(getattr(user, "sub", "") or ""),
            str(getattr(user, "email", "") or ""),
        )

    def get_subject_identifier(self, user) -> str:
        value = getattr(user, "sub", None)
        if value is None:
            value = getattr(user, "pk", None)
        if value is None:
            value = getattr(user, "id", None)
        return "" if value is None else str(value)

    def get_login_url(self, request) -> str:
        return getattr(settings, "LOGIN_URL", "/")

    def on_violation(self, request, reason: str):
        return None

    def on_timeout(self, request, kind: str) -> None:
        return None

    def on_session_init(self, request) -> None:
        return None

    def rebaseline_claims(self, request, user=None) -> None:
        """Public API for a reviewed, legitimate server-side identity update."""

        if request.session.get("_sa_version") != _STATE_VERSION:
            raise ValueError("SessionArmor state is not initialized.")
        subject = request.user if user is None else user
        request.session["_sa_claims_mac"] = self._claims_mac(subject)

    def _factor_items(self, request) -> tuple[tuple[str, str], ...]:
        factors = self.get_fingerprint_factors(request)
        if not isinstance(factors, Mapping):
            raise TypeError("get_fingerprint_factors() must return a mapping.")
        if len(factors) > 32:
            raise ValueError("too many fingerprint factors.")
        items: list[tuple[str, str]] = []
        for name, value in sorted(factors.items()):
            if (
                not isinstance(name, str)
                or not name
                or len(name) > 64
                or not isinstance(value, str)
                or not value
            ):
                raise ValueError("fingerprint factors require bounded names and non-empty values.")
            items.append((name, value))
        if not items and _boolean("SESSION_ARMOR_REQUIRE_BINDING", True):
            raise SessionConfigurationError(
                "At least one fingerprint factor is required by SESSION_ARMOR_REQUIRE_BINDING."
            )
        return tuple(items)

    def _binding_mac(self, request) -> str:
        flattened = tuple(part for pair in self._factor_items(request) for part in pair)
        return _mac("session-armor:binding:v1", flattened)

    def _claims_mac(self, user) -> str:
        return _mac("session-armor:claims:v1", tuple(self.get_critical_claims(user)))

    def _init_session(self, request, now: float) -> None:
        request.session.cycle_key()
        for key in tuple(request.session):
            if str(key).startswith("_ss_") or str(key).startswith(_PREFIX):
                request.session.pop(key, None)
        request.session.update(
            {
                "_sa_version": _STATE_VERSION,
                "_sa_nonce": secrets.token_hex(32),
                "_sa_started_at": now,
                "_sa_seen_at": now,
                "_sa_binding_mac": self._binding_mac(request),
                "_sa_claims_mac": self._claims_mac(request.user),
            }
        )
        self.on_session_init(request)

    def _validate_state(
        self,
        request,
        *,
        now: float,
        absolute_timeout: int,
        idle_timeout: int,
        clock_skew: int,
    ) -> str | None:
        if request.session.get("_sa_version") != _STATE_VERSION:
            return "unsupported_security_state"
        if not _STATE_KEYS <= set(request.session):
            return "partial_security_state"
        nonce = request.session.get("_sa_nonce")
        if not isinstance(nonce, str) or len(nonce) != 64:
            return "invalid_security_state"
        started = _stored_timestamp(request.session.get("_sa_started_at"))
        seen = _stored_timestamp(request.session.get("_sa_seen_at"))
        if started is None or seen is None or seen < started:
            return "invalid_security_state"
        if started > now + clock_skew or seen > now + clock_skew:
            return "future_security_state"
        if now - started > absolute_timeout:
            return "absolute_timeout"
        if now - seen > idle_timeout:
            return "idle_timeout"

        stored_binding = request.session.get("_sa_binding_mac")
        stored_claims = request.session.get("_sa_claims_mac")
        if not isinstance(stored_binding, str) or not isinstance(stored_claims, str):
            return "invalid_security_state"
        if not hmac.compare_digest(self._binding_mac(request), stored_binding):
            return "fingerprint_mismatch"
        if _boolean("SESSION_ARMOR_DETECT_CLAIM_DRIFT", True) and not hmac.compare_digest(
            self._claims_mac(request.user), stored_claims
        ):
            return "claim_drift"
        return None

    def _assurance(self, request, now: float) -> SessionAssurance:
        subject = self.get_subject_identifier(request.user)
        if not subject:
            raise ValueError("an authenticated session requires a stable subject identifier.")
        factors = tuple(name for name, _value in self._factor_items(request))
        session_identifier = _mac(
            "session-armor:identifier:v1", (request.session["_sa_nonce"], subject)
        )
        return SessionAssurance(
            status=AssuranceStatus.TRUSTED,
            reason="validated",
            subject_identifier=subject,
            session_identifier=session_identifier,
            established_at=float(request.session["_sa_started_at"]),
            verified_at=now,
            last_activity_at=float(request.session["_sa_seen_at"]),
            binding_factors=factors,
            claims_bound=_boolean("SESSION_ARMOR_DETECT_CLAIM_DRIFT", True),
        )

    def _terminate(self, request, reason: str):
        request.session_assurance = SessionAssurance(
            status=AssuranceStatus.UNVERIFIED,
            reason=reason,
        )
        custom = None
        login_url = "/"
        try:
            custom = self.on_violation(request, reason)
            login_url = self.get_login_url(request)
        finally:
            request.session.flush()
        if custom is not None:
            if not isinstance(custom, HttpResponseBase):
                raise TypeError("on_violation() must return an HttpResponse or None.")
            return custom
        return redirect(login_url)

    def _is_exempt(self, request) -> bool:
        return path_is_exempt(request.path, self.exempt_paths)
