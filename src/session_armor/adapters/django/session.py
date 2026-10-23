"""Fail-closed Django session integrity and assurance middleware."""

from __future__ import annotations

import functools
import hashlib
import hmac
import logging
import math
import secrets
import time
from collections.abc import Callable, Mapping, Sequence

from django.conf import settings
from django.http.response import HttpResponseBase
from django.shortcuts import redirect
from django.utils.functional import Promise

from ...assurance import AssuranceStatus, SessionAssurance
from ...exceptions import SessionConfigurationError
from .utils import _secret_bytes, get_client_ip, hash_ip, is_authenticated, path_is_exempt

_STATE_VERSION = 1
logger = logging.getLogger("session_armor.session")
_PREFIX = "_sa_"
# Bound in place of an absent or empty User-Agent. A valid header value cannot
# contain NUL, so a session started with a User-Agent never matches one without.
_NO_USER_AGENT = "\x00absent"
_STATE_KEYS = frozenset(
    {
        "_sa_version",
        "_sa_nonce",
        "_sa_started_at",
        "_sa_seen_at",
        "_sa_binding_mac",
        "_sa_claims_mac",
        "_sa_state_mac",
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
    return _secret_bytes(value, "SESSION_ARMOR_STATE_KEY (or SECRET_KEY)")


def _fallback_keys() -> tuple[bytes, ...]:
    """Retired state keys: accepted to verify existing state, never to sign."""

    configured = getattr(settings, "SESSION_ARMOR_STATE_KEY_FALLBACKS", None)
    if configured is not None:
        if isinstance(configured, str | bytes | bytearray) or not isinstance(configured, Sequence):
            raise SessionConfigurationError(
                "SESSION_ARMOR_STATE_KEY_FALLBACKS must be a sequence of keys."
            )
        return tuple(
            _secret_bytes(value, "Each SESSION_ARMOR_STATE_KEY_FALLBACKS key")
            for value in configured
        )
    state_key = getattr(settings, "SESSION_ARMOR_STATE_KEY", "")
    if state_key and state_key != getattr(settings, "SECRET_KEY", ""):
        return ()
    # A state key that follows SECRET_KEY follows Django's documented rotation
    # too. An entry unusable as a state key is skipped: state signed with it
    # fails closed, as it did before fallbacks were read.
    keys = []
    for value in getattr(settings, "SECRET_KEY_FALLBACKS", None) or ():
        try:
            keys.append(_secret_bytes(value, "SECRET_KEY_FALLBACKS"))
        except SessionConfigurationError:
            continue
    return tuple(keys)


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


@functools.lru_cache(maxsize=64)
def _subkey(key: bytes, purpose: str) -> bytes:
    # Keyed on the key bytes, so a rotated or overridden key derives afresh.
    return hmac.digest(key, purpose.encode("ascii"), hashlib.sha256)


def _mac(purpose: str, values: Sequence[str], *, key: bytes | None = None) -> str:
    # Purposes stay in the "session-armor:" namespace, which hash_ip() separates.
    derived = _subkey(_key() if key is None else key, purpose)
    return hmac.digest(derived, _frame(values), hashlib.sha256).hex()


def _verified_with(compute: Callable[[bytes | None], str], stored: str) -> bool | None:
    """True if ``stored`` verifies with the current key, False if only with a
    fallback key, None if with neither."""

    if hmac.compare_digest(compute(None), stored):
        return True
    for key in _fallback_keys():
        if hmac.compare_digest(compute(key), stored):
            return False
    return None


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

    def __init__(self, get_response: Callable[..., HttpResponseBase]) -> None:
        if not callable(get_response):
            raise TypeError("get_response must be callable.")
        self.get_response = get_response

    def __call__(self, request) -> HttpResponseBase:
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

        violation = None
        try:
            now = time.time()
            absolute_timeout = _seconds("SESSION_ARMOR_ABSOLUTE_TIMEOUT", 28_800)
            idle_timeout = _seconds("SESSION_ARMOR_IDLE_TIMEOUT", 1_800)
            clock_skew = _seconds("SESSION_ARMOR_CLOCK_SKEW", 60, allow_zero=True)
            # Fallbacks are otherwise read only after a MAC mismatch, where a
            # malformed value would replace the violation's termination with a
            # configuration error. Validate them with the other settings.
            _fallback_keys()
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
                if any(str(key).startswith(_PREFIX) for key in request.session.keys()):
                    violation = "partial_security_state"
                else:
                    self._init_session(request, now)

            if violation is None:
                violation = self._validate_state(
                    request,
                    now=now,
                    absolute_timeout=absolute_timeout,
                    idle_timeout=idle_timeout,
                    clock_skew=clock_skew,
                )
            if violation is None:
                previous = float(request.session["_sa_seen_at"])
                if now - previous >= resolution:
                    request.session["_sa_seen_at"] = now
                    request.session["_sa_state_mac"] = self._state_mac(request)
                request.session_assurance = self._assurance(request, now)
                enforce_no_store = _boolean("SESSION_ARMOR_NO_STORE", True)
        except SessionConfigurationError:
            raise
        except Exception:
            # Fail closed, but keep the cause diagnosable. The record adds no
            # request path, header or claim value of its own.
            logger.warning("SessionArmor session evaluation failed", exc_info=True)
            violation = "session_evaluation_error"

        # Terminate once, outside the containment above: a session that cannot
        # be invalidated propagates rather than being reported a second time.
        if violation is not None:
            if violation in {"absolute_timeout", "idle_timeout"}:
                try:
                    self.on_timeout(request, violation.removesuffix("_timeout"))
                except Exception:
                    logger.exception("SessionArmor timeout hook failed")
            return self._terminate(request, violation)

        # Application exceptions retain their normal Django behavior. Only the
        # security evaluation above is contained as a session violation.
        response = self.get_response(request)
        if enforce_no_store:
            response.headers.setdefault("Cache-Control", "private, no-store")
        return response

    def get_fingerprint_factors(self, request) -> Mapping[str, str]:
        """Return named continuity signals; override to add device or mTLS signals."""

        factors: dict[str, str] = {}
        if _boolean("SESSION_ARMOR_BIND_IP", True):
            factors["ip"] = get_client_ip(request)
        if _boolean("SESSION_ARMOR_BIND_USER_AGENT", True):
            factors["user_agent"] = request.META.get("HTTP_USER_AGENT", "") or _NO_USER_AGENT
        return factors

    def binding_digests(self, request) -> dict[str, str]:
        """Per-factor keyed digests of the current fingerprint, for diagnostics only.

        Each value is ``hash_ip(value, length=12)`` (audit pepper), so the ``ip``
        digest is a prefix of the audit ``ip_hash``. Raw factor values never leave.
        """

        return {name: hash_ip(value, length=12) for name, value in self._factor_items(request)}

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

    def on_violation(self, request, reason: str) -> HttpResponseBase | None:
        return None

    def on_timeout(self, request, kind: str) -> None:
        return None

    def on_session_init(self, request) -> None:
        return None

    @staticmethod
    def has_state(session) -> bool:
        """Whether ``session`` holds this release's state (what rebaseline_claims() needs)."""

        return bool(session.get("_sa_version") == _STATE_VERSION)

    @staticmethod
    def discard_state(session) -> None:
        """Forget SessionArmor state, current and legacy, at an authentication boundary."""

        for key in tuple(session.keys()):
            if str(key).startswith("_ss_") or str(key).startswith(_PREFIX):
                session.pop(key, None)

    def rebaseline_claims(self, request, user=None, *, refresh_assurance: bool = False) -> None:
        """Public API for a reviewed, legitimate server-side identity update.

        ``user`` defaults to ``request.user``. With ``refresh_assurance=True`` the
        request's trusted evidence is also re-verified and re-issued (reason
        ``claims_rebaselined``), as :meth:`refresh_assurance` does.
        """

        if request.session.get("_sa_version") != _STATE_VERSION:
            raise ValueError("SessionArmor state is not initialized.")
        subject = request.user if user is None else user
        request.session["_sa_claims_mac"] = self._claims_mac(subject)
        request.session["_sa_state_mac"] = self._state_mac(request, user=subject)
        if refresh_assurance:
            self._reissue_assurance(request, subject, "claims_rebaselined")

    def refresh_assurance(self, request, user=None) -> SessionAssurance | None:
        """Re-verify this request's session now and re-issue its evidence.

        Call it right before an authorization decision that runs long after the
        middleware. Only evidence this middleware already trusts is refreshed, so a
        refresh keeps or withdraws trust but never grants it; otherwise the request
        is left unchanged and None is returned. It never writes, flushes or
        redirects: on a violation the evidence becomes UNVERIFIED and the next
        request terminates the session normally.
        """

        return self._reissue_assurance(request, user, "reverified")

    def _reissue_assurance(self, request, user, reason: str) -> SessionAssurance | None:
        current = getattr(request, "session_assurance", None)
        if not isinstance(current, SessionAssurance) or not current.trusted:
            return None
        subject = request.user if user is None else user
        try:
            now = time.time()
            violation = self._validate_state(
                request,
                now=now,
                absolute_timeout=_seconds("SESSION_ARMOR_ABSOLUTE_TIMEOUT", 28_800),
                idle_timeout=_seconds("SESSION_ARMOR_IDLE_TIMEOUT", 1_800),
                clock_skew=_seconds("SESSION_ARMOR_CLOCK_SKEW", 60, allow_zero=True),
                user=subject,
            )
            if violation is None and (
                self.get_subject_identifier(subject) != current.subject_identifier
            ):
                violation = "subject_changed"
            evidence = (
                SessionAssurance.unverified(violation)
                if violation is not None
                else self._assurance(request, now, reason=reason, user=subject)
            )
        except SessionConfigurationError:
            raise
        except Exception:
            # As in __call__: withdraw trust, but keep the cause diagnosable.
            logger.warning("SessionArmor session re-verification failed", exc_info=True)
            evidence = SessionAssurance.unverified("session_evaluation_error")
        request.session_assurance = evidence
        return evidence

    def establish(self, request, user=None) -> None:
        """Bind the session while the login request is still being answered.

        Call it from the login view once the session holds the new identity
        (after ``login()`` or its equivalent), passing the user the next
        request will see. The cookie the login response sets is then already
        bound to this client. Otherwise the first later request presenting
        that cookie, from any client, sets the baseline, and with a stateless
        backend such as signed cookies the unbound cookie stays usable until
        it expires. Assurance evidence is published from the next request.
        """

        if not hasattr(request, "session"):
            raise SessionConfigurationError("establish() requires Django SessionMiddleware.")
        subject = request.user if user is None else user
        if not self.get_subject_identifier(subject):
            raise ValueError("establish() requires a subject identifier.")
        self._init_session(request, time.time(), user=subject)

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

    def _binding_mac(self, request, *, key: bytes | None = None) -> str:
        flattened = tuple(part for pair in self._factor_items(request) for part in pair)
        return _mac("session-armor:binding:v1", flattened, key=key)

    def _claims_mac(self, user, *, key: bytes | None = None) -> str:
        claims = self.get_critical_claims(user)
        if isinstance(claims, str) or not isinstance(claims, Sequence):
            raise TypeError("get_critical_claims() must return a sequence of strings.")
        return _mac("session-armor:claims:v1", tuple(claims), key=key)

    def _state_mac(self, request, *, user=None, key: bytes | None = None) -> str:
        subject = request.user if user is None else user
        values = (
            str(request.session.get("_sa_version", "")),
            str(request.session.get("_sa_nonce", "")),
            format(float(request.session.get("_sa_started_at", 0)), ".17g"),
            format(float(request.session.get("_sa_seen_at", 0)), ".17g"),
            str(request.session.get("_sa_binding_mac", "")),
            str(request.session.get("_sa_claims_mac", "")),
            self.get_subject_identifier(subject),
        )
        return _mac("session-armor:state:v1", values, key=key)

    def _init_session(self, request, now: float, *, user=None) -> None:
        subject = request.user if user is None else user
        request.session.cycle_key()
        self.discard_state(request.session)
        request.session.update(
            {
                "_sa_version": _STATE_VERSION,
                "_sa_nonce": secrets.token_hex(32),
                "_sa_started_at": now,
                "_sa_seen_at": now,
                "_sa_binding_mac": self._binding_mac(request),
                "_sa_claims_mac": self._claims_mac(subject),
            }
        )
        request.session["_sa_state_mac"] = self._state_mac(request, user=subject)
        self.on_session_init(request)

    def _validate_state(
        self,
        request,
        *,
        now: float,
        absolute_timeout: int,
        idle_timeout: int,
        clock_skew: int,
        user=None,
    ) -> str | None:
        if request.session.get("_sa_version") != _STATE_VERSION:
            return "unsupported_security_state"
        if not _STATE_KEYS <= set(request.session.keys()):
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
        stored_state = request.session.get("_sa_state_mac")
        if (
            not isinstance(stored_binding, str)
            or not isinstance(stored_claims, str)
            or not isinstance(stored_state, str)
        ):
            return "invalid_security_state"
        state = _verified_with(
            lambda key: self._state_mac(request, user=user, key=key), stored_state
        )
        if state is None:
            return "state_integrity_failure"
        binding = _verified_with(lambda key: self._binding_mac(request, key=key), stored_binding)
        if binding is None:
            return "fingerprint_mismatch"
        claims_user = request.user if user is None else user
        claims: bool | None = True
        if _boolean("SESSION_ARMOR_DETECT_CLAIM_DRIFT", True):
            claims = _verified_with(
                lambda key: self._claims_mac(claims_user, key=key), stored_claims
            )
            if claims is None:
                return "claim_drift"
        if not (state and binding and claims):
            # Verified with a retired key: re-sign what was verified with the
            # current key, so the fallback is needed for one request only.
            if not binding:
                request.session["_sa_binding_mac"] = self._binding_mac(request)
            if not claims:
                request.session["_sa_claims_mac"] = self._claims_mac(claims_user)
            request.session["_sa_state_mac"] = self._state_mac(request, user=user)
        return None

    def _assurance(
        self, request, now: float, *, reason: str = "validated", user=None
    ) -> SessionAssurance:
        subject = self.get_subject_identifier(request.user if user is None else user)
        if not subject:
            raise ValueError("an authenticated session requires a stable subject identifier.")
        factors = tuple(name for name, _value in self._factor_items(request))
        session_identifier = _mac(
            "session-armor:identifier:v1", (request.session["_sa_nonce"], subject)
        )
        # Stored times may lead this clock by up to SESSION_ARMOR_CLOCK_SKEW (another
        # instance wrote them); evidence never reports activity after its verification.
        return SessionAssurance(
            status=AssuranceStatus.TRUSTED,
            reason=reason,
            subject_identifier=subject,
            session_identifier=session_identifier,
            established_at=min(float(request.session["_sa_started_at"]), now),
            verified_at=now,
            last_activity_at=min(float(request.session["_sa_seen_at"]), now),
            binding_factors=factors,
            claims_bound=_boolean("SESSION_ARMOR_DETECT_CLAIM_DRIFT", True),
        )

    def _terminate(self, request, reason: str) -> HttpResponseBase:
        request.session_assurance = SessionAssurance(
            status=AssuranceStatus.UNVERIFIED,
            reason=reason,
        )
        custom = None
        login_url = "/"
        try:
            custom = self.on_violation(request, reason)
        except Exception:
            logger.exception("SessionArmor violation hook failed")
        try:
            candidate = self.get_login_url(request)
            if isinstance(candidate, Promise):
                # LOGIN_URL may be lazy, e.g. reverse_lazy("login").
                candidate = str(candidate)
            if isinstance(candidate, str) and candidate:
                login_url = candidate
        except Exception:
            logger.exception("SessionArmor login URL hook failed")
        try:
            request.session.flush()
        except Exception as error:
            raise RuntimeError("SessionArmor could not invalidate the session.") from error
        if custom is not None:
            if isinstance(custom, HttpResponseBase):
                return custom
            logger.error("SessionArmor ignored an invalid violation-hook response")
        return redirect(login_url)

    def _is_exempt(self, request) -> bool:
        # Match the path Django routes on. request.path also carries SCRIPT_NAME,
        # which a server may take from a forwarded request header.
        return path_is_exempt(request.path_info, self.exempt_paths)
