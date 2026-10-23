"""Typed, identity-bound request gates for Django middleware stacks."""

from __future__ import annotations

import logging
import math
import re
import time
from collections.abc import Callable, Mapping

from django.conf import settings
from django.http import HttpResponseForbidden
from django.http.response import HttpResponseBase

from ...assurance import AssuranceStatus, SessionAssurance
from ...decisions import GateDecision, GateOutcome
from ...exceptions import SessionConfigurationError
from .utils import is_authenticated, path_is_exempt

logger = logging.getLogger("session_armor.gate")
_GATE_ID_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}\Z")


class GateMiddleware:
    """Base class for fail-closed, cacheable workflow gates.

    ``check()`` and ``before_check()`` use :class:`GateDecision`; booleans and
    other truthy values are rejected. Cached results are scoped to both the
    authenticated subject and, when available, SessionArmor's session evidence.

    ``follow_session_exemptions = True`` also lets through requests that
    ``SessionSecurityMiddleware`` left unverified because their path is in its
    ``exempt_paths``, instead of repeating those paths here.
    """

    gate_id: str = ""
    cache_ttl_setting: str = ""
    default_cache_ttl: int = 300
    exempt_paths: tuple[str, ...] = ()
    requires_auth: bool = True
    requires_trusted_session: bool = False
    follow_session_exemptions: bool = False
    recheck_after_pass: bool = True
    sticky_pass_max_age: int | None = None
    # Lifetime cap (seconds) for a rejection produced by on_error(); None keeps the TTL.
    error_cache_ttl: int | None = None

    def __init__(self, get_response: Callable[..., HttpResponseBase]) -> None:
        if not callable(get_response):
            raise TypeError("get_response must be callable.")
        self.get_response = get_response
        self.gate_id = self.gate_id or self.__class__.__name__.lower()
        self._validate_configuration()

    def __call__(self, request) -> HttpResponseBase:
        if self._is_exempt(request) or self._is_session_exempt(request):
            return self.get_response(request)
        if self.requires_auth and not is_authenticated(request):
            return self.get_response(request)
        if self.requires_trusted_session and not bool(
            getattr(getattr(request, "session_assurance", None), "trusted", False)
        ):
            return self._reject(request, GateDecision.reject("trusted_session_required"))

        try:
            decision = self._evaluate(request)
            if decision.outcome is GateOutcome.REJECT:
                return self._reject(request, decision)
            if decision.outcome is GateOutcome.PASS:
                self.on_pass(request, decision)
        except SessionConfigurationError:
            raise
        except Exception as error:
            logger.error("Gate evaluation failed closed", exc_info=True)
            return self._reject(
                request,
                GateDecision.reject(
                    "gate_evaluation_error",
                    context={"error_type": type(error).__name__},
                ),
            )
        # Only gate evaluation fails closed; application exceptions keep Django's handling.
        return self.get_response(request)

    def _evaluate(self, request) -> GateDecision:
        precondition = self.before_check(request)
        if precondition is not None:
            self._require_decision(precondition, hook="before_check")
            if precondition.outcome is GateOutcome.PASS:
                raise TypeError("before_check() may return only GateDecision.skip/reject or None.")
            return precondition

        now = time.time()
        ttl = self._get_cache_ttl()
        version = self._state_version(request)
        scope = self.get_cache_scope(request)
        cached = self._cached_decision(request, now, ttl, version, scope)
        if cached is not None:
            return cached

        from_error = False
        try:
            decision = self.check(request)
            self._require_decision(decision, hook="check")
            if decision.outcome is GateOutcome.SKIP:
                raise TypeError("check() cannot return GateDecision.skip().")
        except Exception as error:
            from_error = True
            decision = self.on_error(request, error)
            self._require_decision(decision, hook="on_error")
            if decision.outcome is not GateOutcome.REJECT:
                raise TypeError("on_error() must return a rejecting GateDecision.")

        self.after_check(request, decision)
        self._cache(request, decision, now, version, scope, from_error=from_error)
        return decision

    def before_check(self, request) -> GateDecision | None:
        return None

    def check(self, request) -> GateDecision:
        raise NotImplementedError(f"{self.__class__.__name__} must implement check()")

    def after_check(self, request, decision: GateDecision) -> None:
        return None

    def on_reject(self, request, decision: GateDecision) -> HttpResponseBase:
        return HttpResponseForbidden("Access denied")

    def on_pass(self, request, decision: GateDecision) -> None:
        return None

    def on_error(self, request, error: Exception) -> GateDecision:
        logger.error("Gate check raised %s", type(error).__name__, exc_info=True)
        return GateDecision.reject(
            "gate_check_error", context={"error_type": type(error).__name__}
        )

    def get_state_version(self, request) -> str | None:
        return None

    def get_cache_scope(self, request) -> str | None:
        if not is_authenticated(request):
            # Only reachable with requires_auth = False: no subject to bind a result to.
            return None
        assurance = getattr(request, "session_assurance", None)
        session_identifier = getattr(assurance, "session_identifier", None)
        if isinstance(session_identifier, str) and session_identifier:
            return session_identifier
        user = getattr(request, "user", None)
        value = getattr(user, "sub", None)
        if value is None:
            value = getattr(user, "pk", None)
        if value is None:
            value = getattr(user, "id", None)
        if value is None or not str(value):
            raise ValueError("an authenticated gate requires a stable cache scope.")
        return str(value)

    @classmethod
    def invalidate(cls, request) -> None:
        prefix = f"_gate_{cls.gate_id or cls.__name__.lower()}"
        for suffix in (
            "_at",
            "_outcome",
            "_reason",
            "_context",
            "_version",
            "_scope",
            "_owner",
            "_error",
        ):
            request.session.pop(f"{prefix}{suffix}", None)
        # Remove legacy boolean results during the API migration.
        request.session.pop(f"{prefix}_result", None)

    @classmethod
    def get_context(cls, request) -> dict[str, object]:
        prefix = f"_gate_{cls.gate_id or cls.__name__.lower()}"
        value = request.session.get(f"{prefix}_context", {})
        return dict(value) if isinstance(value, Mapping) else {}

    @classmethod
    def get_cached_decision(cls, request) -> GateDecision | None:
        """Return the last stored result, or None when there is none or it is malformed.

        Its age, scope and version are not re-validated: use it to explain a rejection,
        never to grant access.
        """
        prefix = f"_gate_{cls.gate_id or cls.__name__.lower()}"
        outcome = request.session.get(f"{prefix}_outcome")
        if outcome not in (GateOutcome.PASS.value, GateOutcome.REJECT.value):
            return None
        try:
            return GateDecision(
                GateOutcome(outcome),
                request.session.get(f"{prefix}_reason"),
                request.session.get(f"{prefix}_context", {}),
            )
        except (TypeError, ValueError):
            return None

    @property
    def _cache_prefix(self) -> str:
        return f"_gate_{self.gate_id}"

    @property
    def _cache_owner(self) -> str:
        # Gate classes that share a gate_id never reuse each other's results.
        return f"{type(self).__module__}.{type(self).__qualname__}"

    def _validate_configuration(self) -> None:
        if _GATE_ID_RE.fullmatch(self.gate_id) is None:
            raise SessionConfigurationError("gate_id contains invalid characters or is too long.")
        for name in (
            "requires_auth",
            "requires_trusted_session",
            "follow_session_exemptions",
            "recheck_after_pass",
        ):
            if not isinstance(getattr(self, name), bool):
                raise SessionConfigurationError(f"{name} must be a boolean.")
        if self.sticky_pass_max_age is not None and (
            isinstance(self.sticky_pass_max_age, bool)
            or not isinstance(self.sticky_pass_max_age, int)
            or self.sticky_pass_max_age <= 0
        ):
            raise SessionConfigurationError("sticky_pass_max_age must be a positive integer.")
        if self.error_cache_ttl is not None and (
            isinstance(self.error_cache_ttl, bool)
            or not isinstance(self.error_cache_ttl, int)
            or not 1 <= self.error_cache_ttl <= 86_400
        ):
            raise SessionConfigurationError("error_cache_ttl must be between 1 and 86400 seconds.")
        path_is_exempt("/", self.exempt_paths)

    def _get_cache_ttl(self) -> int:
        value = (
            getattr(settings, self.cache_ttl_setting, self.default_cache_ttl)
            if self.cache_ttl_setting
            else self.default_cache_ttl
        )
        if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= 86_400:
            raise SessionConfigurationError("gate cache TTL must be between 1 and 86400 seconds.")
        return value

    def _state_version(self, request) -> str | None:
        version = self.get_state_version(request)
        if version is not None and (
            not isinstance(version, str) or not version or len(version) > 256
        ):
            raise TypeError("get_state_version() must return a bounded non-empty string or None.")
        return version

    def _cached_decision(self, request, now, ttl, version, scope) -> GateDecision | None:
        if scope is None:
            return None
        prefix = self._cache_prefix
        outcome_value = request.session.get(f"{prefix}_outcome")
        if outcome_value not in {GateOutcome.PASS.value, GateOutcome.REJECT.value}:
            return None
        owner = request.session.get(f"{prefix}_owner")
        if owner is not None and owner != self._cache_owner:
            logger.warning("Gate cache entry %s was written by another gate", prefix)
            return None
        if request.session.get(f"{prefix}_scope") != scope:
            self.invalidate(request)
            return None
        if version is None and request.session.get(f"{prefix}_version") is not None:
            self.invalidate(request)
            return None
        if version is not None and request.session.get(f"{prefix}_version") != version:
            self.invalidate(request)
            return None
        checked_at = request.session.get(f"{prefix}_at")
        if isinstance(checked_at, bool) or not isinstance(checked_at, int | float):
            self.invalidate(request)
            return None
        age = now - float(checked_at)
        if not math.isfinite(age) or age < 0:
            self.invalidate(request)
            return None
        outcome = GateOutcome(outcome_value)
        if outcome is GateOutcome.PASS and not self.recheck_after_pass:
            if version is None and self.sticky_pass_max_age is None:
                return None
            valid = self.sticky_pass_max_age is None or age < self.sticky_pass_max_age
        elif (
            outcome is GateOutcome.REJECT
            and self.error_cache_ttl is not None
            and request.session.get(f"{prefix}_error") is True
        ):
            valid = age < min(ttl, self.error_cache_ttl)
        else:
            valid = age < ttl
        if not valid:
            return None
        reason = request.session.get(f"{prefix}_reason")
        context = request.session.get(f"{prefix}_context", {})
        try:
            return GateDecision(outcome, reason, context)
        except (TypeError, ValueError):
            self.invalidate(request)
            return None

    def _cache(self, request, decision, now, version, scope, *, from_error=False) -> None:
        if scope is None:
            return
        prefix = self._cache_prefix
        if from_error and self.error_cache_ttl is not None:
            request.session[f"{prefix}_error"] = True
        else:
            request.session.pop(f"{prefix}_error", None)
        request.session[f"{prefix}_at"] = now
        request.session[f"{prefix}_outcome"] = decision.outcome.value
        request.session[f"{prefix}_reason"] = decision.reason
        request.session[f"{prefix}_context"] = dict(decision.context)
        request.session[f"{prefix}_scope"] = scope
        request.session[f"{prefix}_owner"] = self._cache_owner
        if version is not None:
            request.session[f"{prefix}_version"] = version
        else:
            request.session.pop(f"{prefix}_version", None)

    def _reject(self, request, decision: GateDecision) -> HttpResponseBase:
        response = self.on_reject(request, decision)
        if not isinstance(response, HttpResponseBase):
            raise TypeError("on_reject() must return an HttpResponse.")
        return response

    @staticmethod
    def _require_decision(value: object, *, hook: str) -> None:
        if not isinstance(value, GateDecision):
            raise TypeError(f"{hook}() must return a GateDecision.")

    def _is_exempt(self, request) -> bool:
        # Match the path Django routes on. request.path also carries SCRIPT_NAME,
        # which a server may take from a forwarded request header.
        return path_is_exempt(request.path_info, self.exempt_paths)

    def _is_session_exempt(self, request) -> bool:
        if not self.follow_session_exemptions:
            return False
        assurance = getattr(request, "session_assurance", None)
        return (
            isinstance(assurance, SessionAssurance)
            and assurance.status is AssuranceStatus.UNVERIFIED
            and assurance.reason == "exempt_path"
        )
