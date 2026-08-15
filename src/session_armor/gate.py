"""Typed, identity-bound request gates for Django middleware stacks."""

from __future__ import annotations

import logging
import math
import re
import time
from collections.abc import Mapping
from dataclasses import dataclass, field
from enum import Enum
from types import MappingProxyType

from django.conf import settings
from django.http import HttpResponseForbidden
from django.http.response import HttpResponseBase

from .exceptions import SessionConfigurationError
from .utils import is_authenticated, path_is_exempt

logger = logging.getLogger("session_armor.gate")
_GATE_ID_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}\Z")


class GateOutcome(str, Enum):
    """Explicit gate outcome; arbitrary truthy values are never accepted."""

    PASS = "pass"
    REJECT = "reject"
    SKIP = "skip"


def _freeze_context(value: Mapping[str, object]) -> Mapping[str, object]:
    if not isinstance(value, Mapping) or len(value) > 64:
        raise TypeError("gate context must be a mapping with at most 64 fields.")
    frozen: dict[str, object] = {}
    for key, item in value.items():
        if not isinstance(key, str) or not key or len(key) > 128:
            raise TypeError("gate context keys must be bounded non-empty strings.")
        if item is None or isinstance(item, bool | int | float | str):
            if isinstance(item, float) and not math.isfinite(item):
                raise ValueError("gate context numbers must be finite.")
            if isinstance(item, str) and len(item) > 2_048:
                raise ValueError("gate context strings are too long.")
            frozen[key] = item
        elif isinstance(item, list | tuple) and len(item) <= 128 and all(
            child is None or isinstance(child, bool | int | float | str) for child in item
        ):
            frozen[key] = tuple(item)
        else:
            raise TypeError("gate context values must be bounded JSON primitives.")
    return MappingProxyType(frozen)


@dataclass(frozen=True, slots=True)
class GateDecision:
    """A validated gate result with a machine-readable reason."""

    outcome: GateOutcome
    reason: str
    context: Mapping[str, object] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not isinstance(self.outcome, GateOutcome):
            raise TypeError("gate outcome must be a GateOutcome value.")
        if (
            not isinstance(self.reason, str)
            or re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}", self.reason) is None
        ):
            raise ValueError("gate reason must be a bounded machine-readable identifier.")
        object.__setattr__(self, "context", _freeze_context(self.context))

    @property
    def passed(self) -> bool:
        return self.outcome is GateOutcome.PASS

    @classmethod
    def allow(cls, reason: str = "requirements_satisfied") -> GateDecision:
        return cls(GateOutcome.PASS, reason)

    @classmethod
    def reject(
        cls, reason: str = "requirements_not_satisfied", *, context: Mapping[str, object] | None = None
    ) -> GateDecision:
        return cls(GateOutcome.REJECT, reason, context or {})

    @classmethod
    def skip(cls, reason: str = "not_applicable") -> GateDecision:
        return cls(GateOutcome.SKIP, reason)


class GateMiddleware:
    """Base class for fail-closed, cacheable workflow gates.

    ``check()`` and ``before_check()`` use :class:`GateDecision`; booleans and
    other truthy values are rejected. Cached results are scoped to both the
    authenticated subject and, when available, SessionArmor's session evidence.
    """

    gate_id: str = ""
    cache_ttl_setting: str = ""
    default_cache_ttl: int = 300
    exempt_paths: tuple[str, ...] = ()
    requires_auth: bool = True
    requires_trusted_session: bool = False
    recheck_after_pass: bool = True
    sticky_pass_max_age: int | None = None

    def __init__(self, get_response):
        if not callable(get_response):
            raise TypeError("get_response must be callable.")
        self.get_response = get_response
        self.gate_id = self.gate_id or self.__class__.__name__.lower()
        self._validate_configuration()

    def __call__(self, request):
        if self._is_exempt(request):
            return self.get_response(request)
        if self.requires_auth and not is_authenticated(request):
            return self.get_response(request)
        if self.requires_trusted_session and not bool(
            getattr(getattr(request, "session_assurance", None), "trusted", False)
        ):
            return self._reject(request, GateDecision.reject("trusted_session_required"))

        try:
            precondition = self.before_check(request)
            if precondition is not None:
                self._require_decision(precondition, hook="before_check")
                if precondition.outcome is GateOutcome.SKIP:
                    return self.get_response(request)
                if precondition.outcome is GateOutcome.REJECT:
                    return self._reject(request, precondition)
                raise TypeError("before_check() may return only GateDecision.skip/reject or None.")

            now = time.time()
            ttl = self._get_cache_ttl()
            version = self._state_version(request)
            scope = self.get_cache_scope(request)
            cached = self._cached_decision(request, now, ttl, version, scope)
            if cached is not None:
                return self._apply(request, cached)

            try:
                decision = self.check(request)
                self._require_decision(decision, hook="check")
                if decision.outcome is GateOutcome.SKIP:
                    raise TypeError("check() cannot return GateDecision.skip().")
            except Exception as error:
                decision = self.on_error(request, error)
                self._require_decision(decision, hook="on_error")
                if decision.outcome is not GateOutcome.REJECT:
                    raise TypeError("on_error() must return a rejecting GateDecision.")

            self.after_check(request, decision)
            self._cache(request, decision, now, version, scope)
            return self._apply(request, decision)
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

    def before_check(self, request) -> GateDecision | None:
        return None

    def check(self, request) -> GateDecision:
        raise NotImplementedError(f"{self.__class__.__name__} must implement check()")

    def after_check(self, request, decision: GateDecision) -> None:
        return None

    def on_reject(self, request, decision: GateDecision):
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

    def get_cache_scope(self, request) -> str:
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
        for suffix in ("_at", "_outcome", "_reason", "_context", "_version", "_scope"):
            request.session.pop(f"{prefix}{suffix}", None)
        # Remove legacy boolean results during the API migration.
        request.session.pop(f"{prefix}_result", None)

    @classmethod
    def get_context(cls, request) -> dict[str, object]:
        prefix = f"_gate_{cls.gate_id or cls.__name__.lower()}"
        value = request.session.get(f"{prefix}_context", {})
        return dict(value) if isinstance(value, Mapping) else {}

    @property
    def _cache_prefix(self) -> str:
        return f"_gate_{self.gate_id}"

    def _validate_configuration(self) -> None:
        if _GATE_ID_RE.fullmatch(self.gate_id) is None:
            raise SessionConfigurationError("gate_id contains invalid characters or is too long.")
        for name in ("requires_auth", "requires_trusted_session", "recheck_after_pass"):
            if not isinstance(getattr(self, name), bool):
                raise SessionConfigurationError(f"{name} must be a boolean.")
        if self.sticky_pass_max_age is not None and (
            isinstance(self.sticky_pass_max_age, bool)
            or not isinstance(self.sticky_pass_max_age, int)
            or self.sticky_pass_max_age <= 0
        ):
            raise SessionConfigurationError("sticky_pass_max_age must be a positive integer.")
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
        prefix = self._cache_prefix
        outcome_value = request.session.get(f"{prefix}_outcome")
        if outcome_value not in {GateOutcome.PASS.value, GateOutcome.REJECT.value}:
            return None
        if request.session.get(f"{prefix}_scope") != scope:
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

    def _cache(self, request, decision, now, version, scope) -> None:
        prefix = self._cache_prefix
        request.session[f"{prefix}_at"] = now
        request.session[f"{prefix}_outcome"] = decision.outcome.value
        request.session[f"{prefix}_reason"] = decision.reason
        request.session[f"{prefix}_context"] = dict(decision.context)
        request.session[f"{prefix}_scope"] = scope
        if version is not None:
            request.session[f"{prefix}_version"] = version
        else:
            request.session.pop(f"{prefix}_version", None)

    def _apply(self, request, decision: GateDecision):
        if decision.outcome is GateOutcome.REJECT:
            return self._reject(request, decision)
        self.on_pass(request, decision)
        return self.get_response(request)

    def _reject(self, request, decision: GateDecision):
        response = self.on_reject(request, decision)
        if not isinstance(response, HttpResponseBase):
            raise TypeError("on_reject() must return an HttpResponse.")
        return response

    @staticmethod
    def _require_decision(value: object, *, hook: str) -> None:
        if not isinstance(value, GateDecision):
            raise TypeError(f"{hook}() must return a GateDecision.")

    def _is_exempt(self, request) -> bool:
        return path_is_exempt(request.path, self.exempt_paths)
