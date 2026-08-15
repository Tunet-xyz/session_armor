"""Typed session-assurance evidence for authorization and application code."""

from __future__ import annotations

import math
from collections.abc import Mapping
from dataclasses import dataclass
from enum import Enum
from types import MappingProxyType

ASSURANCE_SCHEMA = "session-armor.assurance/v1"
ASSURANCE_CONTEXT_KEY = "session_assurance"


class AssuranceStatus(str, Enum):
    """Whether SessionArmor established trust for the current request."""

    TRUSTED = "trusted"
    UNVERIFIED = "unverified"


def _timestamp(value: float | None, *, field_name: str) -> float | None:
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, int | float):
        raise TypeError(f"{field_name} must be a number or None.")
    result = float(value)
    if not math.isfinite(result) or result < 0:
        raise ValueError(f"{field_name} must be a finite non-negative timestamp.")
    return result


@dataclass(frozen=True, slots=True)
class SessionAssurance:
    """Immutable evidence produced after SessionArmor evaluates a request.

    The object contains signals, never raw fingerprint inputs, claim values,
    cookies, or tokens. :meth:`to_authorization_context` is the stable bridge
    consumed by AccessGate and other framework-neutral policy engines.
    """

    status: AssuranceStatus
    reason: str
    subject_identifier: str | None = None
    session_identifier: str | None = None
    established_at: float | None = None
    verified_at: float | None = None
    last_activity_at: float | None = None
    binding_factors: tuple[str, ...] = ()
    claims_bound: bool = False

    def __post_init__(self) -> None:
        if not isinstance(self.status, AssuranceStatus):
            raise TypeError("status must be an AssuranceStatus value.")
        if not isinstance(self.reason, str) or not self.reason or len(self.reason) > 128:
            raise ValueError("reason must be a non-empty string of at most 128 characters.")
        for field_name in ("subject_identifier", "session_identifier"):
            value = getattr(self, field_name)
            if value is not None and (not isinstance(value, str) or not value or len(value) > 512):
                raise ValueError(f"{field_name} must be a bounded non-empty string or None.")
        for field_name in ("established_at", "verified_at", "last_activity_at"):
            object.__setattr__(
                self,
                field_name,
                _timestamp(getattr(self, field_name), field_name=field_name),
            )
        if not isinstance(self.binding_factors, tuple) or not all(
            isinstance(value, str) and value and len(value) <= 64
            for value in self.binding_factors
        ):
            raise TypeError("binding_factors must be a tuple of bounded non-empty strings.")
        if len(set(self.binding_factors)) != len(self.binding_factors):
            raise ValueError("binding_factors must not contain duplicates.")
        if not isinstance(self.claims_bound, bool):
            raise TypeError("claims_bound must be a boolean.")
        if self.status is AssuranceStatus.TRUSTED:
            required = (
                self.subject_identifier,
                self.session_identifier,
                self.established_at,
                self.verified_at,
                self.last_activity_at,
            )
            if any(value is None for value in required):
                raise ValueError("trusted assurance requires complete session evidence.")

    @property
    def trusted(self) -> bool:
        return self.status is AssuranceStatus.TRUSTED

    @classmethod
    def unverified(cls, reason: str) -> SessionAssurance:
        return cls(status=AssuranceStatus.UNVERIFIED, reason=reason)

    def to_authorization_context(self) -> Mapping[str, object]:
        """Return the versioned, primitive-only AccessGate interoperability shape."""

        return MappingProxyType(
            {
                "schema": ASSURANCE_SCHEMA,
                "status": self.status.value,
                "reason": self.reason,
                "subject_identifier": self.subject_identifier,
                "session_identifier": self.session_identifier,
                "established_at": self.established_at,
                "verified_at": self.verified_at,
                "last_activity_at": self.last_activity_at,
                "binding_factors": self.binding_factors,
                "claims_bound": self.claims_bound,
            }
        )
