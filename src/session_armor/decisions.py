"""Framework-neutral, typed gate decisions."""

from __future__ import annotations

import math
import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from enum import Enum
from types import MappingProxyType


class GateOutcome(str, Enum):
    """Explicit gate outcome; arbitrary truthy values are never accepted."""

    # This is an authorization outcome label, not a credential.
    PASS = "pass"  # nosec B105
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
    """A validated, framework-neutral gate result."""

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
        cls,
        reason: str = "requirements_not_satisfied",
        *,
        context: Mapping[str, object] | None = None,
    ) -> GateDecision:
        return cls(GateOutcome.REJECT, reason, context or {})

    @classmethod
    def skip(cls, reason: str = "not_applicable") -> GateDecision:
        return cls(GateOutcome.SKIP, reason)
