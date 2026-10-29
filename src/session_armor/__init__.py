"""SessionArmor's framework-neutral session-assurance contracts."""

from .assurance import (
    ASSURANCE_CONTEXT_KEY,
    ASSURANCE_SCHEMA,
    AssuranceStatus,
    SessionAssurance,
)
from .decisions import GateDecision, GateOutcome
from .exceptions import AuditEmissionError, SessionArmorError, SessionConfigurationError

__all__ = [
    "ASSURANCE_CONTEXT_KEY",
    "ASSURANCE_SCHEMA",
    "AssuranceStatus",
    "AuditEmissionError",
    "GateDecision",
    "GateOutcome",
    "SessionArmorError",
    "SessionAssurance",
    "SessionConfigurationError",
]

__version__ = "0.6.0"
