"""Framework-neutral session-assurance contracts with an optional Django adapter for session integrity, privacy-aware audit logging, and configurable request gates."""

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

__version__ = "1.0.0"
