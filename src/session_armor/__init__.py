"""
SessionArmor — security-focused Django session middleware.

Session security, audit logging, and configurable request gates with hooks.

Three middleware classes, one base class:

    SessionSecurityMiddleware
        Fingerprint binding, absolute/idle timeouts, claim drift detection.

    AuditMiddleware
        Privacy-preserving audit trail for every authenticated request.

    GateMiddleware
        Base class for building cacheable, hookable conditional gates
        (compliance, onboarding, feature flags, maintenance, etc.).
"""

from .assurance import (
    ASSURANCE_CONTEXT_KEY,
    ASSURANCE_SCHEMA,
    AssuranceStatus,
    SessionAssurance,
)
from .audit import AuditErrorMode, AuditMiddleware
from .exceptions import AuditEmissionError, SessionArmorError, SessionConfigurationError
from .gate import GateDecision, GateMiddleware, GateOutcome
from .session import SessionSecurityMiddleware

__all__ = [
    "GateMiddleware",
    "GateDecision",
    "GateOutcome",
    "SessionSecurityMiddleware",
    "AuditMiddleware",
    "AuditErrorMode",
    "ASSURANCE_CONTEXT_KEY",
    "ASSURANCE_SCHEMA",
    "AssuranceStatus",
    "SessionAssurance",
    "SessionArmorError",
    "SessionConfigurationError",
    "AuditEmissionError",
]

__version__ = "0.4.0"
