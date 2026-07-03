"""
SessionArmor — defense-grade Django middleware.

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

from .audit import AuditMiddleware
from .gate import GateMiddleware
from .session import SessionSecurityMiddleware

__all__ = [
    "GateMiddleware",
    "SessionSecurityMiddleware",
    "AuditMiddleware",
]

__version__ = "0.1.0"
