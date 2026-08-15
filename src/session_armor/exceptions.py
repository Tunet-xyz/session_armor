"""SessionArmor exception hierarchy."""


class SessionArmorError(Exception):
    """Base class for SessionArmor failures."""


class SessionConfigurationError(SessionArmorError, ValueError):
    """A security-sensitive setting or middleware option is invalid."""


class AuditEmissionError(SessionArmorError):
    """A required security audit event could not be constructed or emitted."""
