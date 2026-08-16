from __future__ import annotations

import pytest

from session_armor import AssuranceStatus, SessionAssurance


def trusted_assurance() -> SessionAssurance:
    return SessionAssurance(
        status=AssuranceStatus.TRUSTED,
        reason="validated",
        subject_identifier="user-1",
        session_identifier="session-1",
        established_at=1.0,
        verified_at=2.0,
        last_activity_at=2.0,
        binding_factors=("ip",),
        claims_bound=True,
    )


def test_authorization_context_is_versioned_and_immutable() -> None:
    context = trusted_assurance().to_authorization_context()
    assert context["schema"] == "session-armor.assurance/v1"
    with pytest.raises(TypeError):
        context["status"] = "untrusted"


@pytest.mark.parametrize(
    "kwargs",
    [
        {"reason": ""},
        {"subject_identifier": ""},
        {"verified_at": float("inf")},
        {"binding_factors": ("ip", "ip")},
        {"claims_bound": "yes"},
    ],
)
def test_invalid_assurance_evidence_is_rejected(kwargs) -> None:
    values = {
        "status": AssuranceStatus.UNVERIFIED,
        "reason": "unverified",
        **kwargs,
    }
    with pytest.raises((TypeError, ValueError)):
        SessionAssurance(**values)


def test_trusted_evidence_requires_all_security_fields() -> None:
    with pytest.raises(ValueError, match="complete"):
        SessionAssurance(status=AssuranceStatus.TRUSTED, reason="validated")
