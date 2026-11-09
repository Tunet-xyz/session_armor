"""Real SessionArmor evidence through AccessGate's Django resolver and assurance policy."""

from __future__ import annotations

from unittest.mock import patch

import pytest

pytest.importorskip("access_gate.adapters.django")

from access_gate import AuthorizationRequest, SessionAssurancePolicy, Subject  # noqa: E402
from access_gate.adapters.django import default_context_resolver  # noqa: E402

from session_armor.adapters.django import SessionSecurityMiddleware  # noqa: E402
from tests.test_session import make_request, ok_response  # noqa: E402

CLOCK = "session_armor.adapters.django.session.time.time"


def evaluated(*, now, session=None, user_agent="TestAgent/1.0"):
    request = make_request(session=session)
    request.META["HTTP_USER_AGENT"] = user_agent
    with patch(CLOCK, return_value=now):
        SessionSecurityMiddleware(ok_response)(request)
    return request


def assurance_failure(request, *, now, subject="user-123"):
    decision = SessionAssurancePolicy(actions={"records.read"}, clock=lambda: now).evaluate(
        AuthorizationRequest(
            subject=Subject(subject),
            action="records.read",
            context=default_context_resolver(request),
        )
    )
    return None if decision is None else decision.metadata["assurance_failure"]


def test_fresh_evidence_passes_the_boundary():
    assert assurance_failure(evaluated(now=1_000.0), now=1_000.0) is None


def test_stale_mismatched_unbound_and_terminated_evidence_is_denied(settings):
    request = evaluated(now=1_000.0)
    assert assurance_failure(request, now=1_031.0) == "stale_verification"
    assert assurance_failure(request, now=1_000.0, subject="someone-else") == "subject_mismatch"

    request = evaluated(now=1_001.0, session=request.session, user_agent="OtherAgent/2.0")
    assert assurance_failure(request, now=1_001.0) == "untrusted"

    settings.SESSION_ARMOR_DETECT_CLAIM_DRIFT = False
    assert assurance_failure(evaluated(now=1_000.0), now=1_000.0) == "claim_binding_required"


def test_state_written_by_an_instance_ahead_within_skew_passes_the_boundary():
    session = evaluated(now=1_020.0).session
    assert assurance_failure(evaluated(now=1_000.0, session=session), now=1_000.0) is None
