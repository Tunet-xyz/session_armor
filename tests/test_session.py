"""Adversarial tests for SessionSecurityMiddleware."""

from __future__ import annotations

from unittest.mock import patch

import pytest
from django.http import HttpResponse, HttpResponseForbidden
from django.test import RequestFactory

from session_armor import AssuranceStatus, SessionConfigurationError
from session_armor.session import SessionSecurityMiddleware, _mac


class FakeUser:
    is_authenticated = True

    def __init__(self, sub="user-123", email="test@example.com"):
        self.sub = sub
        self.email = email


class FakeSession(dict):
    def cycle_key(self):
        self["_cycled"] = True

    def flush(self):
        self.clear()
        self["_flushed"] = True


def ok_response(_request):
    return HttpResponse("OK")


def make_request(path="/test/", *, session=None):
    request = RequestFactory().get(path)
    request.user = FakeUser()
    request.session = FakeSession() if session is None else session
    request.META["REMOTE_ADDR"] = "10.0.0.1"
    request.META["HTTP_USER_AGENT"] = "TestAgent/1.0"
    return request


def initialize(middleware, request, *, now=1_000.0):
    with patch("session_armor.session.time.time", return_value=now):
        response = middleware(request)
    assert response.status_code == 200
    return response


class TestSessionSecurityMiddleware:
    def test_unauthenticated_and_exempt_requests_are_explicitly_unverified(self):
        middleware = SessionSecurityMiddleware(ok_response)
        request = make_request()
        request.user.is_authenticated = False
        middleware(request)
        assert request.session_assurance.status is AssuranceStatus.UNVERIFIED
        assert request.session_assurance.reason == "unauthenticated"

        class Exempt(SessionSecurityMiddleware):
            exempt_paths = ("/health",)

        request = make_request("/health/live")
        Exempt(ok_response)(request)
        assert request.session_assurance.reason == "exempt_path"

    def test_initialization_rotates_key_and_publishes_trusted_evidence(self):
        request = make_request()
        response = initialize(SessionSecurityMiddleware(ok_response), request)

        assert request.session["_sa_version"] == 1
        assert request.session["_cycled"] is True
        assert len(request.session["_sa_nonce"]) == 64
        assert request.session_assurance.trusted
        assert request.session_assurance.subject_identifier == "user-123"
        assert request.session_assurance.binding_factors == ("ip", "user_agent")
        assert response.headers["Cache-Control"] == "private, no-store"

    def test_legacy_state_is_replaced_without_becoming_trusted_input(self):
        request = make_request(session=FakeSession({"_ss_auth_time": 1, "_ss_fingerprint": "x"}))
        initialize(SessionSecurityMiddleware(ok_response), request)
        assert not any(key.startswith("_ss_") for key in request.session)
        assert request.session["_sa_version"] == 1

    @pytest.mark.parametrize(
        ("field", "value"),
        [
            ("_sa_started_at", "yesterday"),
            ("_sa_seen_at", float("nan")),
            ("_sa_nonce", "short"),
            ("_sa_binding_mac", None),
        ],
    )
    def test_malformed_state_is_flushed(self, field, value):
        middleware = SessionSecurityMiddleware(ok_response)
        request = make_request()
        initialize(middleware, request)
        request.session[field] = value
        with patch("session_armor.session.time.time", return_value=1_001.0):
            response = middleware(request)
        assert response.status_code == 302
        assert request.session == {"_flushed": True}

    def test_partial_state_is_flushed(self):
        request = make_request(session=FakeSession({"_sa_version": 1}))
        response = SessionSecurityMiddleware(ok_response)(request)
        assert response.status_code == 302
        assert request.session == {"_flushed": True}

    def test_absolute_idle_and_future_timestamps_fail_closed(self, settings):
        middleware = SessionSecurityMiddleware(ok_response)
        request = make_request()
        initialize(middleware, request)

        settings.SESSION_ARMOR_ABSOLUTE_TIMEOUT = 100
        with patch("session_armor.session.time.time", return_value=1_101.0):
            assert middleware(request).status_code == 302

        request = make_request()
        initialize(middleware, request)
        settings.SESSION_ARMOR_IDLE_TIMEOUT = 60
        request.session["_sa_seen_at"] = 900.0
        with patch("session_armor.session.time.time", return_value=1_000.0):
            assert middleware(request).status_code == 302

        request = make_request()
        initialize(middleware, request)
        request.session["_sa_seen_at"] = 2_000.0
        with patch("session_armor.session.time.time", return_value=1_000.0):
            assert middleware(request).status_code == 302

    def test_fingerprint_and_claim_changes_terminate(self):
        middleware = SessionSecurityMiddleware(ok_response)
        request = make_request()
        initialize(middleware, request)
        request.META["HTTP_USER_AGENT"] = "AttackerAgent"
        with patch("session_armor.session.time.time", return_value=1_001.0):
            assert middleware(request).status_code == 302

        request = make_request()
        initialize(middleware, request)
        request.user.email = "changed@example.com"
        with patch("session_armor.session.time.time", return_value=1_001.0):
            assert middleware(request).status_code == 302

    def test_public_rebaseline_api_accepts_reviewed_claim_change(self):
        middleware = SessionSecurityMiddleware(ok_response)
        request = make_request()
        initialize(middleware, request)
        request.user.email = "reviewed@example.com"
        middleware.rebaseline_claims(request)
        with patch("session_armor.session.time.time", return_value=1_001.0):
            assert middleware(request).status_code == 200

    def test_custom_violation_response_never_prevents_flush(self):
        class Custom(SessionSecurityMiddleware):
            def on_violation(self, request, reason):
                return HttpResponseForbidden(reason)

        middleware = Custom(ok_response)
        request = make_request()
        initialize(middleware, request)
        request.session["_sa_binding_mac"] = "0" * 64
        response = middleware(request)
        assert response.status_code == 403
        assert request.session == {"_flushed": True}

    def test_invalid_security_configuration_raises_at_boundary(self, settings):
        settings.SESSION_ARMOR_IDLE_TIMEOUT = 0
        with pytest.raises(SessionConfigurationError):
            SessionSecurityMiddleware(ok_response)(make_request())

    def test_length_framing_prevents_delimiter_ambiguity(self):
        assert _mac("test", ("a|b", "c")) != _mac("test", ("a", "b|c"))

