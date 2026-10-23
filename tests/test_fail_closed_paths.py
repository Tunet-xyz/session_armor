"""Regression tests for fail-closed branches that no other test reaches."""

from __future__ import annotations

import json
import logging
from unittest.mock import patch

import pytest
from django.http import HttpResponse
from django.test import RequestFactory, override_settings

from session_armor import (
    AssuranceStatus,
    GateDecision,
    SessionConfigurationError,
)
from session_armor.adapters.django import AuditMiddleware, GateMiddleware, SessionSecurityMiddleware
from session_armor.adapters.django.utils import get_client_ip, hash_ip

SESSION_CLOCK = "session_armor.adapters.django.session.time.time"
GATE_CLOCK = "session_armor.adapters.django.gate.time.time"


class FakeUser:
    is_authenticated = True

    def __init__(self, sub="user-1", email="user@example.com"):
        self.sub = sub
        self.email = email


class FakeSession(dict):
    flushed = False

    def cycle_key(self):
        pass

    def flush(self):
        self.clear()
        self.flushed = True


def ok_response(_request):
    return HttpResponse("OK")


def make_request(path="/test/", *, session=None, remote="10.0.0.1", forwarded=None):
    extra = {"REMOTE_ADDR": remote, "HTTP_USER_AGENT": "TestAgent/1.0"}
    if forwarded is not None:
        extra["HTTP_X_FORWARDED_FOR"] = forwarded
    request = RequestFactory().get(path, **extra)
    request.user = FakeUser()
    request.session = FakeSession() if session is None else session
    return request


def established_session(now=1_000.0):
    request = make_request()
    with patch(SESSION_CLOCK, return_value=now):
        assert SessionSecurityMiddleware(ok_response)(request).status_code == 200
    return request.session


class TestSessionFailClosed:
    def test_idle_timeout_terminates(self):
        session = established_session()
        request = make_request(session=session)
        with patch(SESSION_CLOCK, return_value=1_000.0 + 1_801):
            response = SessionSecurityMiddleware(ok_response)(request)
        assert response.status_code == 302
        assert session.flushed
        assert request.session_assurance.reason == "idle_timeout"

    def test_evaluation_error_terminates_instead_of_passing_through(self):
        class Broken(SessionSecurityMiddleware):
            def get_fingerprint_factors(self, request):
                raise RuntimeError("hook failure")

        calls = []
        request = make_request()
        response = Broken(lambda r: calls.append(r) or ok_response(r))(request)
        assert calls == []
        assert response.status_code == 302
        assert request.session_assurance.reason == "session_evaluation_error"

    def test_orphaned_private_state_is_terminated_not_reinitialized(self):
        request = make_request(session=FakeSession({"_sa_nonce": "x" * 64}))
        response = SessionSecurityMiddleware(ok_response)(request)
        assert response.status_code == 302
        assert request.session_assurance.reason == "partial_security_state"

    def test_unsupported_state_version_terminates(self):
        session = established_session()
        session["_sa_version"] = 2
        request = make_request(session=session)
        with patch(SESSION_CLOCK, return_value=1_001.0):
            assert SessionSecurityMiddleware(ok_response)(request).status_code == 302
        assert request.session_assurance.reason == "unsupported_security_state"

    @override_settings(SESSION_ARMOR_STATE_KEY="short")
    def test_short_state_key_is_rejected(self):
        with pytest.raises(SessionConfigurationError, match="16 bytes"):
            SessionSecurityMiddleware(ok_response)(make_request())

    def test_flush_failure_is_not_swallowed(self):
        class Unflushable(FakeSession):
            def flush(self):
                raise OSError("backend down")

        request = make_request(session=Unflushable({"_sa_nonce": "x" * 64}))
        with pytest.raises(RuntimeError, match="could not invalidate"):
            SessionSecurityMiddleware(ok_response)(request)

    def test_empty_subject_is_never_trusted(self):
        request = make_request()
        request.user.sub = ""
        SessionSecurityMiddleware(ok_response)(request)
        assert request.session_assurance.status is AssuranceStatus.UNVERIFIED
        assert request.session_assurance.reason == "session_evaluation_error"

    @override_settings(SESSION_ARMOR_BIND_IP=False, SESSION_ARMOR_BIND_USER_AGENT=False)
    def test_require_binding_rejects_an_empty_factor_set(self):
        with pytest.raises(SessionConfigurationError, match="REQUIRE_BINDING"):
            SessionSecurityMiddleware(ok_response)(make_request())


class TestProxyAndPepperConfiguration:
    @override_settings(
        SESSION_ARMOR_TRUSTED_PROXY_DEPTH=1, SESSION_ARMOR_TRUSTED_PROXY_CIDRS=("10.0.0.0/8",)
    )
    def test_untrusted_socket_peer_cannot_supply_a_forwarded_ip(self):
        request = make_request(remote="203.0.113.5", forwarded="198.51.100.1")
        assert get_client_ip(request) == ""

    @override_settings(
        SESSION_ARMOR_TRUSTED_PROXY_DEPTH=1, SESSION_ARMOR_TRUSTED_PROXY_CIDRS=("0.0.0.0/0",)
    )
    def test_catch_all_proxy_cidr_is_rejected(self):
        with pytest.raises(SessionConfigurationError, match="catch-all"):
            get_client_ip(make_request(forwarded="198.51.100.1"))

    @override_settings(SESSION_ARMOR_AUDIT_PEPPER="short")
    def test_short_audit_pepper_is_rejected(self):
        with pytest.raises(SessionConfigurationError, match="16 bytes"):
            hash_ip("10.0.0.1")


class CountingGate(GateMiddleware):
    gate_id = "counting"
    default_cache_ttl = 60
    calls = 0

    def check(self, request):
        type(self).calls += 1
        return GateDecision.allow("ok")


class Assurance:
    trusted = True
    session_identifier = "session-1"


def gate_request(session):
    request = RequestFactory().get("/gated/")
    request.user = FakeUser()
    request.session = session
    request.session_assurance = Assurance()
    return request


class TestGateCacheFailClosed:
    def setup_method(self):
        CountingGate.calls = 0

    def test_expired_cache_is_rechecked(self):
        session = {}
        gate = CountingGate(ok_response)
        with patch(GATE_CLOCK, return_value=1_000.0):
            gate(gate_request(session))
        with patch(GATE_CLOCK, return_value=1_061.0):
            gate(gate_request(session))
        assert CountingGate.calls == 2

    def test_future_dated_cache_is_discarded(self):
        session = {}
        gate = CountingGate(ok_response)
        with patch(GATE_CLOCK, return_value=1_000.0):
            gate(gate_request(session))
        session["_gate_counting_at"] = 10_000.0
        with patch(GATE_CLOCK, return_value=1_001.0):
            gate(gate_request(session))
        assert CountingGate.calls == 2

    def test_non_numeric_cache_timestamp_is_discarded(self):
        session = {}
        gate = CountingGate(ok_response)
        gate(gate_request(session))
        session["_gate_counting_at"] = "forever"
        assert gate(gate_request(session)).status_code == 200
        assert CountingGate.calls == 2

    def test_gate_without_any_cache_scope_fails_closed(self):
        request = gate_request({})
        request.session_assurance = None
        request.user.sub = None
        assert CountingGate(ok_response)(request).status_code == 403
        assert CountingGate.calls == 0

    def test_non_finite_gate_context_is_rejected(self):
        with pytest.raises(ValueError):
            GateDecision.reject("blocked", context={"score": float("nan")})


def test_audit_records_an_unvalidated_client_ip_as_null(caplog):
    with caplog.at_level(logging.DEBUG, logger="security.audit"):
        assert AuditMiddleware(ok_response)(make_request(remote="not-an-ip")).status_code == 200
    entry = json.loads(caplog.records[-1].message.split(" ", 1)[1])
    assert entry["ip_hash"] is None
