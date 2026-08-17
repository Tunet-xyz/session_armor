"""Tests for typed, identity-bound gates."""

from __future__ import annotations

import time

import pytest
from django.http import HttpResponse
from django.test import RequestFactory

from session_armor import GateDecision
from session_armor.adapters.django import GateMiddleware


class FakeUser:
    is_authenticated = True

    def __init__(self, sub="user-1"):
        self.sub = sub


class Assurance:
    trusted = True
    session_identifier = "session-1"


def ok_response(_request):
    return HttpResponse("OK")


def make_request(path="/test/"):
    request = RequestFactory().get(path)
    request.user = FakeUser()
    request.session = {}
    request.session_assurance = Assurance()
    return request


class PassGate(GateMiddleware):
    gate_id = "test_pass"

    def check(self, request):
        return GateDecision.allow("test_passed")


class FailGate(GateMiddleware):
    gate_id = "test_fail"

    def check(self, request):
        return GateDecision.reject("test_failed", context={"step": 3})


class TestGateMiddleware:
    def test_explicit_pass_and_reject(self):
        assert PassGate(ok_response)(make_request()).status_code == 200
        request = make_request()
        assert FailGate(ok_response)(request).status_code == 403
        assert FailGate.get_context(request) == {"step": 3}

    def test_arbitrary_truthy_check_result_fails_closed(self):
        class Unsafe(GateMiddleware):
            def check(self, request):
                return "yes"

        assert Unsafe(ok_response)(make_request()).status_code == 403

    def test_error_fails_closed_and_records_reason(self):
        class Error(GateMiddleware):
            def check(self, request):
                raise RuntimeError("database unavailable")

        request = make_request()
        assert Error(ok_response)(request).status_code == 403
        prefix = "_gate_error"
        assert request.session[f"{prefix}_reason"] == "gate_check_error"
        assert request.session[f"{prefix}_context"] == {"error_type": "RuntimeError"}

    def test_before_check_requires_an_explicit_skip(self):
        class Skipped(FailGate):
            def before_check(self, request):
                return GateDecision.skip("not_applicable")

        assert Skipped(ok_response)(make_request()).status_code == 200

        class BooleanSkip(FailGate):
            def before_check(self, request):
                return False

        assert BooleanSkip(ok_response)(make_request()).status_code == 403

    def test_cache_is_scoped_to_session_identity(self):
        calls = []

        class Counting(GateMiddleware):
            gate_id = "counting"

            def check(self, request):
                calls.append(1)
                return GateDecision.allow()

        request = make_request()
        gate = Counting(ok_response)
        gate(request)
        gate(request)
        assert calls == [1]

        request.session_assurance.session_identifier = "session-2"
        gate(request)
        assert calls == [1, 1]

    def test_malformed_cache_is_ignored(self):
        request = make_request()
        request.session.update(
            {
                "_gate_test_pass_at": time.time(),
                "_gate_test_pass_outcome": True,
                "_gate_test_pass_scope": "session-1",
            }
        )
        assert PassGate(ok_response)(request).status_code == 200
        assert request.session["_gate_test_pass_outcome"] == "pass"

    def test_unbounded_sticky_pass_is_not_reused(self):
        calls = []

        class Sticky(GateMiddleware):
            gate_id = "sticky"
            recheck_after_pass = False

            def check(self, request):
                calls.append(1)
                return GateDecision.allow()

        request = make_request()
        gate = Sticky(ok_response)
        gate(request)
        gate(request)
        assert calls == [1, 1]

    def test_bounded_sticky_pass_and_version_invalidation(self):
        calls = []

        class Sticky(GateMiddleware):
            gate_id = "sticky_versioned"
            recheck_after_pass = False
            sticky_pass_max_age = 3600
            version = "v1"

            def get_state_version(self, request):
                return self.version

            def check(self, request):
                calls.append(1)
                return GateDecision.allow()

        request = make_request()
        gate = Sticky(ok_response)
        gate(request)
        gate(request)
        assert calls == [1]
        gate.version = "v2"
        gate(request)
        assert calls == [1, 1]

        gate.version = None
        gate(request)
        assert calls == [1, 1, 1]

    def test_trusted_session_requirement_is_fail_closed(self):
        class Sensitive(PassGate):
            requires_trusted_session = True

        request = make_request()
        request.session_assurance.trusted = False
        assert Sensitive(ok_response)(request).status_code == 403

    def test_invalidate_clears_new_and_legacy_cache_keys(self):
        request = make_request()
        for suffix in ("at", "outcome", "reason", "context", "version", "scope", "result"):
            request.session[f"_gate_test_pass_{suffix}"] = "value"
        PassGate.invalidate(request)
        assert not request.session

    @pytest.mark.parametrize("value", [0, -1, True, 86_401, "300"])
    def test_invalid_ttl_is_rejected(self, value):
        class Invalid(PassGate):
            default_cache_ttl = value

        with pytest.raises(ValueError, match="cache TTL"):
            Invalid(ok_response)(make_request())
