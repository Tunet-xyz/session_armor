"""Tests for typed, identity-bound gates."""

from __future__ import annotations

import time
from pathlib import Path

import pytest
from django.contrib.auth.models import AnonymousUser
from django.contrib.sessions.backends.signed_cookies import SessionStore
from django.core.cache import cache
from django.http import HttpResponse
from django.test import RequestFactory

from session_armor import GateDecision, SessionAssurance, SessionConfigurationError
from session_armor.adapters.django import GateMiddleware, SessionSecurityMiddleware


class FakeUser:
    is_authenticated = True

    def __init__(self, sub="user-1"):
        self.sub = sub


class Assurance:
    trusted = True
    session_identifier = "session-1"


def ok_response(_request):
    return HttpResponse("OK")


def make_request(path="/test/", **extra):
    request = RequestFactory().get(path, **extra)
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

    def test_application_exceptions_are_not_turned_into_rejections(self):
        def broken_view(_request):
            raise ZeroDivisionError("view bug")

        class Skipped(PassGate):
            def before_check(self, request):
                return GateDecision.skip()

        for gate in (PassGate(broken_view), Skipped(broken_view)):
            request = make_request()
            for _attempt in ("fresh", "cached"):
                with pytest.raises(ZeroDivisionError):
                    gate(request)

    def test_error_rejection_lifetime_is_capped_by_error_cache_ttl(self):
        calls = []

        class Flaky(GateMiddleware):
            gate_id = "flaky"
            default_cache_ttl = 3600
            error_cache_ttl = 30
            down = True

            def check(self, request):
                calls.append(1)
                if self.down:
                    raise ConnectionError("backend unavailable")
                return GateDecision.allow()

        request = make_request()
        gate = Flaky(ok_response)
        assert gate(request).status_code == 403
        gate.down = False
        request.session["_gate_flaky_at"] -= 29
        assert gate(request).status_code == 403
        assert calls == [1]
        request.session["_gate_flaky_at"] -= 2
        assert gate(request).status_code == 200
        assert calls == [1, 1]
        assert "_gate_flaky_error" not in request.session

    def test_error_cache_ttl_does_not_shorten_check_rejections(self):
        class Blocked(FailGate):
            default_cache_ttl = 3600
            error_cache_ttl = 30

        request = make_request()
        gate = Blocked(ok_response)
        gate(request)
        request.session["_gate_test_fail_at"] -= 600
        request.session["_gate_test_fail_reason"] = "cached_rejection"
        gate(request)
        assert request.session["_gate_test_fail_reason"] == "cached_rejection"

    @pytest.mark.parametrize("value", [0, True, 86_401, "30"])
    def test_invalid_error_cache_ttl_is_rejected(self, value):
        class Invalid(PassGate):
            error_cache_ttl = value

        with pytest.raises(ValueError, match="error_cache_ttl"):
            Invalid(ok_response)

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

    def test_anonymous_requests_are_checked_without_caching(self):
        calls = []

        class Maintenance(GateMiddleware):
            gate_id = "maintenance"
            requires_auth = False

            def check(self, request):
                calls.append(1)
                return GateDecision.allow("not_in_maintenance")

        request = make_request()
        request.user = AnonymousUser()
        request.session_assurance = SessionAssurance.unverified("unauthenticated")
        gate = Maintenance(ok_response)
        assert gate(request).status_code == 200
        assert gate(request).status_code == 200
        assert calls == [1, 1]
        assert request.session == {}

    def test_gates_sharing_a_gate_id_do_not_reuse_each_others_results(self):
        class Terms(PassGate):
            gate_id = "shared"

        class Suspended(FailGate):
            gate_id = "shared"

        request = make_request()
        chain = Terms(Suspended(ok_response))
        assert chain(request).status_code == 403
        assert chain(request).status_code == 403

    def test_subclass_variant_does_not_reuse_its_parents_result(self):
        class Role(GateMiddleware):
            gate_id = "role"
            required = "staff"

            def check(self, request):
                if self.required == "staff":
                    return GateDecision.allow()
                return GateDecision.reject("role_required")

        class Admin(Role):
            required = "admin"

        request = make_request()
        assert Role(Admin(ok_response))(request).status_code == 403

    def test_entries_without_an_owner_are_still_reused(self):
        request = make_request()
        request.session.update(
            {
                "_gate_test_fail_at": time.time(),
                "_gate_test_fail_outcome": "pass",
                "_gate_test_fail_reason": "seeded",
                "_gate_test_fail_context": {},
                "_gate_test_fail_scope": "session-1",
            }
        )
        assert FailGate(ok_response)(request).status_code == 200

    def test_cached_decision_is_readable_without_private_keys(self):
        request = make_request()
        assert FailGate.get_cached_decision(request) is None
        FailGate(ok_response)(request)
        decision = FailGate.get_cached_decision(request)
        assert decision == GateDecision.reject("test_failed", context={"step": 3})
        request.session["_gate_test_fail_reason"] = "not a reason!"
        assert FailGate.get_cached_decision(request) is None

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

    def test_exempt_paths_match_the_routed_path_not_the_script_prefix(self):
        class Guarded(FailGate):
            exempt_paths = ("/static/", "/compliance/")

        # A client-chosen SCRIPT_NAME must not exempt the view Django routes to.
        spoofed = make_request("/account/export/", SCRIPT_NAME="/static")
        assert spoofed.path == "/static/account/export/"
        assert Guarded(ok_response)(spoofed).status_code == 403
        # Mounted under a prefix, the gate's own landing page stays exempt.
        mounted = make_request("/compliance/", SCRIPT_NAME="/app")
        assert Guarded(ok_response)(mounted).status_code == 200

    def test_gate_can_follow_session_exemptions(self):
        class SessionExempt(SessionSecurityMiddleware):
            exempt_paths = ("/.well-known/",)

        class Sensitive(FailGate):
            requires_trusted_session = True

        class Following(Sensitive):
            follow_session_exemptions = True

        def stack(gate, path):
            request = make_request(path)
            request.session = SessionStore()
            request.META.update(REMOTE_ADDR="10.0.0.1", HTTP_USER_AGENT="Test/1.0")
            return SessionExempt(gate(ok_response))(request), request

        # By default a gate repeats SessionArmor's exemptions by hand or rejects them.
        assert stack(Sensitive, "/.well-known/change-password")[0].status_code == 403
        response, request = stack(Following, "/.well-known/change-password")
        assert response.status_code == 200
        assert not request.session.keys()
        # Only SessionArmor's own exempt-path evidence is followed.
        assert stack(Following, "/account/")[0].status_code == 403
        request = make_request()
        request.session_assurance = SessionAssurance.unverified("unauthenticated")
        assert Following(ok_response)(request).status_code == 403

    def test_follow_session_exemptions_must_be_boolean(self):
        class Invalid(PassGate):
            follow_session_exemptions = "yes"

        with pytest.raises(SessionConfigurationError, match="follow_session_exemptions"):
            Invalid(ok_response)

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


@pytest.mark.parametrize(
    "context",
    [
        {"documents": ["terms", "x" * 2_049]},
        {"scores": (float("nan"),)},
        {"scores": [float("inf")]},
    ],
)
def test_context_list_items_have_the_same_bounds_as_fields(context):
    with pytest.raises(ValueError):
        GateDecision.reject("blocked", context=context)


def test_context_lists_are_frozen_to_tuples():
    decision = GateDecision.reject("blocked", context={"documents": ["terms", None, 1]})
    assert decision.context["documents"] == ("terms", None, 1)


def test_readme_check_once_gate_example_passes_once_with_no_version_key():
    readme = (Path(__file__).resolve().parents[1] / "README.md").read_text()
    section = readme.split('### "Check once" gates', 1)[1]
    source = section.split("```python\n", 1)[1].split("```", 1)[0]
    calls = []
    namespace = {
        "GateMiddleware": GateMiddleware,
        "GateDecision": GateDecision,
        "user_accepted_current_terms": lambda request: calls.append(1) or True,
    }
    exec(source, namespace)
    gate = namespace["ComplianceGate"](ok_response)
    request = make_request()
    request.user.platform = "web"
    cache.delete("compliance_version:web")
    assert gate(request).status_code == 200
    assert gate(request).status_code == 200
    assert calls == [1]
