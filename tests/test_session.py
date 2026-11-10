"""Adversarial tests for SessionSecurityMiddleware."""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
from unittest.mock import patch

import pytest
from django.contrib.sessions.backends.signed_cookies import SessionStore
from django.http import HttpResponse, HttpResponseForbidden
from django.test import RequestFactory
from django.utils.functional import lazystr

from session_armor import AssuranceStatus, SessionConfigurationError
from session_armor.adapters.django import AuditMiddleware, SessionSecurityMiddleware
from session_armor.adapters.django.session import _mac
from session_armor.adapters.django.utils import hash_ip


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


def make_request(path="/test/", *, session=None, **extra):
    request = RequestFactory().get(path, **extra)
    request.user = FakeUser()
    request.session = FakeSession() if session is None else session
    request.META["REMOTE_ADDR"] = "10.0.0.1"
    request.META["HTTP_USER_AGENT"] = "TestAgent/1.0"
    return request


def initialize(middleware, request, *, now=1_000.0):
    with patch("session_armor.adapters.django.session.time.time", return_value=now):
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

    def test_exempt_paths_match_the_routed_path_not_the_script_prefix(self):
        class Exempt(SessionSecurityMiddleware):
            exempt_paths = ("/static/",)

        # A client-chosen SCRIPT_NAME must not exempt the view Django routes to.
        request = make_request("/account/", SCRIPT_NAME="/static")
        assert request.path == "/static/account/"
        initialize(Exempt(ok_response), request)
        assert request.session_assurance.trusted

        request = make_request("/static/app.css", SCRIPT_NAME="/app")
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

    def test_initialization_supports_a_real_django_session_store(self):
        request = make_request(session=SessionStore())

        response = initialize(SessionSecurityMiddleware(ok_response), request)

        assert response.status_code == 200
        assert request.session["_sa_version"] == 1
        assert request.session_assurance.trusted

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
        with patch("session_armor.adapters.django.session.time.time", return_value=1_001.0):
            response = middleware(request)
        assert response.status_code == 302
        assert request.session == {"_flushed": True}

    def test_valid_looking_timestamp_tampering_breaks_state_integrity(self):
        middleware = SessionSecurityMiddleware(ok_response)
        request = make_request()
        initialize(middleware, request)
        request.session["_sa_started_at"] = 999.0
        with patch("session_armor.adapters.django.session.time.time", return_value=1_001.0):
            assert middleware(request).status_code == 302
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
        with patch("session_armor.adapters.django.session.time.time", return_value=1_101.0):
            assert middleware(request).status_code == 302

        request = make_request()
        initialize(middleware, request)
        settings.SESSION_ARMOR_IDLE_TIMEOUT = 60
        request.session["_sa_seen_at"] = 900.0
        with patch("session_armor.adapters.django.session.time.time", return_value=1_000.0):
            assert middleware(request).status_code == 302

        request = make_request()
        initialize(middleware, request)
        request.session["_sa_seen_at"] = 2_000.0
        with patch("session_armor.adapters.django.session.time.time", return_value=1_000.0):
            assert middleware(request).status_code == 302

    def test_fingerprint_and_claim_changes_terminate(self):
        middleware = SessionSecurityMiddleware(ok_response)
        request = make_request()
        initialize(middleware, request)
        request.META["HTTP_USER_AGENT"] = "AttackerAgent"
        with patch("session_armor.adapters.django.session.time.time", return_value=1_001.0):
            assert middleware(request).status_code == 302

        request = make_request()
        initialize(middleware, request)
        request.user.email = "changed@example.com"
        with patch("session_armor.adapters.django.session.time.time", return_value=1_001.0):
            assert middleware(request).status_code == 302

    def test_public_rebaseline_api_accepts_reviewed_claim_change(self):
        middleware = SessionSecurityMiddleware(ok_response)
        request = make_request()
        initialize(middleware, request)
        request.user.email = "reviewed@example.com"
        middleware.rebaseline_claims(request)
        with patch("session_armor.adapters.django.session.time.time", return_value=1_001.0):
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

    def test_broken_violation_hook_still_flushes_and_redirects(self):
        class Broken(SessionSecurityMiddleware):
            def on_violation(self, request, reason):
                raise RuntimeError("broken observer")

        middleware = Broken(ok_response)
        request = make_request()
        initialize(middleware, request)
        request.session["_sa_binding_mac"] = "0" * 64
        assert middleware(request).status_code == 302
        assert request.session == {"_flushed": True}

    def test_application_exception_is_not_misclassified_as_session_violation(self):
        def application_error(_request):
            raise RuntimeError("view failed")

        middleware = SessionSecurityMiddleware(application_error)
        request = make_request()
        with patch("session_armor.adapters.django.session.time.time", return_value=1_000.0):
            with pytest.raises(RuntimeError, match="view failed"):
                middleware(request)
        assert request.session_assurance.trusted
        assert "_flushed" not in request.session

    def test_invalid_security_configuration_raises_at_boundary(self, settings):
        settings.SESSION_ARMOR_IDLE_TIMEOUT = 0
        with pytest.raises(SessionConfigurationError):
            SessionSecurityMiddleware(ok_response)(make_request())

    def test_length_framing_prevents_delimiter_ambiguity(self):
        assert _mac("test", ("a|b", "c")) != _mac("test", ("a", "b|c"))


def call_at(middleware, request, now):
    with patch("session_armor.adapters.django.session.time.time", return_value=now):
        return middleware(request)


class TestStateKeyRotation:
    OLD = "retired-state-key-0123456789"
    NEW = "current-state-key-0123456789"

    def rotated_session(self, settings, **rotation):
        settings.SESSION_ARMOR_STATE_KEY = self.OLD
        middleware = SessionSecurityMiddleware(ok_response)
        request = make_request()
        initialize(middleware, request)
        settings.SESSION_ARMOR_STATE_KEY = self.NEW
        for name, value in rotation.items():
            setattr(settings, name, value)
        return middleware, request

    def test_rotation_without_fallbacks_still_fails_closed(self, settings):
        middleware, request = self.rotated_session(settings)
        assert call_at(middleware, request, 1_001.0).status_code == 302
        assert request.session_assurance.reason == "state_integrity_failure"

    def test_fallback_key_verifies_and_state_is_resigned_with_the_current_key(self, settings):
        middleware, request = self.rotated_session(
            settings, SESSION_ARMOR_STATE_KEY_FALLBACKS=[self.OLD]
        )
        assert call_at(middleware, request, 1_001.0).status_code == 200
        assert request.session_assurance.trusted

        # The retired key is no longer needed, and no longer verifies anything.
        settings.SESSION_ARMOR_STATE_KEY_FALLBACKS = []
        assert call_at(middleware, request, 1_002.0).status_code == 200
        settings.SESSION_ARMOR_STATE_KEY = self.OLD
        assert call_at(middleware, request, 1_003.0).status_code == 302

    def test_fallback_key_does_not_excuse_a_changed_fingerprint_or_tampering(self, settings):
        middleware, request = self.rotated_session(
            settings, SESSION_ARMOR_STATE_KEY_FALLBACKS=[self.OLD]
        )
        request.META["HTTP_USER_AGENT"] = "AttackerAgent"
        assert call_at(middleware, request, 1_001.0).status_code == 302
        assert request.session_assurance.reason == "fingerprint_mismatch"

        middleware, request = self.rotated_session(
            settings, SESSION_ARMOR_STATE_KEY_FALLBACKS=[self.OLD]
        )
        request.session["_sa_started_at"] = 999.0
        assert call_at(middleware, request, 1_001.0).status_code == 302
        assert request.session_assurance.reason == "state_integrity_failure"

    def test_state_key_that_follows_secret_key_follows_secret_key_fallbacks(self, settings):
        for state_key in ("", self.NEW):
            settings.SECRET_KEY = self.OLD
            settings.SESSION_ARMOR_STATE_KEY = state_key and self.OLD
            middleware = SessionSecurityMiddleware(ok_response)
            request = make_request()
            initialize(middleware, request)
            settings.SECRET_KEY = self.NEW
            settings.SESSION_ARMOR_STATE_KEY = state_key
            settings.SECRET_KEY_FALLBACKS = [self.OLD]
            assert call_at(middleware, request, 1_001.0).status_code == 200

    def test_dedicated_state_key_ignores_secret_key_fallbacks(self, settings):
        middleware, request = self.rotated_session(settings, SECRET_KEY_FALLBACKS=[self.OLD])
        assert call_at(middleware, request, 1_001.0).status_code == 302

    @pytest.mark.parametrize("fallbacks", ["retired-state-key-0123456789", [64], ["short"]])
    def test_invalid_explicit_fallbacks_are_a_configuration_error(self, settings, fallbacks):
        middleware, request = self.rotated_session(
            settings, SESSION_ARMOR_STATE_KEY_FALLBACKS=fallbacks
        )
        with pytest.raises(SessionConfigurationError):
            call_at(middleware, request, 1_001.0)

    @pytest.mark.parametrize("fallbacks", ["retired-state-key-0123456789", [64], ["short"]])
    def test_invalid_explicit_fallbacks_fail_before_a_violation_can_be_retried(
        self, settings, fallbacks
    ):
        settings.SESSION_ARMOR_STATE_KEY_FALLBACKS = fallbacks
        with pytest.raises(SessionConfigurationError):
            call_at(SessionSecurityMiddleware(ok_response), make_request(), 1_000.0)


class TestStateKeyEncoding:
    @pytest.mark.parametrize("value", [64, [65] * 20, 2**70])
    def test_non_text_state_key_is_a_configuration_error(self, settings, value):
        settings.SESSION_ARMOR_STATE_KEY = value
        with pytest.raises(SessionConfigurationError):
            call_at(SessionSecurityMiddleware(ok_response), make_request(), 1_000.0)


def test_mac_matches_the_reference_construction_for_each_key(settings):
    for key in ("first-state-key-0123456789", "second-state-key-0123456789"):
        settings.SESSION_ARMOR_STATE_KEY = key
        derived = hmac.new(key.encode(), b"test", hashlib.sha256).digest()
        framed = b"\x00\x00\x00\x01\x00\x00\x00\x01a"
        expected = hmac.new(derived, framed, hashlib.sha256).hexdigest()
        assert _mac("test", ("a",)) == expected


class TestEvaluationDiagnostics:
    def test_contained_evaluation_error_is_logged_and_still_fails_closed(self, caplog):
        reasons = []

        class Broken(SessionSecurityMiddleware):
            def get_critical_claims(self, user):
                raise TypeError("unexpected claim shape")

            def on_violation(self, request, reason):
                reasons.append(reason)

        request = make_request("/private/area/")
        with caplog.at_level(logging.DEBUG, logger="session_armor.session"):
            response = call_at(Broken(ok_response), request, 1_000.0)
        assert response.status_code == 302
        assert reasons == ["session_evaluation_error"]
        records = [record for record in caplog.records if record.name == "session_armor.session"]
        assert [(record.levelno, record.getMessage()) for record in records] == [
            (logging.WARNING, "SessionArmor session evaluation failed")
        ]
        assert records[0].exc_info[0] is TypeError
        assert "/private/area/" not in caplog.text

    def test_failing_timeout_hook_keeps_the_timeout_reason(self):
        reasons = []

        class Observed(SessionSecurityMiddleware):
            def on_timeout(self, request, kind):
                raise RuntimeError("observer unavailable")

            def on_violation(self, request, reason):
                reasons.append(reason)

        middleware = Observed(ok_response)
        request = make_request()
        initialize(middleware, request)
        assert call_at(middleware, request, 2_801.0).status_code == 302
        assert reasons == ["idle_timeout"]
        assert request.session_assurance.reason == "idle_timeout"


class TestSingleTermination:
    def test_failed_termination_reports_the_violation_once(self, caplog):
        reasons = []

        class Observed(SessionSecurityMiddleware):
            def on_violation(self, request, reason):
                reasons.append(reason)

        class UnflushableSession(FakeSession):
            def flush(self):
                raise ConnectionError("session store unavailable")

        middleware = Observed(ok_response)
        request = make_request(session=UnflushableSession())
        initialize(middleware, request)
        request.META["HTTP_USER_AGENT"] = "AttackerAgent"
        with caplog.at_level(logging.DEBUG, logger="security.audit"):
            with pytest.raises(RuntimeError, match="could not invalidate"):
                call_at(middleware, request, 1_001.0)
        assert reasons == ["fingerprint_mismatch"]
        assert request.session_assurance.reason == "fingerprint_mismatch"
        # The session is still valid, so no termination is recorded.
        assert audit_events(caplog) == []


def audit_events(caplog, logger="security.audit"):
    """(level, prefix, entry) for each event line recorded on ``logger``."""

    events = []
    for record in caplog.records:
        if record.name == logger:
            prefix, _, entry = record.getMessage().partition(" ")
            events.append((record.levelno, prefix, json.loads(entry)))
    return events


def terminated(reason, **fields):
    return {
        "event": "session.terminated",
        "reason": reason,
        "uid": "user-123",
        "ip_hash": hash_ip("10.0.0.1", length=32),
        **fields,
    }


def change_user_agent(request):
    request.META["HTTP_USER_AGENT"] = "AttackerAgent/9.9"


def change_email(request):
    request.user.email = "changed@example.com"


def move_started_at(request):
    request.session["_sa_started_at"] = 999.0


def drop_state_mac(request):
    del request.session["_sa_state_mac"]


class TestTerminationAudit:
    @pytest.mark.parametrize(
        ("tamper", "reason"),
        [
            (change_user_agent, "fingerprint_mismatch"),
            (change_email, "claim_drift"),
            (move_started_at, "state_integrity_failure"),
            (drop_state_mac, "partial_security_state"),
        ],
    )
    def test_each_termination_is_recorded_once_without_path_or_client_details(
        self, caplog, tamper, reason
    ):
        middleware = SessionSecurityMiddleware(ok_response)
        request = make_request("/private/area/")
        initialize(middleware, request)
        tamper(request)
        with caplog.at_level(logging.DEBUG, logger="security.audit"):
            assert call_at(middleware, request, 1_001.0).status_code == 302
        assert request.session == {"_flushed": True}
        assert audit_events(caplog) == [(logging.WARNING, "AUDIT_DENIED", terminated(reason))]
        for detail in ("/private/area/", "10.0.0.1", "Agent"):
            assert detail not in caplog.text

    @pytest.mark.parametrize(
        ("now", "reason"), [(2_801.0, "idle_timeout"), (29_801.0, "absolute_timeout")]
    )
    def test_a_timeout_is_recorded_as_routine(self, caplog, now, reason):
        middleware = SessionSecurityMiddleware(ok_response)
        request = make_request()
        initialize(middleware, request)
        with caplog.at_level(logging.DEBUG, logger="security.audit"):
            assert call_at(middleware, request, now).status_code == 302
        assert audit_events(caplog) == [(logging.INFO, "AUDIT", terminated(reason))]

    def test_the_documented_middleware_order_records_the_termination(self, caplog):
        # SessionSecurityMiddleware runs first, so AuditMiddleware never sees
        # the terminated request.
        middleware = SessionSecurityMiddleware(AuditMiddleware(ok_response))
        request = make_request()
        initialize(middleware, request)
        change_user_agent(request)
        caplog.clear()
        with caplog.at_level(logging.DEBUG, logger="security.audit"):
            assert call_at(middleware, request, 1_001.0).status_code == 302
        assert audit_events(caplog) == [
            (logging.WARNING, "AUDIT_DENIED", terminated("fingerprint_mismatch"))
        ]

    def test_request_and_termination_events_name_the_same_subject_and_address(self, caplog):
        middleware = AuditMiddleware(SessionSecurityMiddleware(ok_response))
        request = make_request()
        request.user.sub = "user-\x1b[31m123\n"
        initialize(middleware, request)
        change_user_agent(request)
        caplog.clear()
        with caplog.at_level(logging.DEBUG, logger="security.audit"):
            assert call_at(middleware, request, 1_001.0).status_code == 302
        termination, completed = audit_events(caplog)
        assert termination == (logging.WARNING, "AUDIT_DENIED", terminated("fingerprint_mismatch"))
        assert completed[2]["event"] == "request.completed"
        assert completed[2]["status"] == 302
        assert completed[2]["uid"] == termination[2]["uid"] == "user-123"
        assert completed[2]["ip_hash"] == termination[2]["ip_hash"]

    def test_a_hook_that_signs_the_user_out_keeps_the_terminated_subject(self, caplog):
        class Anonymous:
            is_authenticated = False

        class SignsOut(SessionSecurityMiddleware):
            def on_violation(self, request, reason):
                request.user = Anonymous()
                return HttpResponseForbidden(reason)

        middleware = SignsOut(ok_response)
        request = make_request()
        initialize(middleware, request)
        change_email(request)
        with caplog.at_level(logging.DEBUG, logger="security.audit"):
            assert call_at(middleware, request, 1_001.0).status_code == 403
        assert audit_events(caplog) == [
            (logging.WARNING, "AUDIT_DENIED", terminated("claim_drift"))
        ]

    def test_an_address_that_cannot_be_validated_is_recorded_as_null(self, caplog):
        middleware = SessionSecurityMiddleware(ok_response)
        request = make_request()
        initialize(middleware, request)
        request.META["REMOTE_ADDR"] = "not-an-ip"
        with caplog.at_level(logging.DEBUG, logger="security.audit"):
            assert call_at(middleware, request, 1_001.0).status_code == 302
        assert audit_events(caplog) == [
            (logging.WARNING, "AUDIT_DENIED", terminated("session_evaluation_error", ip_hash=None))
        ]

    def test_a_failure_to_record_never_undoes_the_termination(self, caplog, settings):
        middleware = SessionSecurityMiddleware(ok_response)
        request = make_request()
        initialize(middleware, request)
        settings.SESSION_ARMOR_AUDIT_PEPPER = "too-short"
        change_user_agent(request)
        with caplog.at_level(logging.DEBUG, logger="security.audit"):
            assert call_at(middleware, request, 1_001.0).status_code == 302
        assert request.session == {"_flushed": True}
        records = [record for record in caplog.records if record.name == "security.audit"]
        assert [(record.levelno, record.getMessage()) for record in records] == [
            (logging.CRITICAL, "Security audit failed while recording a session termination")
        ]
        assert records[0].exc_info[0] is SessionConfigurationError

    def test_the_audit_logger_can_be_renamed(self, caplog):
        class Renamed(SessionSecurityMiddleware):
            audit_logger_name = "example.audit"

        middleware = Renamed(ok_response)
        request = make_request()
        initialize(middleware, request)
        change_user_agent(request)
        with caplog.at_level(logging.DEBUG, logger="example.audit"):
            assert call_at(middleware, request, 1_001.0).status_code == 302
        assert audit_events(caplog, "example.audit") == [
            (logging.WARNING, "AUDIT_DENIED", terminated("fingerprint_mismatch"))
        ]
        assert audit_events(caplog) == []

    def test_a_subclass_that_sets_up_its_own_init_still_records(self, caplog):
        class OwnInit(SessionSecurityMiddleware):
            def __init__(self, get_response):
                self.get_response = get_response

        middleware = OwnInit(ok_response)
        request = make_request()
        initialize(middleware, request)
        change_user_agent(request)
        with caplog.at_level(logging.DEBUG, logger="security.audit"):
            assert call_at(middleware, request, 1_001.0).status_code == 302
        assert audit_events(caplog) == [
            (logging.WARNING, "AUDIT_DENIED", terminated("fingerprint_mismatch"))
        ]

    @pytest.mark.parametrize("name", ["", None, b"security.audit"])
    def test_the_audit_logger_must_be_named(self, name):
        class Unnamed(SessionSecurityMiddleware):
            audit_logger_name = name

        with pytest.raises(SessionConfigurationError, match="audit_logger_name"):
            Unnamed(ok_response)


class TestLoginUrl:
    def test_lazy_login_url_is_honoured(self, settings):
        settings.LOGIN_URL = lazystr("/accounts/sign-in/")
        middleware = SessionSecurityMiddleware(ok_response)
        request = make_request()
        initialize(middleware, request)
        request.META["HTTP_USER_AGENT"] = "AttackerAgent"
        response = call_at(middleware, request, 1_001.0)
        assert response.status_code == 302
        assert response["Location"] == "/accounts/sign-in/"


class TestUserAgentBinding:
    def test_client_without_user_agent_keeps_a_bound_session(self):
        middleware = SessionSecurityMiddleware(ok_response)
        request = make_request()
        del request.META["HTTP_USER_AGENT"]
        initialize(middleware, request)
        assert request.session_assurance.binding_factors == ("ip", "user_agent")
        request.META["HTTP_USER_AGENT"] = ""
        assert call_at(middleware, request, 1_001.0).status_code == 200

        request.META["HTTP_USER_AGENT"] = "TestAgent/1.0"
        assert call_at(middleware, request, 1_002.0).status_code == 302
        assert request.session_assurance.reason == "fingerprint_mismatch"

    def test_user_agent_that_disappears_is_a_fingerprint_mismatch(self):
        middleware = SessionSecurityMiddleware(ok_response)
        request = make_request()
        initialize(middleware, request)
        del request.META["HTTP_USER_AGENT"]
        assert call_at(middleware, request, 1_001.0).status_code == 302
        assert request.session_assurance.reason == "fingerprint_mismatch"


class TestEstablish:
    def test_login_response_cookie_is_bound_to_the_login_client(self):
        middleware = SessionSecurityMiddleware(ok_response)
        login = make_request("/login/", session=SessionStore())
        with patch("session_armor.adapters.django.session.time.time", return_value=1_000.0):
            middleware.establish(login)
        login.session.save()
        cookie = login.session.session_key

        replay = make_request(session=SessionStore(session_key=cookie))
        replay.META["REMOTE_ADDR"] = "203.0.113.9"
        assert call_at(middleware, replay, 1_001.0).status_code == 302
        assert replay.session_assurance.reason == "fingerprint_mismatch"

        follow_up = make_request(session=SessionStore(session_key=cookie))
        assert call_at(middleware, follow_up, 1_001.0).status_code == 200
        assert follow_up.session_assurance.trusted
        assert follow_up.session_assurance.established_at == 1_000.0

    def test_establish_binds_the_given_user_and_replaces_stale_state(self):
        class Anonymous:
            is_authenticated = False

        middleware = SessionSecurityMiddleware(ok_response)
        request = make_request(session=FakeSession({"_sa_nonce": "stale", "_ss_old": 1}))
        request.user = Anonymous()
        with patch("session_armor.adapters.django.session.time.time", return_value=1_000.0):
            middleware.establish(request, FakeUser())
        assert request.session["_cycled"] is True
        assert "_ss_old" not in request.session

        request.user = FakeUser()
        assert call_at(middleware, request, 1_001.0).status_code == 200
        assert request.session_assurance.established_at == 1_000.0

    def test_establish_requires_a_subject(self):
        class NoSubject:
            is_authenticated = True

        request = make_request()
        with pytest.raises(ValueError):
            SessionSecurityMiddleware(ok_response).establish(request, NoSubject())
        assert "_sa_version" not in request.session


def test_evidence_from_state_written_ahead_never_postdates_its_verification():
    # Another instance, 20 s ahead (inside SESSION_ARMOR_CLOCK_SKEW), wrote the state.
    middleware = SessionSecurityMiddleware(ok_response)
    request = make_request()
    initialize(middleware, request, now=1_020.0)

    request = make_request(session=request.session)
    initialize(middleware, request, now=1_000.0)

    evidence = request.session_assurance
    assert evidence.trusted
    assert evidence.established_at == evidence.last_activity_at == evidence.verified_at == 1_000.0
    assert request.session["_sa_started_at"] == request.session["_sa_seen_at"] == 1_020.0


def test_refresh_assurance_reverifies_and_reissues_trusted_evidence():
    middleware = SessionSecurityMiddleware(ok_response)
    request = make_request()
    initialize(middleware, request)
    before = request.session_assurance
    stored = dict(request.session)

    with patch("session_armor.adapters.django.session.time.time", return_value=1_040.0):
        evidence = middleware.refresh_assurance(request)

    assert evidence is request.session_assurance
    assert evidence.trusted
    assert evidence.reason == "reverified"
    assert evidence.verified_at == 1_040.0
    assert evidence.session_identifier == before.session_identifier
    assert evidence.established_at == before.established_at
    assert request.session == stored


def test_refresh_assurance_withdraws_trust_without_touching_the_session():
    middleware = SessionSecurityMiddleware(ok_response)
    request = make_request()
    initialize(middleware, request)
    stored = dict(request.session)

    request.META["HTTP_USER_AGENT"] = "AttackerAgent"
    with patch("session_armor.adapters.django.session.time.time", return_value=1_001.0):
        evidence = middleware.refresh_assurance(request)
    assert evidence.status is AssuranceStatus.UNVERIFIED
    assert evidence.reason == "fingerprint_mismatch"

    request.META["HTTP_USER_AGENT"] = "TestAgent/1.0"
    assert middleware.refresh_assurance(request) is None
    assert request.session_assurance is evidence
    assert request.session == stored


def test_refresh_assurance_logs_a_contained_error(caplog):
    class Flaky(SessionSecurityMiddleware):
        broken = False

        def get_fingerprint_factors(self, request):
            if self.broken:
                raise ConnectionError("device signal unavailable")
            return super().get_fingerprint_factors(request)

    middleware = Flaky(ok_response)
    request = make_request("/private/area/")
    initialize(middleware, request)
    stored = dict(request.session)
    middleware.broken = True
    with caplog.at_level(logging.DEBUG, logger="session_armor.session"):
        evidence = call_at(middleware.refresh_assurance, request, 1_001.0)
    assert evidence.status is AssuranceStatus.UNVERIFIED
    assert evidence.reason == "session_evaluation_error"
    assert request.session == stored
    records = [record for record in caplog.records if record.name == "session_armor.session"]
    assert [(record.levelno, record.getMessage()) for record in records] == [
        (logging.WARNING, "SessionArmor session re-verification failed")
    ]
    assert records[0].exc_info[0] is ConnectionError
    assert "/private/area/" not in caplog.text


def test_refresh_assurance_never_grants_trust_or_moves_it_to_another_user():
    class Exempt(SessionSecurityMiddleware):
        exempt_paths = ("/health",)

    middleware = Exempt(ok_response)
    request = make_request()
    initialize(middleware, request)
    exempt = make_request("/health/live", session=request.session)
    middleware(exempt)
    assert middleware.refresh_assurance(exempt) is None
    assert exempt.session_assurance.reason == "exempt_path"

    with patch("session_armor.adapters.django.session.time.time", return_value=1_001.0):
        evidence = middleware.refresh_assurance(request, FakeUser(sub="someone-else"))
    assert evidence.status is AssuranceStatus.UNVERIFIED


def test_rebaseline_reissues_evidence_from_library_settings_only_on_request(settings):
    middleware = SessionSecurityMiddleware(ok_response)
    request = make_request()
    initialize(middleware, request)
    before = request.session_assurance

    request.user.email = "reviewed@example.com"
    middleware.rebaseline_claims(request, request.user)
    assert request.session_assurance is before

    with patch("session_armor.adapters.django.session.time.time", return_value=1_040.0):
        middleware.rebaseline_claims(request, request.user, refresh_assurance=True)
    evidence = request.session_assurance
    assert evidence.trusted
    assert evidence.reason == "claims_rebaselined"
    assert evidence.verified_at == 1_040.0
    assert evidence.session_identifier == before.session_identifier
    assert evidence.claims_bound is True

    settings.SESSION_ARMOR_DETECT_CLAIM_DRIFT = False
    with patch("session_armor.adapters.django.session.time.time", return_value=1_041.0):
        middleware.rebaseline_claims(request, refresh_assurance=True)
    assert request.session_assurance.trusted
    assert request.session_assurance.claims_bound is False

    with patch("session_armor.adapters.django.session.time.time", return_value=1_042.0):
        middleware.rebaseline_claims(request, FakeUser(sub="someone-else"), refresh_assurance=True)
    assert request.session_assurance.status is AssuranceStatus.UNVERIFIED
    assert request.session_assurance.reason == "subject_changed"


def test_state_presence_and_discard_are_public():
    request = make_request(session=FakeSession({"app": "kept", "_ss_auth_time": 1}))
    assert not SessionSecurityMiddleware.has_state(request.session)
    initialize(SessionSecurityMiddleware(ok_response), request)
    assert SessionSecurityMiddleware.has_state(request.session)

    request.session["_ss_legacy"] = "x"
    SessionSecurityMiddleware.discard_state(request.session)
    assert not SessionSecurityMiddleware.has_state(request.session)
    assert not any(key.startswith(("_sa_", "_ss_")) for key in request.session)
    assert request.session["app"] == "kept"


def test_binding_digests_are_keyed_per_factor_and_correlate_with_the_audit_hash():
    request = make_request()
    digests = SessionSecurityMiddleware(ok_response).binding_digests(request)
    assert digests == {
        "ip": hash_ip("10.0.0.1", length=12),
        "user_agent": hash_ip("TestAgent/1.0", length=12),
    }
    assert hash_ip("10.0.0.1", length=32).startswith(digests["ip"])
