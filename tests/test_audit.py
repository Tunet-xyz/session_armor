"""Tests for structured, fail-closed security audit events."""

from __future__ import annotations

import json
import logging
from types import SimpleNamespace

import pytest
from django.contrib.auth import logout
from django.contrib.sessions.backends.cache import SessionStore
from django.http import HttpResponse
from django.test import RequestFactory, override_settings

from session_armor import AuditEmissionError
from session_armor.adapters.django import AuditMiddleware


class FakeUser:
    is_authenticated = True
    sub = "user-456"
    pk = 42


def ok_response(_request):
    return HttpResponse("OK")


def make_request(path="/test/", *, authenticated=True, **extra):
    request = RequestFactory().get(path, **extra)
    if authenticated:
        request.user = FakeUser()
    request.META["REMOTE_ADDR"] = "10.0.0.1"
    request.META["HTTP_USER_AGENT"] = "Test/1.0"
    return request


class TestAuditMiddleware:
    def test_full_request_id_is_propagated_and_structured(self, caplog):
        request = make_request()
        with caplog.at_level(logging.DEBUG, logger="security.audit"):
            response = AuditMiddleware(ok_response)(request)
        request_id = request.META["X_REQUEST_ID"]
        assert len(request_id) == 32
        assert response.headers["X-Request-ID"] == request_id
        prefix, payload = caplog.records[0].message.split(" ", 1)
        assert prefix == "AUDIT"
        assert json.loads(payload)["rid"] == request_id

    def test_unauthenticated_and_exempt_requests_are_not_logged(self, caplog):
        class Exempt(AuditMiddleware):
            exempt_paths = ("/health",)

        with caplog.at_level(logging.DEBUG, logger="security.audit"):
            AuditMiddleware(ok_response)(make_request(authenticated=False))
            Exempt(ok_response)(make_request("/health/live"))
        assert not caplog.records

    def test_exempt_paths_match_the_routed_path_not_the_script_prefix(self, caplog):
        class Exempt(AuditMiddleware):
            exempt_paths = ("/static/",)

        with caplog.at_level(logging.DEBUG, logger="security.audit"):
            Exempt(ok_response)(make_request("/static/app.css", SCRIPT_NAME="/app"))
            assert not caplog.records
            # A client-chosen SCRIPT_NAME must not hide the view Django routes to.
            Exempt(ok_response)(make_request("/account/", SCRIPT_NAME="/static"))
        assert len(caplog.records) == 1

    def test_denied_request_has_distinct_prefix(self, caplog):
        with caplog.at_level(logging.WARNING, logger="security.audit"):
            AuditMiddleware(lambda _request: HttpResponse(status=403))(make_request())
        assert caplog.records[0].message.startswith("AUDIT_DENIED ")

    def test_custom_fields_cannot_override_reserved_evidence(self):
        class Collision(AuditMiddleware):
            def get_extra_fields(self, request, response):
                return {"status": 200}

        with pytest.raises(AuditEmissionError):
            Collision(lambda _request: HttpResponse(status=403))(make_request())

        class LateCollision(AuditMiddleware):
            def before_log(self, request, response, entry):
                return {**entry, "status": 200}

        with pytest.raises(AuditEmissionError):
            LateCollision(lambda _request: HttpResponse(status=403))(make_request())

    def test_nested_control_characters_are_sanitized(self, caplog):
        class Injection(AuditMiddleware):
            def get_user_identity(self, request):
                return {"uid": "evil\nforged", "claims": {"role": "admin\rroot"}}

        with caplog.at_level(logging.DEBUG, logger="security.audit"):
            Injection(ok_response)(make_request())
        assert "\n" not in caplog.records[0].message
        assert "\r" not in caplog.records[0].message

    def test_suppression_requires_explicit_class_configuration(self):
        class Suppress(AuditMiddleware):
            def before_log(self, request, response, entry):
                return None

        with pytest.raises(AuditEmissionError):
            Suppress(ok_response)(make_request())

        class AllowedSuppress(Suppress):
            allow_suppression = True

        assert AllowedSuppress(ok_response)(make_request()).status_code == 200

    def test_exception_path_is_audited_without_masking_original(self, caplog):
        def explode(_request):
            raise RuntimeError("boom")

        with caplog.at_level(logging.ERROR, logger="security.audit"):
            with pytest.raises(RuntimeError, match="boom"):
                AuditMiddleware(explode)(make_request())
        assert '\"event\":\"request.failed\"' in caplog.records[0].message
        assert '\"error_type\":\"RuntimeError\"' in caplog.records[0].message

    def test_custom_fields_cannot_shadow_identity_or_failure_evidence(self, caplog):
        class Shadow(AuditMiddleware):
            def get_extra_fields(self, request, response):
                return {"uid": "someone-else"}

        with pytest.raises(AuditEmissionError):
            Shadow(ok_response)(make_request())

        class ForgedFailure(AuditMiddleware):
            def get_extra_fields(self, request, response):
                return {"error_type": "PermissionDenied"}

        with pytest.raises(AuditEmissionError):
            ForgedFailure(ok_response)(make_request())

        class DropFailure(AuditMiddleware):
            def before_log(self, request, response, entry):
                return {key: value for key, value in entry.items() if key != "error_type"}

        def explode(_request):
            raise RuntimeError("boom")

        with caplog.at_level(logging.DEBUG, logger="security.audit"):
            with pytest.raises(RuntimeError, match="boom"):
                DropFailure(explode)(make_request())
        assert [record.levelno for record in caplog.records] == [logging.CRITICAL]

    def test_in_place_hook_edits_cannot_alter_reserved_evidence(self):
        class InPlace(AuditMiddleware):
            def before_log(self, request, response, entry):
                entry["path"] = "/redacted"
                return entry

        with pytest.raises(AuditEmissionError):
            InPlace(ok_response)(make_request())

    def test_unresolvable_client_ip_is_recorded_not_dropped(self, caplog):
        request = make_request()
        # The entry the trusted proxy wrote for the client cannot be parsed.
        request.META["HTTP_X_FORWARDED_FOR"] = "not-an-ip"
        with override_settings(
            SESSION_ARMOR_TRUSTED_PROXY_DEPTH=1, SESSION_ARMOR_TRUSTED_PROXY_CIDRS=("10.0.0.0/8",)
        ):
            with caplog.at_level(logging.DEBUG, logger="security.audit"):
                assert AuditMiddleware(ok_response)(request).status_code == 200
        entry = json.loads(caplog.records[0].message.split(" ", 1)[1])
        assert entry["ip_hash"] is None
        assert entry["uid"] == "user-456"

    def test_audit_path_hook_redacts_url_secrets_and_stays_reserved(self, caplog):
        class Redacting(AuditMiddleware):
            def get_audit_path(self, request):
                if request.path.startswith("/invitation/"):
                    return "/invitation/[token]/"
                return request.path

        with caplog.at_level(logging.DEBUG, logger="security.audit"):
            Redacting(ok_response)(make_request("/invitation/s3cret-token/"))
        assert "s3cret-token" not in caplog.records[0].message
        assert '"path":"/invitation/[token]/"' in caplog.records[0].message

        class Unredacting(Redacting):
            def before_log(self, request, response, entry):
                return {**entry, "path": request.path}

        with pytest.raises(AuditEmissionError):
            Unredacting(ok_response)(make_request("/invitation/s3cret-token/"))

        class NotAString(AuditMiddleware):
            def get_audit_path(self, request):
                return None

        with pytest.raises(AuditEmissionError):
            NotAString(ok_response)(make_request())

    def test_request_that_logs_out_is_recorded_for_its_user(self, caplog):
        def sign_out(request):
            logout(request)
            return HttpResponse("bye")

        request = make_request("/logout/")
        request.session = SessionStore()
        with caplog.at_level(logging.DEBUG, logger="security.audit"):
            AuditMiddleware(sign_out)(request)
        assert json.loads(caplog.records[0].message.split(" ", 1)[1])["uid"] == "user-456"
        assert not request.user.is_authenticated

    def test_oversized_entry_stays_valid_json_with_the_actor(self, caplog):
        class Referer(AuditMiddleware):
            def get_extra_fields(self, request, response):
                return {"referer": request.META.get("HTTP_REFERER", "")}

        wide = "\U0001f600" * 500  # each character is escaped to 12 in the line
        request = make_request("/" + wide)
        request.META["HTTP_USER_AGENT"] = wide
        request.META["HTTP_REFERER"] = wide
        with caplog.at_level(logging.WARNING, logger="security.audit"):
            Referer(lambda _request: HttpResponse(status=403))(request)
        prefix, payload = caplog.records[0].message.split(" ", 1)
        entry = json.loads(payload)
        assert prefix == "AUDIT_DENIED"
        assert (entry["uid"], entry["status"], entry["truncated"]) == ("user-456", 403, True)
        assert "referer" not in entry

    def test_events_the_logger_drops_are_checked_but_not_rendered(self, caplog, monkeypatch):
        from session_armor.adapters.django import audit

        passes, rendered = [], []
        safe_value = audit._safe_value

        def counting(value, *, depth=0):
            if depth == 0:
                passes.append(value)
            return safe_value(value, depth=depth)

        monkeypatch.setattr(audit, "_safe_value", counting)
        monkeypatch.setattr(
            audit, "json", SimpleNamespace(dumps=lambda *args, **kwargs: rendered.append(args) or "{}")
        )
        with caplog.at_level(logging.INFO, logger="security.audit"):
            AuditMiddleware(ok_response)(make_request())  # 2xx is DEBUG: dropped
            assert (len(passes), rendered, caplog.records) == (1, [], [])
            AuditMiddleware(lambda _request: HttpResponse(status=404))(make_request())
        assert (len(rendered), len(caplog.records)) == (1, 1)

        class Broken(AuditMiddleware):
            def before_log(self, request, response, entry):
                return ["not", "a", "mapping"]

        with caplog.at_level(logging.INFO, logger="security.audit"):
            with pytest.raises(AuditEmissionError):  # still fails closed when dropped
                Broken(ok_response)(make_request())
