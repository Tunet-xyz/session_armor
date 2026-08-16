"""Tests for structured, fail-closed security audit events."""

from __future__ import annotations

import json
import logging

import pytest
from django.http import HttpResponse
from django.test import RequestFactory

from session_armor import AuditEmissionError
from session_armor.audit import AuditMiddleware


class FakeUser:
    is_authenticated = True
    sub = "user-456"
    pk = 42


def ok_response(_request):
    return HttpResponse("OK")


def make_request(path="/test/", *, authenticated=True):
    request = RequestFactory().get(path)
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
