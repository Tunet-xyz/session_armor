"""Tests for session_armor.audit.AuditMiddleware."""

import logging

import pytest
from django.http import HttpResponse
from django.test import RequestFactory

from session_armor.audit import AuditMiddleware


class FakeUser:
    is_authenticated = True
    sub = 'user-456'
    pk = 42


def ok_response(request):
    return HttpResponse("OK")


def error_response(request):
    return HttpResponse("Forbidden", status=403)


def make_request(path='/test/', authenticated=True):
    factory = RequestFactory()
    request = factory.get(path)
    if authenticated:
        request.user = FakeUser()
    request.META['REMOTE_ADDR'] = '10.0.0.1'
    return request


class TestAuditMiddleware:
    def test_attaches_request_id(self):
        middleware = AuditMiddleware(ok_response)
        request = make_request()
        middleware(request)
        assert 'X_REQUEST_ID' in request.META
        assert len(request.META['X_REQUEST_ID']) == 8

    def test_logs_authenticated_request(self, caplog, settings):
        settings.SESSION_ARMOR_TRUSTED_PROXY_DEPTH = 0
        middleware = AuditMiddleware(ok_response)
        request = make_request()

        with caplog.at_level(logging.DEBUG, logger='security.audit'):
            middleware(request)

        assert len(caplog.records) == 1
        assert 'AUDIT' in caplog.records[0].message

    def test_skips_unauthenticated(self, caplog, settings):
        settings.SESSION_ARMOR_TRUSTED_PROXY_DEPTH = 0
        middleware = AuditMiddleware(ok_response)
        request = make_request(authenticated=False)

        with caplog.at_level(logging.DEBUG, logger='security.audit'):
            middleware(request)

        assert len(caplog.records) == 0

    def test_denied_request_logged_differently(self, caplog, settings):
        settings.SESSION_ARMOR_TRUSTED_PROXY_DEPTH = 0
        middleware = AuditMiddleware(error_response)
        request = make_request()

        with caplog.at_level(logging.DEBUG, logger='security.audit'):
            middleware(request)

        assert len(caplog.records) == 1
        assert 'AUDIT_DENIED' in caplog.records[0].message

    def test_exempt_path_skips_logging(self, caplog, settings):
        settings.SESSION_ARMOR_TRUSTED_PROXY_DEPTH = 0

        class ExemptAudit(AuditMiddleware):
            exempt_paths = ('/health/',)

        middleware = ExemptAudit(ok_response)
        request = make_request(path='/health/ping')

        with caplog.at_level(logging.DEBUG, logger='security.audit'):
            middleware(request)

        assert len(caplog.records) == 0

    def test_custom_identity(self, caplog, settings):
        settings.SESSION_ARMOR_TRUSTED_PROXY_DEPTH = 0

        class CustomAudit(AuditMiddleware):
            def get_user_identity(self, request):
                return {'uid': 'custom-id', 'role': 'admin'}

        middleware = CustomAudit(ok_response)
        request = make_request()

        with caplog.at_level(logging.DEBUG, logger='security.audit'):
            middleware(request)

        assert 'custom-id' in caplog.records[0].message

    def test_before_log_suppression(self, caplog, settings):
        settings.SESSION_ARMOR_TRUSTED_PROXY_DEPTH = 0

        class SuppressAudit(AuditMiddleware):
            def before_log(self, request, response, entry):
                return None  # suppress

        middleware = SuppressAudit(ok_response)
        request = make_request()

        with caplog.at_level(logging.DEBUG, logger='security.audit'):
            middleware(request)

        assert len(caplog.records) == 0
