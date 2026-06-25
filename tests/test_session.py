"""Tests for session_armor.session.SessionSecurityMiddleware."""

import hashlib
import time

import pytest
from django.http import HttpResponse
from django.test import RequestFactory

from session_armor.session import SessionSecurityMiddleware


class FakeUser:
    is_authenticated = True
    sub = 'user-123'
    email = 'test@example.com'


class FakeSession(dict):
    """Dict with cycle_key() and flush() for testing."""

    def cycle_key(self):
        self['_cycled'] = True

    def flush(self):
        self.clear()
        self['_flushed'] = True


def ok_response(request):
    return HttpResponse("OK")


def make_request(path='/test/'):
    factory = RequestFactory()
    request = factory.get(path)
    request.user = FakeUser()
    request.session = FakeSession()
    request.META['REMOTE_ADDR'] = '10.0.0.1'
    request.META['HTTP_USER_AGENT'] = 'TestAgent/1.0'
    return request


def _fingerprint(ip='10.0.0.1', ua='TestAgent/1.0'):
    return hashlib.sha256(f'{ip}|{ua}'.encode('utf-8')).hexdigest()


def _claims_hash(sub='user-123', email='test@example.com'):
    return hashlib.sha256(f'{sub}|{email}'.encode('utf-8')).hexdigest()


# ── Tests ────────────────────────────────────────────────────────────────

class TestSessionSecurityMiddleware:
    def test_unauthenticated_passes_through(self):
        middleware = SessionSecurityMiddleware(ok_response)
        request = make_request()
        request.user.is_authenticated = False
        response = middleware(request)
        assert response.status_code == 200

    def test_first_request_initializes_session(self, settings):
        settings.SESSION_ARMOR_TRUSTED_PROXY_DEPTH = 0
        middleware = SessionSecurityMiddleware(ok_response)
        request = make_request()

        response = middleware(request)

        assert response.status_code == 200
        assert '_ss_auth_time' in request.session
        assert '_ss_last_active' in request.session
        assert '_ss_fingerprint' in request.session
        assert '_ss_claims_hash' in request.session
        assert request.session.get('_cycled') is True  # session.cycle_key() called

    def test_subsequent_request_updates_last_active(self, settings):
        settings.SESSION_ARMOR_TRUSTED_PROXY_DEPTH = 0
        middleware = SessionSecurityMiddleware(ok_response)
        request = make_request()

        now = time.time()
        request.session['_ss_auth_time'] = now
        request.session['_ss_last_active'] = now - 10
        request.session['_ss_fingerprint'] = _fingerprint()
        request.session['_ss_claims_hash'] = _claims_hash()

        response = middleware(request)
        assert response.status_code == 200
        assert request.session['_ss_last_active'] > now - 10

    def test_last_active_throttled_skips_recent_write(self, settings):
        settings.SESSION_ARMOR_TRUSTED_PROXY_DEPTH = 0

        class ThrottledSecurity(SessionSecurityMiddleware):
            last_active_resolution = 60

        middleware = ThrottledSecurity(ok_response)
        request = make_request()

        now = time.time()
        recent = now - 5  # within the 60s resolution window
        request.session['_ss_auth_time'] = now
        request.session['_ss_last_active'] = recent
        request.session['_ss_fingerprint'] = _fingerprint()
        request.session['_ss_claims_hash'] = _claims_hash()

        response = middleware(request)
        assert response.status_code == 200
        # Not enough time elapsed → timestamp left untouched (no session write).
        assert request.session['_ss_last_active'] == recent

    def test_last_active_throttled_writes_after_resolution(self, settings):
        settings.SESSION_ARMOR_TRUSTED_PROXY_DEPTH = 0

        class ThrottledSecurity(SessionSecurityMiddleware):
            last_active_resolution = 60

        middleware = ThrottledSecurity(ok_response)
        request = make_request()

        now = time.time()
        stale = now - 120  # beyond the resolution window
        request.session['_ss_auth_time'] = now
        request.session['_ss_last_active'] = stale
        request.session['_ss_fingerprint'] = _fingerprint()
        request.session['_ss_claims_hash'] = _claims_hash()

        response = middleware(request)
        assert response.status_code == 200
        assert request.session['_ss_last_active'] > stale

    def test_absolute_timeout(self, settings):
        settings.SESSION_ABSOLUTE_TIMEOUT = 100
        settings.SESSION_ARMOR_TRUSTED_PROXY_DEPTH = 0
        middleware = SessionSecurityMiddleware(ok_response)
        request = make_request()

        request.session['_ss_auth_time'] = time.time() - 200
        request.session['_ss_last_active'] = time.time()
        request.session['_ss_fingerprint'] = _fingerprint()
        request.session['_ss_claims_hash'] = _claims_hash()

        response = middleware(request)
        assert response.status_code == 302  # redirect to login

    def test_idle_timeout(self, settings):
        settings.SESSION_IDLE_TIMEOUT = 60
        settings.SESSION_ARMOR_TRUSTED_PROXY_DEPTH = 0
        middleware = SessionSecurityMiddleware(ok_response)
        request = make_request()

        request.session['_ss_auth_time'] = time.time()
        request.session['_ss_last_active'] = time.time() - 120
        request.session['_ss_fingerprint'] = _fingerprint()
        request.session['_ss_claims_hash'] = _claims_hash()

        response = middleware(request)
        assert response.status_code == 302

    def test_fingerprint_mismatch(self, settings):
        settings.SESSION_ARMOR_TRUSTED_PROXY_DEPTH = 0
        middleware = SessionSecurityMiddleware(ok_response)
        request = make_request()

        request.session['_ss_auth_time'] = time.time()
        request.session['_ss_last_active'] = time.time()
        request.session['_ss_fingerprint'] = 'wrong_fingerprint'
        request.session['_ss_claims_hash'] = _claims_hash()

        response = middleware(request)
        assert response.status_code == 302

    def test_claim_drift(self, settings):
        settings.SESSION_DETECT_CLAIM_DRIFT = True
        settings.SESSION_ARMOR_TRUSTED_PROXY_DEPTH = 0
        middleware = SessionSecurityMiddleware(ok_response)
        request = make_request()

        request.session['_ss_auth_time'] = time.time()
        request.session['_ss_last_active'] = time.time()
        request.session['_ss_fingerprint'] = _fingerprint()
        request.session['_ss_claims_hash'] = 'old_claims_hash'

        response = middleware(request)
        assert response.status_code == 302

    def test_exempt_path(self, settings):
        class ExemptSecurity(SessionSecurityMiddleware):
            exempt_paths = ('/health/',)

        middleware = ExemptSecurity(ok_response)
        request = make_request(path='/health/check')
        # No session data at all — would fail if not exempt
        response = middleware(request)
        assert response.status_code == 200
