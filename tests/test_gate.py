"""Tests for session_armor.gate.GateMiddleware."""

import time

import pytest
from django.http import HttpResponse, HttpResponseForbidden
from django.test import RequestFactory

from session_armor.gate import GateMiddleware


class PassGate(GateMiddleware):
    gate_id = 'test_pass'

    def check(self, request) -> bool:
        return True


class FailGate(GateMiddleware):
    gate_id = 'test_fail'

    def check(self, request) -> bool:
        return False


class ErrorGate(GateMiddleware):
    gate_id = 'test_error'
    fail_open = False

    def check(self, request) -> bool:
        raise RuntimeError("boom")


class ErrorGateFailOpen(GateMiddleware):
    gate_id = 'test_error_open'
    fail_open = True

    def check(self, request) -> bool:
        raise RuntimeError("boom")


class FakeUser:
    is_authenticated = True


def ok_response(request):
    return HttpResponse("OK")


def make_request(path='/test/', authenticated=True):
    factory = RequestFactory()
    request = factory.get(path)
    if authenticated:
        request.user = FakeUser()
    request.session = {}
    return request


# ── Tests ────────────────────────────────────────────────────────────────

class TestGateMiddleware:
    def test_pass_gate(self):
        middleware = PassGate(ok_response)
        request = make_request()
        response = middleware(request)
        assert response.status_code == 200

    def test_fail_gate_returns_403(self):
        middleware = FailGate(ok_response)
        request = make_request()
        response = middleware(request)
        assert response.status_code == 403

    def test_unauthenticated_skips_gate(self):
        middleware = FailGate(ok_response)
        request = make_request(authenticated=False)
        response = middleware(request)
        assert response.status_code == 200  # Gate skipped

    def test_exempt_path_skips_gate(self):
        class ExemptGate(FailGate):
            exempt_paths = ('/test/',)

        middleware = ExemptGate(ok_response)
        request = make_request(path='/test/something')
        response = middleware(request)
        assert response.status_code == 200

    def test_session_cache_hit(self):
        middleware = PassGate(ok_response)
        request = make_request()
        now = time.time()
        request.session['_gate_test_pass_at'] = now
        request.session['_gate_test_pass_result'] = True

        response = middleware(request)
        assert response.status_code == 200

    def test_session_cache_expired(self):
        middleware = PassGate(ok_response)
        middleware.default_cache_ttl = 60
        request = make_request()
        request.session['_gate_test_pass_at'] = time.time() - 120
        request.session['_gate_test_pass_result'] = False

        # Cache expired → re-check → PassGate returns True → 200
        response = middleware(request)
        assert response.status_code == 200

    def test_error_gate_fail_closed(self):
        middleware = ErrorGate(ok_response)
        request = make_request()
        response = middleware(request)
        assert response.status_code == 403

    def test_error_gate_fail_open(self):
        middleware = ErrorGateFailOpen(ok_response)
        request = make_request()
        response = middleware(request)
        assert response.status_code == 200

    def test_invalidate_clears_session(self):
        request = make_request()
        request.session['_gate_test_pass_at'] = time.time()
        request.session['_gate_test_pass_result'] = True
        request.session['_gate_test_pass_context'] = {'foo': 'bar'}

        PassGate.invalidate(request)

        assert '_gate_test_pass_at' not in request.session
        assert '_gate_test_pass_result' not in request.session
        assert '_gate_test_pass_context' not in request.session

    def test_get_context(self):
        request = make_request()
        request.session['_gate_test_pass_context'] = {'step': 3}
        assert PassGate.get_context(request) == {'step': 3}

    def test_get_context_empty(self):
        request = make_request()
        assert PassGate.get_context(request) == {}

    def test_before_check_false_skips(self):
        class SkipGate(FailGate):
            def before_check(self, request):
                return False

        middleware = SkipGate(ok_response)
        request = make_request()
        response = middleware(request)
        assert response.status_code == 200  # Gate skipped

    def test_sticky_pass_skips_ttl_recheck(self):
        calls = []

        class StickyGate(GateMiddleware):
            gate_id = 'test_sticky'
            recheck_after_pass = False
            default_cache_ttl = 60

            def check(self, request) -> bool:
                calls.append(1)
                return True

        middleware = StickyGate(ok_response)
        request = make_request()
        # Cached pass from long before the TTL window
        request.session['_gate_test_sticky_at'] = time.time() - 9999
        request.session['_gate_test_sticky_result'] = True

        response = middleware(request)
        assert response.status_code == 200
        assert calls == []  # check() never ran

    def test_sticky_pass_still_rechecks_failures(self):
        calls = []

        class StickyGate(GateMiddleware):
            gate_id = 'test_sticky_fail'
            recheck_after_pass = False
            default_cache_ttl = 60

            def check(self, request) -> bool:
                calls.append(1)
                return True

        middleware = StickyGate(ok_response)
        request = make_request()
        # Cached *failure* past the TTL → must re-check
        request.session['_gate_test_sticky_fail_at'] = time.time() - 120
        request.session['_gate_test_sticky_fail_result'] = False

        response = middleware(request)
        assert response.status_code == 200
        assert calls == [1]

    def test_version_mismatch_invalidates_cache(self):
        calls = []

        class VersionedGate(GateMiddleware):
            gate_id = 'test_versioned'
            recheck_after_pass = False

            def check(self, request) -> bool:
                calls.append(1)
                return True

            def get_state_version(self, request):
                return 'v2'

        middleware = VersionedGate(ok_response)
        request = make_request()
        request.session['_gate_test_versioned_at'] = time.time()
        request.session['_gate_test_versioned_result'] = True
        request.session['_gate_test_versioned_version'] = 'v1'

        response = middleware(request)
        assert response.status_code == 200
        assert calls == [1]  # Re-checked despite cached pass
        assert request.session['_gate_test_versioned_version'] == 'v2'

    def test_version_match_uses_cache(self):
        calls = []

        class VersionedGate(GateMiddleware):
            gate_id = 'test_versioned_hit'
            recheck_after_pass = False

            def check(self, request) -> bool:
                calls.append(1)
                return True

            def get_state_version(self, request):
                return 'v1'

        middleware = VersionedGate(ok_response)
        request = make_request()
        request.session['_gate_test_versioned_hit_at'] = time.time() - 9999
        request.session['_gate_test_versioned_hit_result'] = True
        request.session['_gate_test_versioned_hit_version'] = 'v1'

        response = middleware(request)
        assert response.status_code == 200
        assert calls == []

    def test_invalidate_clears_version(self):
        request = make_request()
        request.session['_gate_test_pass_version'] = 'v1'
        PassGate.invalidate(request)
        assert '_gate_test_pass_version' not in request.session

    def test_not_implemented_check(self):
        class NoCheck(GateMiddleware):
            gate_id = 'nocheck'

        middleware = NoCheck(ok_response)
        request = make_request()
        # check() raises NotImplementedError → on_error → fail_open=False → 403
        response = middleware(request)
        assert response.status_code == 403
