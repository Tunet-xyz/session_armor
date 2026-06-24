"""Tests for session_armor.utils."""

import pytest

from session_armor.utils import (
    get_client_ip,
    hash_ip,
    hash_value,
    is_authenticated,
    path_is_exempt,
    sanitize_for_log,
)


class FakeRequest:
    def __init__(self, meta=None):
        self.META = meta or {}


class FakeUser:
    is_authenticated = True


class AnonUser:
    is_authenticated = False


# ── hash_value ───────────────────────────────────────────────────────────

class TestHashValue:
    def test_deterministic(self):
        assert hash_value("hello") == hash_value("hello")

    def test_different_inputs(self):
        assert hash_value("a") != hash_value("b")

    def test_truncation(self):
        result = hash_value("test", length=8)
        assert len(result) == 8

    def test_full_length(self):
        result = hash_value("test")
        assert len(result) == 64  # SHA-256 hex


# ── hash_ip ──────────────────────────────────────────────────────────────

class TestHashIp:
    def test_deterministic(self, settings):
        settings.SESSION_ARMOR_AUDIT_PEPPER = 'pepper'
        assert hash_ip('1.2.3.4') == hash_ip('1.2.3.4')

    def test_different_ips(self, settings):
        settings.SESSION_ARMOR_AUDIT_PEPPER = 'pepper'
        assert hash_ip('1.2.3.4') != hash_ip('1.2.3.5')

    def test_default_length(self, settings):
        settings.SESSION_ARMOR_AUDIT_PEPPER = 'pepper'
        assert len(hash_ip('1.2.3.4')) == 16

    def test_full_length(self, settings):
        settings.SESSION_ARMOR_AUDIT_PEPPER = 'pepper'
        assert len(hash_ip('1.2.3.4', length=0)) == 64

    def test_pepper_changes_digest(self, settings):
        settings.SESSION_ARMOR_AUDIT_PEPPER = 'pepper-a'
        a = hash_ip('1.2.3.4', length=0)
        settings.SESSION_ARMOR_AUDIT_PEPPER = 'pepper-b'
        b = hash_ip('1.2.3.4', length=0)
        assert a != b

    def test_not_equal_to_unkeyed_hash(self, settings):
        # The whole point: keyed digest must differ from the reversible
        # unsalted SHA-256 an attacker would precompute.
        settings.SESSION_ARMOR_AUDIT_PEPPER = 'pepper'
        assert hash_ip('1.2.3.4', length=0) != hash_value('1.2.3.4')

    def test_falls_back_to_secret_key(self, settings):
        # No dedicated pepper → uses SECRET_KEY, still keyed (not raw SHA-256).
        settings.SESSION_ARMOR_AUDIT_PEPPER = ''
        assert hash_ip('1.2.3.4', length=0) != hash_value('1.2.3.4')


# ── get_client_ip ────────────────────────────────────────────────────────

class TestGetClientIp:
    def test_remote_addr_fallback(self, settings):
        settings.SESSION_ARMOR_TRUSTED_PROXY_DEPTH = 0
        req = FakeRequest({'REMOTE_ADDR': '1.2.3.4'})
        assert get_client_ip(req) == '1.2.3.4'

    def test_xff_no_depth(self, settings):
        settings.SESSION_ARMOR_TRUSTED_PROXY_DEPTH = 0
        req = FakeRequest({
            'HTTP_X_FORWARDED_FOR': '10.0.0.1, 10.0.0.2',
            'REMOTE_ADDR': '127.0.0.1',
        })
        # No depth = leftmost (legacy)
        assert get_client_ip(req) == '10.0.0.1'

    def test_xff_with_depth_1(self, settings):
        settings.SESSION_ARMOR_TRUSTED_PROXY_DEPTH = 1
        req = FakeRequest({
            'HTTP_X_FORWARDED_FOR': 'spoofed, real, proxy1',
            'REMOTE_ADDR': '127.0.0.1',
        })
        assert get_client_ip(req) == 'real'

    def test_xff_with_depth_1_two_entries(self, settings):
        settings.SESSION_ARMOR_TRUSTED_PROXY_DEPTH = 1
        req = FakeRequest({
            'HTTP_X_FORWARDED_FOR': 'real, proxy1',
            'REMOTE_ADDR': '127.0.0.1',
        })
        assert get_client_ip(req) == 'real'

    def test_xff_too_short_for_depth(self, settings):
        settings.SESSION_ARMOR_TRUSTED_PROXY_DEPTH = 1
        req = FakeRequest({
            'HTTP_X_FORWARDED_FOR': 'spoofed_only',
            'REMOTE_ADDR': '127.0.0.1',
        })
        # Only 1 entry but depth=1 needs at least 2 → fallback
        assert get_client_ip(req) == '127.0.0.1'

    def test_no_xff_no_remote(self, settings):
        settings.SESSION_ARMOR_TRUSTED_PROXY_DEPTH = 0
        req = FakeRequest({})
        assert get_client_ip(req) == ''

    def test_default_depth_is_secure(self, settings):
        # With the setting absent, the default must NOT trust a fully
        # client-controlled single-entry X-Forwarded-For; it falls back to
        # REMOTE_ADDR (depth defaults to 1, not 0).
        del settings.SESSION_ARMOR_TRUSTED_PROXY_DEPTH
        req = FakeRequest({
            'HTTP_X_FORWARDED_FOR': 'spoofed',
            'REMOTE_ADDR': '127.0.0.1',
        })
        assert get_client_ip(req) == '127.0.0.1'


# ── is_authenticated ─────────────────────────────────────────────────────

class TestIsAuthenticated:
    def test_authenticated_user(self):
        req = FakeRequest()
        req.user = FakeUser()
        assert is_authenticated(req) is True

    def test_anonymous_user(self):
        req = FakeRequest()
        req.user = AnonUser()
        assert is_authenticated(req) is False

    def test_no_user(self):
        req = FakeRequest()
        assert is_authenticated(req) is False


# ── sanitize_for_log ─────────────────────────────────────────────────────

class TestSanitizeForLog:
    def test_clean_string(self):
        assert sanitize_for_log("hello world") == "hello world"

    def test_strips_newlines(self):
        assert sanitize_for_log("line1\nline2\rline3") == "line1line2line3"

    def test_strips_null_bytes(self):
        assert sanitize_for_log("abc\x00def") == "abcdef"

    def test_strips_ansi_escapes(self):
        assert sanitize_for_log("\x1b[31mred\x1b[0m") == "31mred0m"

    def test_truncation(self):
        long_string = "a" * 500
        result = sanitize_for_log(long_string, max_length=100)
        assert len(result) == 100

    def test_default_max_length(self):
        long_string = "a" * 300
        result = sanitize_for_log(long_string)
        assert len(result) == 200


# ── path_is_exempt ───────────────────────────────────────────────────────

class TestPathIsExempt:
    def test_exact_match(self):
        assert path_is_exempt('/health', ('/health',)) is True

    def test_subpath_with_trailing_slash_prefix(self):
        assert path_is_exempt('/health/live', ('/health/',)) is True

    def test_subpath_without_trailing_slash_prefix(self):
        assert path_is_exempt('/health/live', ('/health',)) is True

    def test_sibling_prefix_not_exempt(self):
        # The key hardening: a shared string prefix must not leak exemption.
        assert path_is_exempt('/health-internal', ('/health',)) is False

    def test_no_prefixes(self):
        assert path_is_exempt('/anything', ()) is False

    def test_multiple_prefixes(self):
        prefixes = ('/static/', '/health')
        assert path_is_exempt('/static/app.css', prefixes) is True
        assert path_is_exempt('/health/ping', prefixes) is True
        assert path_is_exempt('/admin', prefixes) is False
