"""Tests for SessionArmor's Django adapter utilities."""

import hashlib
import hmac
import re

import pytest

from session_armor import SessionConfigurationError
from session_armor.adapters.django.utils import (
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
        settings.SESSION_ARMOR_AUDIT_PEPPER = "pepper-long-enough-for-tests"
        assert hash_ip("1.2.3.4") == hash_ip("1.2.3.4")

    def test_different_ips(self, settings):
        settings.SESSION_ARMOR_AUDIT_PEPPER = "pepper-long-enough-for-tests"
        assert hash_ip("1.2.3.4") != hash_ip("1.2.3.5")

    def test_default_length(self, settings):
        settings.SESSION_ARMOR_AUDIT_PEPPER = "pepper-long-enough-for-tests"
        assert len(hash_ip("1.2.3.4")) == 16

    def test_full_length(self, settings):
        settings.SESSION_ARMOR_AUDIT_PEPPER = "pepper-long-enough-for-tests"
        assert len(hash_ip("1.2.3.4", length=0)) == 64

    def test_pepper_changes_digest(self, settings):
        settings.SESSION_ARMOR_AUDIT_PEPPER = "pepper-a-long-enough"
        a = hash_ip("1.2.3.4", length=0)
        settings.SESSION_ARMOR_AUDIT_PEPPER = "pepper-b-long-enough"
        b = hash_ip("1.2.3.4", length=0)
        assert a != b

    def test_not_equal_to_unkeyed_hash(self, settings):
        # The whole point: keyed digest must differ from the reversible
        # unsalted SHA-256 an attacker would precompute.
        settings.SESSION_ARMOR_AUDIT_PEPPER = "pepper-long-enough-for-tests"
        assert hash_ip("1.2.3.4", length=0) != hash_value("1.2.3.4")

    @pytest.mark.parametrize("value", [64, [65] * 20])
    def test_non_text_pepper_is_a_configuration_error(self, settings, value):
        settings.SESSION_ARMOR_AUDIT_PEPPER = value
        with pytest.raises(SessionConfigurationError):
            hash_ip("1.2.3.4")

    def test_bytes_pepper_is_accepted(self, settings):
        settings.SESSION_ARMOR_AUDIT_PEPPER = b"bytes-pepper-long-enough"
        assert len(hash_ip("1.2.3.4")) == 16

    @pytest.mark.parametrize(
        "purpose",
        [
            "session-armor:state:v1",
            "session-armor:binding:v1",
            "session-armor:claims:v1",
            "session-armor:identifier:v1",
        ],
    )
    def test_never_digests_a_state_mac_subkey(self, settings, purpose):
        # The pepper and the state key both default to SECRET_KEY.
        settings.SESSION_ARMOR_AUDIT_PEPPER = "shared-secret-long-enough"
        settings.SESSION_ARMOR_STATE_KEY = "shared-secret-long-enough"
        subkey = hmac.new(b"shared-secret-long-enough", purpose.encode(), hashlib.sha256)
        assert hash_ip(purpose, length=0) != subkey.hexdigest()
        assert hash_ip(purpose, length=0) == hash_ip(purpose, length=0)

    def test_ip_digests_are_unchanged(self, settings):
        settings.SESSION_ARMOR_AUDIT_PEPPER = "pepper-long-enough-for-tests"
        expected = hmac.new(b"pepper-long-enough-for-tests", b"1.2.3.4", hashlib.sha256)
        assert hash_ip("1.2.3.4", length=0) == expected.hexdigest()

    def test_falls_back_to_secret_key(self, settings):
        # No dedicated pepper → uses SECRET_KEY, still keyed (not raw SHA-256).
        settings.SESSION_ARMOR_AUDIT_PEPPER = ""
        assert hash_ip("1.2.3.4", length=0) != hash_value("1.2.3.4")


# ── get_client_ip ────────────────────────────────────────────────────────


class TestGetClientIp:
    def test_remote_addr_fallback(self, settings):
        settings.SESSION_ARMOR_TRUSTED_PROXY_DEPTH = 0
        req = FakeRequest({"REMOTE_ADDR": "1.2.3.4"})
        assert get_client_ip(req) == "1.2.3.4"

    def test_xff_no_depth(self, settings):
        settings.SESSION_ARMOR_TRUSTED_PROXY_DEPTH = 0
        req = FakeRequest(
            {
                "HTTP_X_FORWARDED_FOR": "10.0.0.1, 10.0.0.2",
                "REMOTE_ADDR": "127.0.0.1",
            }
        )
        # No trusted proxy topology means forwarded headers are ignored.
        assert get_client_ip(req) == "127.0.0.1"

    def test_xff_with_depth_1(self, settings):
        settings.SESSION_ARMOR_TRUSTED_PROXY_DEPTH = 1
        settings.SESSION_ARMOR_TRUSTED_PROXY_CIDRS = ("127.0.0.0/8",)
        req = FakeRequest(
            {
                "HTTP_X_FORWARDED_FOR": "192.0.2.99, 198.51.100.8",
                "REMOTE_ADDR": "127.0.0.1",
            }
        )
        assert get_client_ip(req) == "198.51.100.8"

    def test_xff_with_depth_1_two_entries(self, settings):
        settings.SESSION_ARMOR_TRUSTED_PROXY_DEPTH = 1
        settings.SESSION_ARMOR_TRUSTED_PROXY_CIDRS = ("127.0.0.0/8",)
        req = FakeRequest(
            {
                "HTTP_X_FORWARDED_FOR": "198.51.100.8",
                "REMOTE_ADDR": "127.0.0.1",
            }
        )
        assert get_client_ip(req) == "198.51.100.8"

    def test_xff_too_short_for_depth(self, settings):
        settings.SESSION_ARMOR_TRUSTED_PROXY_DEPTH = 1
        settings.SESSION_ARMOR_TRUSTED_PROXY_CIDRS = ("127.0.0.0/8",)
        req = FakeRequest(
            {
                "HTTP_X_FORWARDED_FOR": "not-an-ip",
                "REMOTE_ADDR": "127.0.0.1",
            }
        )
        assert get_client_ip(req) == ""

    def test_no_xff_no_remote(self, settings):
        settings.SESSION_ARMOR_TRUSTED_PROXY_DEPTH = 0
        req = FakeRequest({})
        assert get_client_ip(req) == ""

    def test_ipv4_mapped_addresses_use_the_ipv4_form(self, settings):
        # Dual-stack sockets report IPv4 peers as "::ffff:a.b.c.d".
        settings.SESSION_ARMOR_TRUSTED_PROXY_DEPTH = 0
        assert get_client_ip(FakeRequest({"REMOTE_ADDR": "::ffff:198.51.100.9"})) == "198.51.100.9"
        settings.SESSION_ARMOR_TRUSTED_PROXY_DEPTH = 1
        for cidrs in (("10.0.0.0/8",), ("::ffff:10.0.0.0/104",)):
            settings.SESSION_ARMOR_TRUSTED_PROXY_CIDRS = cidrs
            req = FakeRequest(
                {
                    "HTTP_X_FORWARDED_FOR": "::ffff:198.51.100.9",
                    "REMOTE_ADDR": "::ffff:10.0.0.5",
                }
            )
            assert get_client_ip(req) == "198.51.100.9"

    def test_ipv4_mapped_catch_all_cidr_is_rejected(self, settings):
        settings.SESSION_ARMOR_TRUSTED_PROXY_DEPTH = 1
        settings.SESSION_ARMOR_TRUSTED_PROXY_CIDRS = ("::ffff:0:0/96",)
        req = FakeRequest({"HTTP_X_FORWARDED_FOR": "198.51.100.9", "REMOTE_ADDR": "10.0.0.5"})
        with pytest.raises(SessionConfigurationError, match="catch-all"):
            get_client_ip(req)

    def test_entries_left_of_the_client_are_ignored(self, settings):
        # They are client-controlled (or added by client-side proxies) and never used.
        settings.SESSION_ARMOR_TRUSTED_PROXY_DEPTH = 2
        settings.SESSION_ARMOR_TRUSTED_PROXY_CIDRS = ("10.0.0.0/8",)
        for junk in ("unknown", "_hidden", "", "198.51.100.66:x"):
            req = FakeRequest(
                {
                    "HTTP_X_FORWARDED_FOR": f"{junk}, 198.51.100.9, 10.0.0.7",
                    "REMOTE_ADDR": "10.0.0.5",
                }
            )
            assert get_client_ip(req) == "198.51.100.9"
        # The client entry and every trusted hop must still be valid.
        for xff in ("unknown, 10.0.0.7", "198.51.100.9, unknown", "10.0.0.7"):
            req = FakeRequest({"HTTP_X_FORWARDED_FOR": xff, "REMOTE_ADDR": "10.0.0.5"})
            assert get_client_ip(req) == ""

    @pytest.mark.parametrize(
        ("entry", "expected"),
        [
            ("198.51.100.9:52311", "198.51.100.9"),
            ("[2001:db8::7]:443", "2001:db8::7"),
            ("[2001:db8::7]", "2001:db8::7"),
            ("2001:db8::7", "2001:db8::7"),
            ("198.51.100.9:", ""),
            ("198.51.100.9:http", ""),
            ("[2001:db8::7]:", ""),
            ("[2001:db8::7", ""),
        ],
    )
    def test_forwarded_entries_may_carry_a_port(self, settings, entry, expected):
        settings.SESSION_ARMOR_TRUSTED_PROXY_DEPTH = 1
        settings.SESSION_ARMOR_TRUSTED_PROXY_CIDRS = ("10.0.0.0/8",)
        req = FakeRequest({"HTTP_X_FORWARDED_FOR": entry, "REMOTE_ADDR": "10.0.0.5"})
        assert get_client_ip(req) == expected

    def test_socket_peer_never_carries_a_port(self, settings):
        settings.SESSION_ARMOR_TRUSTED_PROXY_DEPTH = 0
        assert get_client_ip(FakeRequest({"REMOTE_ADDR": "198.51.100.9:52311"})) == ""

    def test_docstring_examples_match_behaviour(self, settings):
        examples = []
        depth = None
        for line in get_client_ip.__doc__.splitlines():
            found = re.search(r"DEPTH = (\d+)", line)
            depth = int(found.group(1)) if found else depth
            example = re.search(r'X-Forwarded-For: (.+?)\s+-> "([^"]*)"', line)
            if example:
                examples.append((depth, example.group(1), example.group(2)))
        assert len(examples) >= 5
        settings.SESSION_ARMOR_TRUSTED_PROXY_CIDRS = ("10.0.0.0/8",)
        for depth, forwarded, expected in examples:
            settings.SESSION_ARMOR_TRUSTED_PROXY_DEPTH = depth
            req = FakeRequest({"HTTP_X_FORWARDED_FOR": forwarded, "REMOTE_ADDR": "10.0.0.5"})
            assert get_client_ip(req) == expected, (depth, forwarded)

    def test_default_depth_is_secure(self, settings):
        # The default ignores client-controlled forwarding headers.
        del settings.SESSION_ARMOR_TRUSTED_PROXY_DEPTH
        req = FakeRequest(
            {
                "HTTP_X_FORWARDED_FOR": "spoofed",
                "REMOTE_ADDR": "127.0.0.1",
            }
        )
        assert get_client_ip(req) == "127.0.0.1"


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
        assert sanitize_for_log("\x1b[31mred\x1b[0m") == "red"

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
        assert path_is_exempt("/health", ("/health",)) is True

    def test_subpath_with_trailing_slash_prefix(self):
        assert path_is_exempt("/health/live", ("/health/",)) is True

    def test_subpath_without_trailing_slash_prefix(self):
        assert path_is_exempt("/health/live", ("/health",)) is True

    def test_sibling_prefix_not_exempt(self):
        # The key hardening: a shared string prefix must not leak exemption.
        assert path_is_exempt("/health-internal", ("/health",)) is False

    def test_no_prefixes(self):
        assert path_is_exempt("/anything", ()) is False

    def test_multiple_prefixes(self):
        prefixes = ("/static/", "/health")
        assert path_is_exempt("/static/app.css", prefixes) is True
        assert path_is_exempt("/health/ping", prefixes) is True
        assert path_is_exempt("/admin", prefixes) is False

    def test_root_prefix_exempts_only_the_root_path(self):
        # As a segment prefix "/" would silently exempt every path.
        assert path_is_exempt("/", ("/",)) is True
        assert path_is_exempt("/admin/", ("/",)) is False
        assert path_is_exempt("/account/delete/", ("/", "/static/")) is False
        assert path_is_exempt("/static/app.css", ("/", "/static/")) is True
