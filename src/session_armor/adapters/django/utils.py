"""
Shared utilities for SessionArmor middleware.
"""

import hashlib
import hmac
import ipaddress
import re
from collections.abc import Iterable

from django.conf import settings

from ...exceptions import SessionConfigurationError

# Characters that can corrupt structured log parsing (newlines, ANSI escapes,
# null bytes, control characters).
_LOG_UNSAFE_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f\r\n]")
_ANSI_ESCAPE_RE = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]")


def hash_value(value: str, length: int = 0) -> str:
    """SHA-256 hash of a string. Optionally truncate to ``length`` chars.

    Note: this is an *unkeyed* digest. Do not use it to pseudonymize
    low-entropy values (such as IP addresses), which are trivially
    recoverable from an unsalted hash — use :func:`hash_ip` instead.
    """
    h = hashlib.sha256(value.encode("utf-8")).hexdigest()
    return h[:length] if length else h


def _audit_pepper() -> bytes:
    """
    Return the secret key used to make audit pseudonymization non-reversible.

    Prefers ``SESSION_ARMOR_AUDIT_PEPPER`` and falls back to Django's
    ``SECRET_KEY`` (always present in a configured project). A dedicated
    pepper lets operators rotate it — or share it across services for
    cross-log correlation — independently of ``SECRET_KEY``.
    """
    pepper = getattr(settings, "SESSION_ARMOR_AUDIT_PEPPER", "") or getattr(
        settings, "SECRET_KEY", ""
    )
    encoded = pepper.encode("utf-8") if isinstance(pepper, str) else bytes(pepper)
    if len(encoded) < 16:
        raise SessionConfigurationError(
            "SESSION_ARMOR_AUDIT_PEPPER (or SECRET_KEY) must contain at least 16 bytes."
        )
    return encoded


def hash_ip(ip: str, length: int = 16) -> str:
    """
    Keyed (HMAC-SHA256) pseudonymous hash of an IP address.

    An IP address has very low entropy (the entire IPv4 space is ~4.3
    billion values), so an *unsalted* SHA-256 is reversible in seconds with
    a precomputed table. Keying the digest with a secret pepper makes the
    mapping non-reversible without the key, while staying deterministic so
    the same IP yields a stable token for correlation across log lines.

    Truncated to ``length`` hex chars (default 16); pass ``length=0`` for
    the full digest.
    """
    if not isinstance(ip, str):
        raise TypeError("ip must be a string.")
    if isinstance(length, bool) or not isinstance(length, int) or not 0 <= length <= 64:
        raise ValueError("length must be an integer between 0 and 64.")
    digest = hmac.new(_audit_pepper(), ip.encode("utf-8"), hashlib.sha256).hexdigest()
    return digest[:length] if length else digest


def _proxy_networks(values: Iterable[str]) -> tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, ...]:
    if isinstance(values, str):
        raise SessionConfigurationError("SESSION_ARMOR_TRUSTED_PROXY_CIDRS must be an iterable.")
    try:
        networks = tuple(ipaddress.ip_network(value, strict=False) for value in values)
    except (TypeError, ValueError) as error:
        raise SessionConfigurationError(
            "SESSION_ARMOR_TRUSTED_PROXY_CIDRS contains an invalid network."
        ) from error
    if any(network.prefixlen == 0 for network in networks):
        raise SessionConfigurationError("A catch-all trusted proxy CIDR is not permitted.")
    return networks


def _ip(value: object) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    if not isinstance(value, str) or not value:
        return None
    try:
        return ipaddress.ip_address(value.strip())
    except ValueError:
        return None


def get_client_ip(request) -> str:
    """
    Extract the originating client IP with proxy-depth awareness.

    ``SESSION_ARMOR_TRUSTED_PROXY_DEPTH`` is the number of reverse proxies
    you operate in front of the app (default ``1``). Only that many
    rightmost ``X-Forwarded-For`` entries are trusted; the client IP is the
    entry just before the trusted proxies.

    If the header has fewer entries than the proxy depth (i.e. the request
    didn't traverse enough proxies), we fall back to ``REMOTE_ADDR`` to
    avoid trusting a spoofed header.

    Setting the depth to ``0`` opts into the legacy, **insecure** behavior
    of trusting the leftmost (fully client-controlled) entry. Only do this
    if you have an upstream that overwrites ``X-Forwarded-For`` and you know
    what you're doing.

    Examples with ``SESSION_ARMOR_TRUSTED_PROXY_DEPTH = 1``::

        X-Forwarded-For: spoofed, real, proxy1
        → returns "real"

        X-Forwarded-For: real, proxy1
        → returns "real"

        X-Forwarded-For: spoofed_only
        → returns REMOTE_ADDR (not enough hops)
    """
    depth = getattr(settings, "SESSION_ARMOR_TRUSTED_PROXY_DEPTH", 0)
    if isinstance(depth, bool) or not isinstance(depth, int) or not 0 <= depth <= 16:
        raise SessionConfigurationError(
            "SESSION_ARMOR_TRUSTED_PROXY_DEPTH must be an integer between 0 and 16."
        )
    forwarded = request.META.get("HTTP_X_FORWARDED_FOR", "")
    remote = _ip(request.META.get("REMOTE_ADDR", ""))

    # Secure default: with no trusted proxy topology configured, forwarded
    # headers are ignored completely.
    if depth == 0 or not forwarded:
        return "" if remote is None else str(remote)

    networks = _proxy_networks(getattr(settings, "SESSION_ARMOR_TRUSTED_PROXY_CIDRS", ()))
    if not networks:
        raise SessionConfigurationError(
            "Trusted proxy CIDRs are required when SESSION_ARMOR_TRUSTED_PROXY_DEPTH is non-zero."
        )
    chain = [_ip(part) for part in forwarded.split(",")]
    if remote is None or any(part is None for part in chain):
        return ""
    addresses = [part for part in chain if part is not None] + [remote]
    if len(addresses) <= depth:
        return ""

    trusted_hops = addresses[-depth:]
    if any(not any(address in network for network in networks) for address in trusted_hops):
        return ""

    return str(addresses[-depth - 1])


def get_client_fingerprint(request, parts: list[str] | None = None) -> str:
    """
    Build a privacy-preserving fingerprint from client connection properties.

    By default hashes IP + User-Agent. Pass *parts* to override.
    """
    if parts is None:
        parts = [
            get_client_ip(request),
            request.META.get("HTTP_USER_AGENT", ""),
        ]
    raw = "|".join(parts)
    return hash_value(raw)


def is_authenticated(request) -> bool:
    """Check whether the request has an authenticated user."""
    user = getattr(request, "user", None)
    return bool(user and getattr(user, "is_authenticated", False))


def sanitize_for_log(value: str, max_length: int = 200) -> str:
    """
    Sanitize a user-controlled string for safe inclusion in log entries.

    Strips control characters, ANSI escape sequences, null bytes, and
    truncates to ``max_length`` to prevent log injection / log flooding.
    """
    if not isinstance(value, str):
        raise TypeError("log values must be strings.")
    if isinstance(max_length, bool) or not isinstance(max_length, int) or max_length < 0:
        raise ValueError("max_length must be a non-negative integer.")
    clean = _ANSI_ESCAPE_RE.sub("", value)
    clean = _LOG_UNSAFE_RE.sub("", clean)
    return clean[:max_length]


def path_is_exempt(path: str, prefixes: tuple[str, ...]) -> bool:
    """
    Return ``True`` if *path* falls under any exempt *prefix*.

    Matching respects path-segment boundaries: a prefix matches the exact
    path or a path immediately followed by ``/``. So ``/health`` exempts
    ``/health`` and ``/health/live`` but **not** ``/health-internal``.

    Plain ``str.startswith`` would let ``/health`` accidentally exempt
    sibling paths like ``/health-internal`` that merely share a string
    prefix — a classic way to widen an exemption further than intended.
    """
    if not isinstance(path, str) or not path.startswith("/"):
        return False
    if not isinstance(prefixes, tuple):
        raise SessionConfigurationError("exempt_paths must be a tuple.")
    for prefix in prefixes:
        if (
            not isinstance(prefix, str)
            or not prefix.startswith("/")
            or "?" in prefix
            or "#" in prefix
        ):
            raise SessionConfigurationError(
                "Every exempt path must be an absolute URL path without a query or fragment."
            )
        if path == prefix:
            return True
        boundary = prefix if prefix.endswith("/") else prefix + "/"
        if path.startswith(boundary):
            return True
    return False
