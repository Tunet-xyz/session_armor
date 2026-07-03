"""
Shared utilities for SessionArmor middleware.
"""

import hashlib
import hmac
import re

from django.conf import settings

# Characters that can corrupt structured log parsing (newlines, ANSI escapes,
# null bytes, control characters).
_LOG_UNSAFE_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f\x1b\[\]\r\n]")


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
    return pepper.encode("utf-8") if isinstance(pepper, str) else bytes(pepper)


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
    digest = hmac.new(_audit_pepper(), ip.encode("utf-8"), hashlib.sha256).hexdigest()
    return digest[:length] if length else digest


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
    depth = getattr(settings, "SESSION_ARMOR_TRUSTED_PROXY_DEPTH", 1)
    forwarded = request.META.get("HTTP_X_FORWARDED_FOR", "")

    if not forwarded:
        return request.META.get("REMOTE_ADDR", "")

    parts = [p.strip() for p in forwarded.split(",")]

    if depth and depth > 0:
        # The client is at index -(depth + 1) from the right.
        # If the header is shorter than depth + 1, it's spoofed — use REMOTE_ADDR.
        client_index = len(parts) - depth - 1
        if client_index < 0:
            return request.META.get("REMOTE_ADDR", "")
        return parts[client_index]

    # depth == 0: explicit opt-in to legacy leftmost (client-controlled, unsafe).
    return parts[0]


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
    clean = _LOG_UNSAFE_RE.sub("", value)
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
    for prefix in prefixes:
        if path == prefix:
            return True
        boundary = prefix if prefix.endswith("/") else prefix + "/"
        if path.startswith(boundary):
            return True
    return False
