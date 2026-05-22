"""
Shared utilities for SessionArmor middleware.
"""

import hashlib
import re

from django.conf import settings

# Characters that can corrupt structured log parsing (newlines, ANSI escapes,
# null bytes, control characters).
_LOG_UNSAFE_RE = re.compile(r'[\x00-\x08\x0b\x0c\x0e-\x1f\x7f\x1b\[\]\r\n]')


def hash_value(value: str, length: int = 0) -> str:
    """SHA-256 hash of a string. Optionally truncate to ``length`` chars."""
    h = hashlib.sha256(value.encode('utf-8')).hexdigest()
    return h[:length] if length else h


def get_client_ip(request) -> str:
    """
    Extract the originating client IP with proxy-depth awareness.

    When ``SESSION_ARMOR_TRUSTED_PROXY_DEPTH`` is set in Django settings,
    only that many rightmost ``X-Forwarded-For`` entries are trusted.
    The client IP is the entry just before the trusted proxies.

    If the header has fewer entries than the proxy depth (i.e. the request
    didn't traverse enough proxies), we fall back to ``REMOTE_ADDR`` to
    avoid trusting a spoofed header.

    Examples with ``SESSION_ARMOR_TRUSTED_PROXY_DEPTH = 1``::

        X-Forwarded-For: spoofed, real, proxy1
        → returns "real"

        X-Forwarded-For: real, proxy1
        → returns "real"

        X-Forwarded-For: spoofed_only
        → returns REMOTE_ADDR (not enough hops)
    """
    depth = getattr(settings, 'SESSION_ARMOR_TRUSTED_PROXY_DEPTH', 0)
    forwarded = request.META.get('HTTP_X_FORWARDED_FOR', '')

    if not forwarded:
        return request.META.get('REMOTE_ADDR', '')

    parts = [p.strip() for p in forwarded.split(',')]

    if depth and depth > 0:
        # The client is at index -(depth + 1) from the right.
        # If the header is shorter than depth + 1, it's spoofed — use REMOTE_ADDR.
        client_index = len(parts) - depth - 1
        if client_index < 0:
            return request.META.get('REMOTE_ADDR', '')
        return parts[client_index]

    # No proxy depth configured — legacy behavior (leftmost, less safe).
    return parts[0]


def get_client_fingerprint(request, parts: list[str] | None = None) -> str:
    """
    Build a privacy-preserving fingerprint from client connection properties.

    By default hashes IP + User-Agent. Pass *parts* to override.
    """
    if parts is None:
        parts = [
            get_client_ip(request),
            request.META.get('HTTP_USER_AGENT', ''),
        ]
    raw = '|'.join(parts)
    return hash_value(raw)


def is_authenticated(request) -> bool:
    """Check whether the request has an authenticated user."""
    user = getattr(request, 'user', None)
    return bool(user and getattr(user, 'is_authenticated', False))


def sanitize_for_log(value: str, max_length: int = 200) -> str:
    """
    Sanitize a user-controlled string for safe inclusion in log entries.

    Strips control characters, ANSI escape sequences, null bytes, and
    truncates to ``max_length`` to prevent log injection / log flooding.
    """
    clean = _LOG_UNSAFE_RE.sub('', value)
    return clean[:max_length]
