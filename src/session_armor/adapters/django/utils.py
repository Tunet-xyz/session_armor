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
# Every purpose the session middleware derives a MAC subkey for starts with this.
_KEY_DERIVATION_NAMESPACE = "session-armor:"


def hash_value(value: str, length: int = 0) -> str:
    """SHA-256 hash of a string. Optionally truncate to ``length`` chars.

    Note: this is an *unkeyed* digest. Do not use it to pseudonymize
    low-entropy values (such as IP addresses), which are trivially
    recoverable from an unsalted hash — use :func:`hash_ip` instead.
    """
    h = hashlib.sha256(value.encode("utf-8")).hexdigest()
    return h[:length] if length else h


def _secret_bytes(value: object, name: str) -> bytes:
    """Encode a configured secret. Only text and bytes are keys: ``bytes()``
    would turn an integer into a public all-zero key."""
    if isinstance(value, str):
        encoded = value.encode("utf-8")
    elif isinstance(value, bytes | bytearray):
        encoded = bytes(value)
    else:
        raise SessionConfigurationError(f"{name} must be bytes or a string.")
    if len(encoded) < 16:
        raise SessionConfigurationError(f"{name} must contain at least 16 bytes.")
    return encoded


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
    return _secret_bytes(pepper, "SESSION_ARMOR_AUDIT_PEPPER (or SECRET_KEY)")


def hash_ip(ip: str, length: int = 16) -> str:
    """
    Keyed (HMAC-SHA256) pseudonymous hash of an IP address.

    An IP address has very low entropy (the entire IPv4 space is ~4.3
    billion values), so an *unsalted* SHA-256 is reversible in seconds with
    a precomputed table. Keying the digest with a secret pepper makes the
    mapping non-reversible without the key, while staying deterministic so
    the same IP yields a stable token for correlation across log lines.

    Truncated to ``length`` hex chars (default 16); pass ``length=0`` for
    the full digest. Values starting with ``session-armor:`` are hashed
    under a separate derived key: that namespace is reserved for key
    derivation.
    """
    if not isinstance(ip, str):
        raise TypeError("ip must be a string.")
    if isinstance(length, bool) or not isinstance(length, int) or not 0 <= length <= 64:
        raise ValueError("length must be an integer between 0 and 64.")
    pepper = _audit_pepper()
    if ip.startswith(_KEY_DERIVATION_NAMESPACE):
        # The session middleware derives its MAC subkeys as HMAC(key, purpose)
        # with purposes in this namespace, and the pepper and the state key
        # both default to SECRET_KEY. Such a value is hashed under a separate
        # key, so no digest can be a subkey; every other digest is unchanged.
        pepper = hmac.digest(pepper, b"session-armor:audit:v1", hashlib.sha256)
    digest = hmac.new(pepper, ip.encode("utf-8"), hashlib.sha256).hexdigest()
    return digest[:length] if length else digest


def _proxy_network(value: str) -> ipaddress.IPv4Network | ipaddress.IPv6Network:
    network = ipaddress.ip_network(value, strict=False)
    if isinstance(network, ipaddress.IPv6Network) and network.prefixlen >= 96:
        mapped = network.network_address.ipv4_mapped
        if mapped is not None:
            # Compare IPv4-mapped ranges in IPv4 form, like addresses (see _ip).
            return ipaddress.ip_network(f"{mapped}/{network.prefixlen - 96}")
    return network


def _proxy_networks(values: Iterable[str]) -> tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, ...]:
    if isinstance(values, str):
        raise SessionConfigurationError("SESSION_ARMOR_TRUSTED_PROXY_CIDRS must be an iterable.")
    try:
        networks = tuple(_proxy_network(value) for value in values)
    except (TypeError, ValueError) as error:
        raise SessionConfigurationError(
            "SESSION_ARMOR_TRUSTED_PROXY_CIDRS contains an invalid network."
        ) from error
    if any(network.prefixlen == 0 for network in networks):
        raise SessionConfigurationError("A catch-all trusted proxy CIDR is not permitted.")
    return networks


def _ip(
    value: object, *, allow_port: bool = False
) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    if not isinstance(value, str) or not value:
        return None
    text = value.strip()
    if allow_port:
        # Some proxies append the port: "a.b.c.d:port" or "[v6]:port".
        if text.startswith("["):
            text, bracket, port = text[1:].partition("]")
            if not bracket or (port and not (port[0] == ":" and _is_port(port[1:]))):
                return None
        elif text.count(":") == 1:
            text, _, port = text.partition(":")
            if not _is_port(port):
                return None
    try:
        address = ipaddress.ip_address(text)
    except ValueError:
        return None
    # A dual-stack socket reports IPv4 peers as "::ffff:a.b.c.d". Use the IPv4
    # form so IPv4 CIDRs match it and the result does not depend on how the
    # running Python version prints mapped addresses.
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped is not None:
        return address.ipv4_mapped
    return address


def _is_port(value: str) -> bool:
    return value.isascii() and value.isdigit()


def get_client_ip(request) -> str:
    """
    Return the originating client IP, or ``""`` when it cannot be trusted.

    ``SESSION_ARMOR_TRUSTED_PROXY_DEPTH`` (default ``0``) is the number of
    reverse proxies in front of the app. With ``0``, ``X-Forwarded-For`` is
    ignored and ``REMOTE_ADDR`` is returned.

    With a depth of ``N``, the socket peer (``REMOTE_ADDR``) and the ``N - 1``
    rightmost ``X-Forwarded-For`` entries are the trusted hops, and every one
    must fall inside ``SESSION_ARMOR_TRUSTED_PROXY_CIDRS`` (required, or
    :class:`SessionConfigurationError` is raised). The client is the entry
    immediately to their left; entries further left are never read. A request
    without the header is treated as a direct connection and gets
    ``REMOTE_ADDR``. A malformed client entry or hop, too short a chain or an
    untrusted hop returns ``""``, which the session middleware treats as a
    violation. So does a Unix-socket peer, which has no address: override
    ``get_fingerprint_factors()`` or disable IP binding behind one.

    Forwarded entries may carry a port (``a.b.c.d:port`` or ``[v6]:port``).
    IPv4-mapped IPv6 addresses are returned, and matched, in IPv4 form.

    Examples with ``CIDRS = ("10.0.0.0/8",)`` and ``REMOTE_ADDR = "10.0.0.5"``.
    The default ``DEPTH = 0`` ignores the header::

        X-Forwarded-For: 203.0.113.7                 -> "10.0.0.5"

    ``DEPTH = 1`` trusts only the socket peer::

        X-Forwarded-For: 198.51.100.66, 203.0.113.7  -> "203.0.113.7"
        X-Forwarded-For: 203.0.113.7                 -> "203.0.113.7"
        X-Forwarded-For: unknown, 203.0.113.7:51234  -> "203.0.113.7"
        X-Forwarded-For: not-an-ip                   -> ""

    ``DEPTH = 2`` also needs the rightmost entry to be a trusted proxy::

        X-Forwarded-For: 198.51.100.66, 203.0.113.7, 10.0.0.7  -> "203.0.113.7"
        X-Forwarded-For: 203.0.113.7, 198.51.100.66             -> ""
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
    entries = forwarded.split(",")
    if remote is None or len(entries) < depth:
        return ""
    # Only the client entry and the trusted hops are read. Entries to their left
    # are client-controlled and never used, so they cannot invalidate the chain.
    chain = [_ip(part, allow_port=True) for part in entries[-depth:]]
    if any(part is None for part in chain):
        return ""
    addresses = [part for part in chain if part is not None] + [remote]

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
    For the same reason ``/`` exempts only the root path, not every path.
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
        if prefix == "/":
            continue
        boundary = prefix if prefix.endswith("/") else prefix + "/"
        if path.startswith(boundary):
            return True
    return False
