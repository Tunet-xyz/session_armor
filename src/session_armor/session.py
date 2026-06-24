"""
SessionSecurityMiddleware — defense-grade session protection.

Enforces:
- Client fingerprint binding (IP + User-Agent hash)
- Absolute session timeout (force re-auth after N hours)
- Idle session timeout (force re-auth after inactivity)
- JWT claim drift detection (critical claims must not change mid-session)

All behavior is customizable via hooks so different auth systems
(Auth0, WorkOS, Django allauth, etc.) can plug in seamlessly.

References:
    NIST SP 800-53 AC-12 (Session Termination)
    NIST SP 800-53 SC-23 (Session Authenticity)
    OWASP Session Management Cheat Sheet

Hooks (override in subclass)::

    get_fingerprint_parts(request) → list[str]
    get_critical_claims(user)      → list[str]
    get_login_url(request)         → str
    on_violation(request, reason)  → HttpResponse | None
    on_timeout(request, kind)      → None
    on_session_init(request)       → None

Usage::

    # Generic (works with any Django auth)
    MIDDLEWARE = [
        ...
        'session_armor.session.SessionSecurityMiddleware',
        ...
    ]

    # Customized
    class MySessionSecurity(SessionSecurityMiddleware):
        def get_critical_claims(self, user):
            return [user.sub, user.tenant_id]

        def get_login_url(self, request):
            return reverse('my_login')
"""

import hashlib
import logging
import time

from django.conf import settings
from django.shortcuts import redirect

from .utils import get_client_ip, is_authenticated, path_is_exempt

logger = logging.getLogger('session_armor.session')


class SessionSecurityMiddleware:
    """
    Session binding, timeouts, and anomaly detection.

    Must run **after** your authentication middleware (needs ``request.user``).

    Settings (read from Django settings with secure defaults):

        SESSION_ABSOLUTE_TIMEOUT    int — seconds (default 28800 / 8 h)
        SESSION_IDLE_TIMEOUT        int — seconds (default 1800 / 30 min)
        SESSION_BIND_IP             bool (default True)
        SESSION_BIND_USER_AGENT     bool (default True)
        SESSION_DETECT_CLAIM_DRIFT  bool (default True)

    Session keys (all prefixed ``_ss_``):

        _ss_fingerprint   Client fingerprint hash
        _ss_auth_time     Absolute session start (epoch)
        _ss_last_active   Last activity timestamp (epoch)
        _ss_claims_hash   Hash of critical JWT claims
    """

    # ── Configuration ────────────────────────────────────────────────────
    exempt_paths: tuple[str, ...] = ()

    # Minimum seconds between ``_ss_last_active`` writes. ``0`` (default)
    # updates the timestamp on every request — preserving the original
    # behavior. Raise it (e.g. to 60) to cut session-store write
    # amplification on busy sessions; idle-timeout granularity then coarsens
    # to roughly this value, which is harmless as long as it stays well
    # below ``SESSION_IDLE_TIMEOUT``.
    last_active_resolution: int = 0

    # ── Django middleware protocol ────────────────────────────────────────

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        if self._is_exempt(request):
            return self.get_response(request)

        if not is_authenticated(request):
            return self.get_response(request)

        now = time.time()
        user = request.user

        # ── Binding check ──
        violation = self._check_binding(request)
        if violation:
            logger.warning(
                "Session binding violation (%s) for user %s, path=%s",
                violation, getattr(user, 'sub', '?'), request.path,
            )
            return self._terminate(request, reason=violation)

        # ── Absolute timeout ──
        auth_time = request.session.get('_ss_auth_time')
        timeout = getattr(settings, 'SESSION_ABSOLUTE_TIMEOUT', 28800)
        if auth_time and (now - auth_time) > timeout:
            logger.info("Absolute timeout for user %s", getattr(user, 'sub', '?'))
            self.on_timeout(request, 'absolute')
            return self._terminate(request, reason='absolute_timeout')

        # ── Idle timeout ──
        last_active = request.session.get('_ss_last_active')
        idle_timeout = getattr(settings, 'SESSION_IDLE_TIMEOUT', 1800)
        if last_active and (now - last_active) > idle_timeout:
            logger.info("Idle timeout for user %s", getattr(user, 'sub', '?'))
            self.on_timeout(request, 'idle')
            return self._terminate(request, reason='idle_timeout')

        # ── Claim drift ──
        if getattr(settings, 'SESSION_DETECT_CLAIM_DRIFT', True):
            drift = self._check_claim_drift(request)
            if drift:
                logger.warning(
                    "JWT claim drift for user %s: %s",
                    getattr(user, 'sub', '?'), drift,
                )
                return self._terminate(request, reason='claim_drift')

        # ── Initialize on first authenticated request ──
        if '_ss_auth_time' not in request.session:
            self._init_session(request, now)
            self.on_session_init(request)

        # ── Update last-active (throttled to limit session-store writes) ──
        prev_active = request.session.get('_ss_last_active', 0)
        if (now - prev_active) >= self.last_active_resolution:
            request.session['_ss_last_active'] = now

        return self.get_response(request)

    # ── HOOKS (override in subclass) ─────────────────────────────────────

    def get_fingerprint_parts(self, request) -> list[str]:
        """
        Return the parts that make up the client fingerprint.

        Override to add custom binding factors (client certs, device ID, etc.).
        Each part is joined with ``|`` and SHA-256 hashed.
        """
        parts = []
        if getattr(settings, 'SESSION_BIND_IP', True):
            parts.append(get_client_ip(request))
        if getattr(settings, 'SESSION_BIND_USER_AGENT', True):
            parts.append(request.META.get('HTTP_USER_AGENT', ''))
        return parts

    def get_critical_claims(self, user) -> list[str]:
        """
        Return claim values that must not change mid-session.

        Override to match your auth system's user model. The values are
        hashed together; if the hash changes, the session is terminated.

        Default extracts ``sub`` and ``email`` (works for most OIDC setups).
        """
        return [
            getattr(user, 'sub', '') or '',
            getattr(user, 'email', '') or '',
        ]

    def get_login_url(self, request) -> str:
        """
        Return the URL to redirect to when a session is terminated.

        Override to implement platform-specific or tenant-specific routing.
        Default uses Django's ``LOGIN_URL`` setting.
        """
        return getattr(settings, 'LOGIN_URL', '/')

    def on_violation(self, request, reason: str):
        """
        Called on security violation, before session flush.

        Return an ``HttpResponse`` to override the default redirect.
        Return ``None`` to use the default behavior (flush → login redirect).
        """
        return None

    def on_timeout(self, request, kind: str) -> None:
        """
        Called on absolute or idle timeout, before session flush.

        ``kind`` is ``'absolute'`` or ``'idle'``.
        Use for logging, metrics, or pre-flush cleanup.
        """
        pass

    def on_session_init(self, request) -> None:
        """
        Called when session security metadata is initialized for a new session.

        Use to set additional session values at auth time.
        """
        pass

    # ── INTERNALS ────────────────────────────────────────────────────────

    def _check_binding(self, request) -> str | None:
        stored = request.session.get('_ss_fingerprint')
        if not stored:
            return None  # First request — will be initialized

        parts = self.get_fingerprint_parts(request)
        current = hashlib.sha256('|'.join(parts).encode('utf-8')).hexdigest()
        if current != stored:
            return 'fingerprint_mismatch'
        return None

    def _check_claim_drift(self, request) -> str | None:
        stored = request.session.get('_ss_claims_hash')
        if not stored:
            return None

        current = self._hash_claims(request.user)
        if current != stored:
            return 'critical_claims_changed'
        return None

    def _hash_claims(self, user) -> str:
        parts = self.get_critical_claims(user)
        raw = '|'.join(str(p) for p in parts)
        return hashlib.sha256(raw.encode('utf-8')).hexdigest()

    def _init_session(self, request, now: float):
        # Rotate session ID to prevent fixation attacks (OWASP A7)
        request.session.cycle_key()

        parts = self.get_fingerprint_parts(request)
        request.session['_ss_fingerprint'] = hashlib.sha256(
            '|'.join(parts).encode('utf-8')
        ).hexdigest()
        request.session['_ss_auth_time'] = now
        request.session['_ss_last_active'] = now
        request.session['_ss_claims_hash'] = self._hash_claims(request.user)
        logger.debug(
            "Session security initialized for user %s",
            getattr(request.user, 'sub', '?'),
        )

    def _terminate(self, request, reason: str):
        # Get login URL BEFORE flushing (user info may be needed)
        custom = self.on_violation(request, reason)
        login_url = self.get_login_url(request)

        request.session.flush()

        if custom is not None:
            return custom
        return redirect(login_url)

    def _is_exempt(self, request) -> bool:
        return path_is_exempt(request.path, self.exempt_paths)
