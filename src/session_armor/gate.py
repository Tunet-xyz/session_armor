"""
GateMiddleware — configurable conditional gate for Django middleware stacks.

A gate checks a condition on each request (with session caching) and either
passes the request through or rejects it. Subclass this to build:

- Compliance gates (legal document acceptance)
- Onboarding gates (step completion)
- Feature gates (entitlement / feature-flag checks)
- Maintenance gates (scheduled downtime)
- Any "must satisfy X before proceeding" pattern

Follows the before/after hooks pattern for maximum customizability::

    class ComplianceGate(GateMiddleware):
        gate_id = 'compliance'
        cache_ttl_setting = 'COMPLIANCE_CACHE_TTL'
        default_cache_ttl = 3600

        def check(self, request) -> bool:
            return user_accepted_terms(request)

        def on_reject(self, request):
            return redirect('/accept-terms/')

Hooks execute in this order::

    before_check  →  check  →  after_check  →  on_pass / on_reject
                       ↓ (exception)
                    on_error
"""

import logging
import time

from django.conf import settings

from .utils import is_authenticated

logger = logging.getLogger('session_armor.gate')


class GateMiddleware:
    """
    Base class for conditional gate middleware with session caching and hooks.

    Configuration (set as class attributes on your subclass):

        gate_id             Unique ID used for session-key namespacing.
        cache_ttl_setting   Name of a Django setting that holds the TTL override.
        default_cache_ttl   Fallback TTL in seconds (default 300).
        exempt_paths        Tuple of path prefixes that bypass this gate.
        requires_auth       Only check authenticated requests (default True).
        fail_open           Pass through on errors (default False).
        recheck_after_pass  Re-run check() after the TTL even when the last
                            result passed (default True). Set False for
                            "check once" gates (onboarding, compliance):
                            a passing result then stays cached for the whole
                            session, until ``invalidate()`` is called or the
                            state version changes.

    Hooks (override any combination in your subclass):

        before_check(request) → bool | None
        check(request) → bool                       **required**
        after_check(request, passed: bool)
        on_reject(request) → HttpResponse
        on_pass(request)
        on_error(request, error) → bool
        get_rejection_context(request) → dict
        get_state_version(request) → str | None
    """

    # ── Configuration (override in subclass) ─────────────────────────────
    gate_id: str = ''
    cache_ttl_setting: str = ''
    default_cache_ttl: int = 300
    exempt_paths: tuple[str, ...] = ()
    requires_auth: bool = True
    fail_open: bool = False
    recheck_after_pass: bool = True

    # ── Django middleware protocol ────────────────────────────────────────

    def __init__(self, get_response):
        self.get_response = get_response
        if not self.gate_id:
            self.gate_id = self.__class__.__name__.lower()

    def __call__(self, request):
        # Exempt paths bypass the gate entirely
        if self._is_exempt(request):
            return self.get_response(request)

        # Auth guard
        if self.requires_auth and not is_authenticated(request):
            return self.get_response(request)

        # ── before_check hook ──
        should_check = self.before_check(request)
        if should_check is False:
            return self.get_response(request)

        now = time.time()
        prefix = self._cache_prefix
        ttl = self._get_cache_ttl()
        version = self.get_state_version(request)

        # ── Session-cache fast path ──
        if f'{prefix}_result' in request.session and self._cache_valid(
            request, now, ttl, version,
        ):
            passed = request.session[f'{prefix}_result']
            if not passed:
                return self.on_reject(request)
            self.on_pass(request)
            return self.get_response(request)

        # ── Run the check ──
        try:
            passed = self.check(request)
        except Exception as exc:
            passed = self.on_error(request, exc)

        # ── after_check hook ──
        self.after_check(request, passed)

        # ── Cache the result ──
        request.session[f'{prefix}_at'] = now
        request.session[f'{prefix}_result'] = passed
        if version is not None:
            request.session[f'{prefix}_version'] = version

        if not passed:
            ctx = self.get_rejection_context(request)
            if ctx:
                request.session[f'{prefix}_context'] = ctx
            return self.on_reject(request)

        self.on_pass(request)
        return self.get_response(request)

    # ── HOOKS (override in subclass) ─────────────────────────────────────

    def before_check(self, request) -> bool | None:
        """Called before ``check()``. Return ``False`` to skip the gate."""
        return True

    def check(self, request) -> bool:
        """
        The main condition.

        Return ``True`` to let the request through, ``False`` to reject it.
        **Must** be overridden in every subclass.
        """
        raise NotImplementedError(
            f"{self.__class__.__name__} must implement check()"
        )

    def after_check(self, request, passed: bool) -> None:
        """Called after ``check()`` with the result. Logging, metrics, side effects."""
        pass

    def on_reject(self, request):
        """Called when the gate rejects. Return an ``HttpResponse``."""
        from django.http import HttpResponseForbidden
        return HttpResponseForbidden("Access denied")

    def on_pass(self, request) -> None:
        """Called when the gate passes. Side effects only (no return value)."""
        pass

    def on_error(self, request, error: Exception) -> bool:
        """
        Called when ``check()`` raises an exception.

        Return ``True`` to pass through (fail-open), ``False`` to reject.
        """
        logger.error(
            "%s check error: %s", self.__class__.__name__, error,
            exc_info=True,
        )
        return self.fail_open

    def get_rejection_context(self, request) -> dict:
        """
        Return extra data to store in session when the gate rejects.

        Accessible later via ``cls.get_context(request)`` from views.
        """
        return {}

    def get_state_version(self, request) -> str | None:
        """
        Return a cheap version stamp for the state behind this gate.

        Return ``None`` (the default) to disable version tracking.

        When a value is returned, the cached gate result is only reused
        while the version matches the one stored at check time. Back the
        stamp with something cheap and shared (e.g. a Django cache key
        bumped whenever an admin publishes a new document version or adds
        an onboarding step) — this propagates invalidation to every active
        session without per-request database hits.
        """
        return None

    # ── CLASS UTILITIES (call from views) ────────────────────────────────

    @classmethod
    def invalidate(cls, request):
        """
        Clear cached gate state, forcing a re-check on the next request.

        Call this from views when the underlying condition changes
        (e.g. user just accepted terms, completed an onboarding step).
        """
        prefix = f'_gate_{cls.gate_id or cls.__name__.lower()}'
        for suffix in ('_at', '_result', '_context', '_version'):
            request.session.pop(f'{prefix}{suffix}', None)

    @classmethod
    def get_context(cls, request) -> dict:
        """Read the cached rejection context from the session."""
        prefix = f'_gate_{cls.gate_id or cls.__name__.lower()}'
        return request.session.get(f'{prefix}_context', {})

    # ── INTERNALS ────────────────────────────────────────────────────────

    @property
    def _cache_prefix(self) -> str:
        return f'_gate_{self.gate_id}'

    def _cache_valid(self, request, now: float, ttl: int, version) -> bool:
        """Decide whether the session-cached result can be reused."""
        prefix = self._cache_prefix

        # Version mismatch always invalidates (state changed behind the gate)
        if version is not None and request.session.get(f'{prefix}_version') != version:
            return False

        passed = request.session[f'{prefix}_result']
        if passed and not self.recheck_after_pass:
            return True  # Sticky pass: no TTL re-check once satisfied

        checked_at = request.session.get(f'{prefix}_at', 0)
        return (now - checked_at) < ttl

    def _get_cache_ttl(self) -> int:
        if self.cache_ttl_setting:
            return getattr(settings, self.cache_ttl_setting, self.default_cache_ttl)
        return self.default_cache_ttl

    def _is_exempt(self, request) -> bool:
        return any(request.path.startswith(p) for p in self.exempt_paths)
