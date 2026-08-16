# SessionArmor

[![Tests](https://github.com/Tunet-xyz/session_armor/actions/workflows/tests.yaml/badge.svg)](https://github.com/Tunet-xyz/session_armor/actions/workflows/tests.yaml)
[![PyPI version](https://badge.fury.io/py/SessionArmor.svg)](https://pypi.org/project/SessionArmor/)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![Django 4.2-5.2](https://img.shields.io/badge/django-4.2--5.2-green.svg)](https://www.djangoproject.com/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

**Security-focused Django middleware for session integrity, privacy-aware audit logging, and configurable request gates.**

Part of the [Tunet](https://tunet.xyz/engineering/) ecosystem — alongside [SwapLayer](https://github.com/Tunet-xyz/swap_layer) and [InfraGlyph](https://github.com/Tunet-xyz/infra_glyph). See the [SessionArmor product page](https://tunet.xyz/engineering/session-armor/) for the public capability overview.

---

## What It Does

SessionArmor provides three drop-in Django middleware classes that harden your application's session layer:

| Middleware | Purpose |
|-----------|---------|
| `SessionSecurityMiddleware` | Keyed continuity binding, validated absolute/idle timeouts, claim drift detection, and typed assurance evidence |
| `AuditMiddleware` | Structured, privacy-aware security audit events for authenticated request outcomes |
| `GateMiddleware` | Typed, identity-bound workflow gates with bounded, revocation-aware caching |

All three are **hookable** — override methods to customize behavior without touching internals.

## References

- [NIST SP 800-53 AC-12](https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final) (Session Termination)
- [NIST SP 800-53 SC-23](https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final) (Session Authenticity)
- [NIST SP 800-53 AU-3/AU-12](https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final) (Audit Content/Generation)
- [OWASP Session Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html)

SessionArmor adds controls around an existing Django authentication and session setup; it does not replace HTTPS, secure cookie settings, CSRF protection, authorization, MFA, or incident response. Fingerprint binding is a replay signal rather than proof of device identity and can require tuning for mobile or privacy-network traffic. See the [security model](docs/security-model.md) for deployment assumptions, limitations, and a release checklist.

---

## Installation

```bash
pip install SessionArmor
```

## Quick Start

```python
# settings.py
MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    # ... your auth middleware ...
    'session_armor.session.SessionSecurityMiddleware',
    'session_armor.audit.AuditMiddleware',
    # ... rest of your middleware ...
]

# Optional settings (shown with defaults)
SESSION_ARMOR_ABSOLUTE_TIMEOUT = 28800
SESSION_ARMOR_IDLE_TIMEOUT = 1800
SESSION_ARMOR_BIND_IP = True
SESSION_ARMOR_BIND_USER_AGENT = True
SESSION_ARMOR_DETECT_CLAIM_DRIFT = True
SESSION_ARMOR_REQUIRE_BINDING = True
SESSION_ARMOR_CLOCK_SKEW = 60
SESSION_ARMOR_LAST_ACTIVE_RESOLUTION = 0
SESSION_ARMOR_NO_STORE = True
SESSION_ARMOR_STATE_KEY = SECRET_KEY
SESSION_ARMOR_AUDIT_PEPPER = SECRET_KEY

# Forwarded headers are ignored unless both values are configured.
SESSION_ARMOR_TRUSTED_PROXY_DEPTH = 0
SESSION_ARMOR_TRUSTED_PROXY_CIDRS = ()
```

> **Note on audit IP hashing.** Audit logs pseudonymize the client IP with a
> keyed HMAC-SHA256 so the value can't be reversed from the (low-entropy) IPv4
> space. Set a dedicated `SESSION_ARMOR_AUDIT_PEPPER` to rotate it independently
> of `SECRET_KEY`, or to share it across services for cross-log correlation.
> If unset, it falls back to `SECRET_KEY`.

> **Note on proxy trust.** The secure default (`DEPTH = 0`) ignores
> `X-Forwarded-For`. To use it, configure both the exact number of proxy hops
> and their CIDR ranges. Each trusted hop is checked from the socket peer back
> toward the client; malformed chains and catch-all trusted networks are rejected.

## Building a Gate

```python
from session_armor import GateDecision, GateMiddleware
from django.shortcuts import redirect

class ComplianceGate(GateMiddleware):
    gate_id = 'compliance'
    cache_ttl_setting = 'COMPLIANCE_CACHE_TTL'
    default_cache_ttl = 3600
    requires_trusted_session = True

    def check(self, request) -> GateDecision:
        if user_accepted_current_terms(request):
            return GateDecision.allow('current_terms_accepted')
        return GateDecision.reject('terms_acceptance_required')

    def on_reject(self, request, decision):
        return redirect('/accept-terms/')
```

### "Check once" gates

For gates that should only kick in once (onboarding, compliance), set
`recheck_after_pass = False`: a passing result stays cached in the session
with no TTL re-checks. To push new requirements to already-passed sessions
(a new document version, a new onboarding step), implement
`get_state_version()` against a shared cache key and bump that key on
publish — every active session re-checks exactly once, with no per-request
database hits:

```python
from django.core.cache import cache

class ComplianceGate(GateMiddleware):
    gate_id = 'compliance'
    recheck_after_pass = False  # Pass once, stay passed

    def get_state_version(self, request) -> str | None:
        # Bumped by admin tooling when a new document version is published
        return cache.get(f'compliance_version:{request.user.platform}', '')

    def check(self, request) -> GateDecision:
        return (
            GateDecision.allow('current_terms_accepted')
            if user_accepted_current_terms(request)
            else GateDecision.reject('terms_acceptance_required')
        )
```

> **Sticky passes and revocation.** With `recheck_after_pass = False`, a pass
> is cached until the session ends, `invalidate()` is called, or the state
> version changes — so it is **not** appropriate for authorization/entitlement
> gates where access may be revoked. For those, use a normal TTL gate, drive
> `get_state_version()`, or set `sticky_pass_max_age` (seconds) to cap how long
> a sticky pass may be reused before a forced re-check.

## Customizing Session Security

```python
from session_armor import SessionSecurityMiddleware

class MySessionSecurity(SessionSecurityMiddleware):
    exempt_paths = ('/health/', '/static/')
    last_active_resolution = 60  # only rewrite last-active timestamp every 60s

    def get_critical_claims(self, user):
        # Auth0 / OIDC claims that must not change mid-session
        return [user.sub, user.organization_uuid, user.platform]

    def get_login_url(self, request):
        platform = getattr(request.user, 'platform', '')
        return f'/{platform}/login/' if platform else '/login/'

# After a reviewed server-side claim update, use the public API rather than
# writing SessionArmor's private session keys.
MySessionSecurity(lambda request: request).rebaseline_claims(request)
```

## AccessGate integration

SessionArmor and AccessGate are complementary boundaries. SessionArmor decides
whether the authenticated session is still trustworthy and attaches an immutable
`request.session_assurance` record. AccessGate's Django adapter carries that
record into authorization context, where `SessionAssurancePolicy` denies stale,
missing, malformed, or subject-mismatched evidence before business policies may
grant an action:

```python
from access_gate import AuthorizationEngine, RolePolicy, SessionAssurancePolicy

engine = AuthorizationEngine([
    SessionAssurancePolicy(actions={'records.read'}),
    RolePolicy({'records_reader'}, actions={'records.read'}),
])
```

The assurance policy is deny-only: a trusted session never grants a permission
by itself. See [`docs/ACCESSGATE_INTEGRATION.md`](docs/ACCESSGATE_INTEGRATION.md).

## Customizing Audit Logging

```python
from session_armor import AuditMiddleware

class MyAudit(AuditMiddleware):
    exempt_paths = ('/health/', '/static/', '/favicon.ico')

    def get_user_identity(self, request):
        return {
            'uid': request.user.sub,
            'platform': request.user.platform,
            'org': request.user.organization_uuid,
        }
```

---

## Development

```bash
# Clone and install
git clone https://github.com/Tunet-xyz/session_armor.git
cd session_armor
pip install -e ".[dev]"

# Run tests
pytest

# Lint
ruff check src/session_armor tests

# Type check
mypy src/session_armor
```


## Public Agent MCP Contract

SessionArmor includes a public agent-operability contract in [`mcp/`](mcp/). It describes how external agents can safely help with middleware ordering, security settings, audit customization, gate design, browser-visible docs, and rollout planning without requiring source-code access or production session data.

From a checkout, run the dependency-free contract server with `python mcp/server.py`. After installation, agents can use the packaged stdio command:

```bash
sessionarmor-mcp
```

## License

MIT — Copyright (c) 2024-2026 Tunet Ltd. See [LICENSE](LICENSE).
