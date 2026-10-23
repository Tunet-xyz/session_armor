# SessionArmor threat model

## Security objective

For every non-exempt authenticated request, SessionArmor must either establish
fresh, subject-bound session evidence or stop the request and flush the session.
It must not turn malformed state, extension failure, proxy ambiguity, or cache
corruption into an authenticated pass-through.

## Assets and trust boundaries

- Django's authenticated user, session identifier, cookie, and server-side
  session record are security assets.
- Socket peer and HTTP headers cross an untrusted network boundary. A forwarded
  chain becomes trusted only after the configured proxy count and every trusted
  hop match explicit CIDRs.
- User/identity hooks, gate checks, audit customizers, session backends, log
  handlers, and clocks are application-controlled extension boundaries.
- `request.session_assurance` crosses from SessionArmor into authorization. It
  contains no raw fingerprint values, tokens, cookies, or claim collections.

## Threats and controls

| Threat | Primary controls |
| --- | --- |
| Stolen-cookie replay | Keyed continuity factors, absolute/idle expiry, claim binding, session-key rotation |
| State confusion or partial migration | Versioned complete state, strict type/range checks, fail-closed flush |
| Digest ambiguity or comparison oracle | Length framing, purpose-separated HMAC-SHA256, constant-time comparison |
| Forwarded-header spoofing | Ignore-by-default policy, exact hop count, CIDR validation, invalid-chain rejection |
| Clock rollback/future state | Finite non-negative timestamps and bounded future skew |
| Truthy gate result or stale grant | Typed decisions, identity/session cache scope, bounded/versioned sticky passes |
| Audit forgery or evidence overwrite | Structured JSON, recursive sanitation, reserved fields, full request IDs |
| Authorization/session confusion | Versioned assurance schema, exact subject match, freshness policy, deny-only boundary |

## Residual risk

Fingerprint continuity is not device identity. An attacker with a valid cookie
and matching observable factors can still replay it. Unless the login view calls
`establish()`, the first authenticated request after login binds the session,
whichever client sends it; with a stateless backend such as signed cookies, the
login cookie stays unbound until it expires. IP binding can also reject
legitimate mobile/privacy-network changes. SessionArmor does not validate OIDC
tokens, implement MFA, authorize objects, secure TLS/cookies, guarantee durable
log delivery, or replace application incident response. AccessGate remains the
authorization boundary; SessionArmor evidence is a prerequisite, not a grant.
