# SessionArmor threat model

This threat model covers the SessionArmor package at a specific source
revision. It is not a system accreditation and must be combined with the host
application's identity, data, deployment, and operational threat models.

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

| Threat | Package control | Residual responsibility |
| --- | --- | --- |
| Stolen-cookie replay | Keyed continuity factors, absolute/idle expiry, claim binding, session-key rotation | Fingerprints are not device identity; call `establish()` at login and keep cookies secure |
| State confusion or partial migration | Versioned complete state, strict type/range checks, fail-closed flush | Roll out key and settings changes deliberately; list retired state keys in `SESSION_ARMOR_STATE_KEY_FALLBACKS` so existing sessions survive rotation |
| Digest ambiguity or comparison oracle | Length framing, purpose-separated HMAC-SHA256, constant-time comparison | Keep state keys and the audit pepper secret; drop a key that may have leaked instead of keeping it as a fallback |
| Forwarded-header spoofing | Ignore-by-default policy, exact hop count, CIDR validation, invalid-chain rejection | Set the proxy depth and CIDRs from the real ingress path |
| Clock rollback/future state | Finite non-negative timestamps and bounded future skew | Keep server clocks synchronized |
| Truthy gate result or stale grant | Typed decisions, identity/session cache scope, bounded/versioned sticky passes | Use TTL gates, state versions, or `invalidate()` where access can be revoked |
| Audit forgery or evidence overwrite | Structured JSON, recursive sanitation, reserved fields, full request IDs | Protect log transport, storage, access, and retention; redact secrets in custom audit paths |
| Authorization/session confusion | Versioned assurance schema, exact subject match, freshness policy, deny-only boundary | Let an authorization layer such as AccessGate make every grant |

## Required invariants

1. A non-exempt authenticated request either receives fresh, subject-bound
   evidence or is stopped and its session flushed.
2. Malformed state, extension failure, proxy ambiguity, and cache corruption
   never produce an authenticated pass-through.
3. By default, a gate whose check raises rejects the request; it never passes
   it.
4. A cached gate decision applies only to the identity and session it was
   computed for.
5. `request.session_assurance` never contains raw fingerprint values, tokens,
   cookies, or claim collections.
6. Session evidence never grants authorization by itself.

## Out of scope

SessionArmor does not validate OIDC tokens, implement MFA, authorize objects,
secure TLS or cookies, guarantee durable log delivery, or replace application
incident response. Django itself, authentication-provider token validation,
edge configuration, object authorization policies, SIEM durability, and
production secret rotation are dependencies of a deployment, not package
controls.

## Residual risks

- Fingerprint continuity is not device identity. An attacker with a valid
  cookie and matching observable factors can still replay it.
- Unless the login view calls `establish()`, the first authenticated request
  after login binds the session, whichever client sends it. With a stateless
  backend such as signed cookies, the login cookie stays unbound until it
  expires.
- IP binding can reject legitimate mobile or privacy-network changes.
- AccessGate remains the authorization boundary; SessionArmor evidence is a
  prerequisite, not a grant.

## Review triggers

Review this model for every change to the session state format, fingerprint
factors, proxy handling, timestamp validation, gate caching, audit fields, the
assurance schema, or the AccessGate bridge, and for every new extension hook or
setting. Record newly accepted residual risks before merge.
