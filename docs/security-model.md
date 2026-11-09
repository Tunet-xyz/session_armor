# SessionArmor security model

SessionArmor adds reviewable session-integrity, audit, and request-gate controls to an existing Django application. It is a defence-in-depth component, not an authentication or authorization system by itself.

## What it helps mitigate

- Reuse of a session from a request context whose configured IP or User-Agent fingerprint has changed.
- Sessions remaining usable beyond configured absolute or idle timeouts.
- Selected authenticated claims changing without the session being re-established.
- Missing or unsafe authenticated-request audit events, including control-character log injection and reversible IPv4 pseudonyms.
- Compliance, onboarding, maintenance, and similar workflow checks being implemented inconsistently across views.
- Sticky gate passes remaining valid indefinitely when `sticky_pass_max_age` is set. A state version alone does not age a pass out; it forces a re-check only when the version changes.

## Deployment assumptions

SessionArmor assumes the application already uses:

- HTTPS, secure cookies, CSRF protection, and an appropriately configured Django session backend.
- Authentication and authorization checks suited to the application.
- A correct `SESSION_ARMOR_TRUSTED_PROXY_DEPTH` for the real reverse-proxy chain, with `SESSION_ARMOR_TRUSTED_PROXY_CIDRS` listing those proxies' networks; a non-zero depth without the CIDRs is a configuration error.
- A secret `SESSION_ARMOR_AUDIT_PEPPER`, preferably separate from `SECRET_KEY` when independent rotation is useful.
- Centralized logging with access controls, retention limits, and monitoring appropriate to the data recorded by custom hooks.

## Important limitations

- A fingerprint is not device identity. A stolen cookie replayed from a sufficiently similar request context may not be detected.
- IP binding can produce false positives on mobile networks, corporate egress pools, VPNs, and privacy relays. Override `get_fingerprint_factors()` or disable individual inputs when the deployment requires it.
- Trusting the wrong `X-Forwarded-For` hop can make the fingerprint attacker-controlled. Set the proxy depth from the actual deployment topology, not from a generic example.
- Audit pseudonymization reduces direct exposure but does not make logs anonymous. Deterministic tokens and custom fields can still be personal data.
- `GateMiddleware` is not a replacement for object-level authorization. Revocable entitlements should use normal TTL rechecks, `get_state_version()`, explicit invalidation, or a bounded `sticky_pass_max_age`.
- SessionArmor does not provide MFA, credential policy, malware protection, transport security, breach detection, or a compliance certification.
- Audit emission occurs after a normal response is produced. If a view performs
  an irreversible side effect before audit emission fails, the resulting 500
  response cannot roll that side effect back; use transactional outbox/audit
  patterns for operations that require atomic business and audit persistence.

## Operational defaults to review

| Control | Default | Deployment decision |
| --- | --- | --- |
| Absolute timeout | 8 hours | Match account sensitivity and reauthentication policy. |
| Idle timeout | 30 minutes | Balance exposure against expected user workflows. |
| IP binding | Enabled | Tune for mobile, VPN, and proxy behavior. |
| User-Agent binding | Enabled | Treat as a weak continuity signal, not identity proof. |
| Trusted proxy depth | 0 | Forwarded headers are ignored until both an exact depth and exact trusted CIDRs are configured. |
| Audit pepper | `SECRET_KEY` fallback | Prefer a dedicated secret where rotation or cross-service correlation matters. |
| Gate failure behavior | Closed | Override only after explicitly accepting the availability/security tradeoff. |

## Release and rollout checklist

1. Verify middleware ordering after Django session and authentication middleware.
2. Confirm proxy depth using requests observed through the production ingress path.
3. Exercise fingerprint changes, idle/absolute expiry, claim drift, exempt paths, and custom rejection responses.
4. Verify that audit output contains no secrets or unnecessary personal data from custom hooks.
5. Test gate invalidation and revocation behavior, including long-lived sessions.
6. Roll out with observable rejection reasons and a documented recovery path for false positives.

For vulnerability reporting and supported versions, see [`SECURITY.md`](../SECURITY.md).
