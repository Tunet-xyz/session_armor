# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.4.0] - 2026-08-15

### Security

- Replaced ambiguous unkeyed fingerprint and claim digests with keyed,
  domain-separated HMAC-SHA256 over a length-framed representation and
  constant-time comparison.
- Added strict validation for session state version, completeness, timestamps,
  future clock values, security settings, proxy chains, factor inputs, and
  extension-hook outputs. Invalid state is flushed and fails closed.
- Forwarded headers are now ignored by default. Enabling them requires exact
  trusted proxy CIDRs and a bounded hop count; catch-all CIDRs are rejected.
- Gate results are typed `GateDecision` values, cache entries are bound to the
  subject/session scope, malformed cache values are ignored, and unbounded
  sticky approvals are never reused.
- Audit records use full 128-bit request IDs, structured JSON, recursive value
  validation, reserved-field protection, explicit suppression policy, and
  exception-path events.

### Added

- Immutable `SessionAssurance` evidence on every request and a stable,
  primitive-only authorization context contract for AccessGate.
- Public `rebaseline_claims()` API for reviewed server-side identity changes.
- AccessGate integration, threat model, secure-development, audit-scope, and
  release documentation.

### Changed

- The runtime dependency is bounded to the tested Django 4.2 and 5.2 release
  lines; unsupported future major versions cannot be selected silently.
- Security settings are consistently namespaced under `SESSION_ARMOR_*`.
- Gate hooks now consume and return `GateDecision`; error paths cannot opt into
  pass-through.
- Private `_ss_*` state is migrated to versioned `_sa_*` state on the next
  authenticated request, rotating the Django session key.

## [0.3.0] - 2026-07-15

### Security
- **Audit IP pseudonymization is now non-reversible.** `AuditMiddleware` previously logged the client IP as an unsalted, truncated SHA-256, which is trivially reversible for the small IPv4 space — defeating the "privacy-preserving" guarantee. IPs are now hashed with a keyed HMAC-SHA256 (`hash_ip()`), peppered by the new `SESSION_ARMOR_AUDIT_PEPPER` setting (falls back to `SECRET_KEY`). Hash tokens stay deterministic for correlation but change value; back-compat with previously logged tokens is intentionally broken.
- **`SESSION_ARMOR_TRUSTED_PROXY_DEPTH` now defaults to `1` instead of `0`.** The previous default trusted the leftmost, fully client-controlled `X-Forwarded-For` entry, allowing source-IP spoofing of fingerprint binding and audit logs when the setting was left unset (contradicting the documented default). Deployments with no reverse proxy that relied on the old leftmost behavior must set the value to `0` explicitly.
- **Audit log injection hardening.** All string fields in an audit entry — including custom `get_user_identity()` / `get_extra_fields()` values such as a JWT `sub` claim — are now run through `sanitize_for_log()`, not just `path` and `ua`. This prevents embedded newlines/control characters in attacker-influenced fields from forging log lines.
- **Exempt-path matching respects segment boundaries.** `exempt_paths` now matches on path segments (via the shared `path_is_exempt()` helper), so an exemption like `/health` no longer accidentally also exempts sibling paths such as `/health-internal`. Prefixes that already end in `/` are unaffected.

### Added
- **`GateMiddleware.sticky_pass_max_age`** — optional absolute lifetime cap (seconds) for sticky passes (`recheck_after_pass=False`). Set it on authorization/entitlement gates so a revoked user can't retain access indefinitely; `None` (default) keeps the previous unbounded behavior.
- **`SessionSecurityMiddleware.last_active_resolution`** — minimum seconds between `_ss_last_active` writes (default `0` = every request, unchanged). Raise it to reduce session-store write amplification on busy sessions.
- **Security CI workflow** — `bandit` static analysis (blocking) and `pip-audit` dependency scanning (non-blocking, plus a weekly schedule) added under `.github/workflows/security.yaml`; both tools added to the `dev` extra.
- **Packaged MCP contract** — added the `sessionarmor-mcp` stdio command and public agent contract for review-first middleware, audit, gate, and rollout guidance.

## [0.2.0] - 2026-06-12

### Added
- **GateMiddleware `recheck_after_pass`** — set to `False` for "check once" gates (onboarding, compliance): a passing result stays cached for the whole session instead of being re-checked on a TTL. Failures still re-check on the TTL, and `invalidate()` still forces an immediate re-check.
- **GateMiddleware `get_state_version(request)` hook** — return a cheap version stamp (e.g. a Django cache key bumped when an admin publishes a new document version or adds an onboarding step) and the cached gate result is invalidated for every active session the moment the stamp changes, without per-request database hits.
- `invalidate()` now also clears the stored version stamp.

## [0.1.0] - 2026-05-22

### Added
- **SessionSecurityMiddleware** — Client fingerprint binding (IP + User-Agent hash), absolute/idle session timeouts, JWT claim drift detection, session fixation prevention via `cycle_key()`.
- **AuditMiddleware** — Privacy-preserving audit trail for authenticated requests with request ID correlation, hashed IPs, sanitized log entries.
- **GateMiddleware** — Base class for building cacheable, hookable conditional gates (compliance, onboarding, feature flags, maintenance).
- **Utilities** — `get_client_ip()` with proxy-depth awareness, `hash_value()`, `sanitize_for_log()` with control character stripping, `is_authenticated()`.
- Full hook system on all three middleware classes for zero-subclass-needed customization.
- `SESSION_ARMOR_TRUSTED_PROXY_DEPTH` setting to prevent X-Forwarded-For spoofing.
- `fail_open=False` as defense-grade default on GateMiddleware.
- CI/CD with GitHub Actions (tests on Python 3.10–3.13, PyPI publishing via trusted publishing).
