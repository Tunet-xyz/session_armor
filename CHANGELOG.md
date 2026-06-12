# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
