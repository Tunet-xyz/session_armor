# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
