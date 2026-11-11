# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- A Contributor Covenant 2.1 code of conduct, and issue templates for bug
  reports and feature requests that send vulnerability reports to private
  reporting.
- `python -m session_armor.mcp` starts the MCP server, like the
  `sessionarmor-mcp` command.
- The Django extra allows Django 6 (`Django>=4.2,<7`); CI tests Django 4.2,
  5.2, and 6.1.

### Changed

- The Product URL points at `www.tunet.xyz`, which serves the product page.
- README examples corrected: the gate example exempts the page its rejection
  redirects to, critical claims and audit identity values are converted to
  strings, and the audit logger's name and levels are documented.
- The security policy uses the layout shared by the Tunet libraries: private
  reporting through the Security tab or by email, one set of response targets
  (critical fixes within 7 days instead of 30), package scope, and secure-use
  guidance.
- `VERSIONING.md` is worded for outside readers; its rules are unchanged.
- Documentation has the layout shared by the Tunet libraries: a docs index, and
  the same sections in the release procedure, threat model, assurance case,
  audit scope, secure-development notes, and MCP README. The security model and
  AccessGate guide now say that a state version alone does not age out a sticky
  pass, that a non-zero proxy depth needs the trusted CIDRs, and that
  AccessGate's default assurance policy denies evidence without claim or
  continuity binding. The release procedure marks the archive checks the
  workflow does not do, and the Documentation URL points at the docs index.
- README sections follow the order the Tunet libraries share: features, version
  status, installation, quick start, usage, MCP server, scope and limitations,
  documentation, development, contributing, and license, with PyPI, Python, and
  license badges. The MCP section says its tools return guidance instead of
  generating drafts, and the proxy comment says a non-zero depth also needs
  CIDRs.
- The README links GeoCanon at its renamed repository, `Tunet-xyz/geo_canon`, and
  calls the owner the owner; links use descriptive labels.
- The AccessGate integration guide moved to `docs/access-gate-integration.md`,
  matching the other kebab-case guide names.
- The copyright year in LICENSE and the README is 2026, the year the project
  started.
- The agent contract names the installed `sessionarmor-mcp` stdio server
  instead of promising a hosted endpoint, adds the `cli` operation mode, quotes
  the `SessionArmor[django]` install in `djangoAdapter`, and points `docsUrl` at
  `docs/README.md`.
- The MCP server's `prompts/get` fills a template in one pass and rejects
  undeclared, missing, or non-string arguments; `tools/call` checks each
  tool's required arguments, types, and allowed values; tool descriptions say
  the tools return contract guidance, and every tool reply says it does not
  run SessionArmor or generate code; error details are cut to 200 characters.
- Package metadata drops the end-of-life Django 5.0 and 5.1 classifiers, adds
  6.1 and `Typing :: Typed`, and its keywords add `mcp`; the sdist ships
  `CODE_OF_CONDUCT.md` and the root `conftest.py`.
- The assurance workflow builds from the hash-locked build requirements without
  build isolation and validates the SPDX SBOM with `pyspdxtools`, as the
  publish workflow now does too; both set `SOURCE_DATE_EPOCH` from the commit.
  CodeQL uses the same codeql-action release as the Scorecard SARIF upload, and
  workflow files end in `.yaml`.

### Security

- `SessionSecurityMiddleware` records each session it terminates as a
  `session.terminated` event on the `security.audit` logger, whatever the
  middleware order, with the reason, the subject identifier, and the keyed IP
  hash that request events carry, and never the path, User-Agent, or raw
  address. Timeouts are logged at `INFO` and every other reason at `WARNING`
  (`AUDIT_DENIED`); the new `audit_logger_name` attribute changes the logger.
  In the documented middleware order, terminations used to leave no audit
  record. An application that already logs terminations from `on_violation()`
  will see two records.

## [1.0.0] - 2026-11-05

### Changed

- Stabilized the documented framework-neutral assurance and gate-decision APIs,
  Django middleware adapters, extension hooks, and local MCP entry point.
- Adopted the shared SemVer, owner-review, manual-workflow, and immutable-release
  policy in `VERSIONING.md`, with matching Claude and Codex instructions.
- Aligned package, runtime, and public MCP versions; preserved the assurance v1
  schema and the 0.6 middleware behavior.
- Declared packaged MIT license files and a PEP 639-capable build backend.
- Made the hash-locked release toolchain cover Windows, Linux, and Python 3.10+
  instead of relying on a Linux/Python 3.13-only dependency resolution.
- Allowed the AccessGate 1.x release in the development integration dependency.

### Documentation

- Documented the stable API, pre-0.5 migration boundaries, supported integration
  ranges, and the local-only scope of the public agent contract.

### Security

- Updated the locked setuptools build tool to 84.2.1, addressing
  GHSA-xmj3-9gf7-h52w in the previous Windows build toolchain.

## [0.6.0] - 2026-10-29 (not published to PyPI; included in 1.0.0)

### Security

- `SessionSecurityMiddleware`, `GateMiddleware` and `AuditMiddleware` match
  `exempt_paths` against `request.path_info` (the path Django routes on) instead
  of `request.path`, so a `SCRIPT_NAME` taken from a forwarded request header
  can no longer exempt a protected view. Remove any mount prefix written into
  `exempt_paths`.
- An exempt path of `/` exempts only the root URL; as a prefix it used to exempt
  every path from session checks, gates and audit.
- `SESSION_ARMOR_STATE_KEY`, `SESSION_ARMOR_AUDIT_PEPPER` and fallback keys must
  be `str` or `bytes`; other types, such as an integer that `bytes()` turned into
  a public all-zero key, raise `SessionConfigurationError`.
- `hash_ip()` hashes values in the reserved `session-armor:` namespace under a
  separate derived key, so no digest can equal a state-MAC subkey when the audit
  pepper and the state key share `SECRET_KEY`. Other digests are unchanged.
- Gate cache entries record the gate class that wrote them; a gate never reuses a
  result cached by a different class with the same `gate_id`.
- Audit: `error_type` is reserved evidence that hooks can neither supply nor
  change, `get_extra_fields()` keys that repeat identity keys raise
  `AuditEmissionError`, and `before_log()` edits made in place on reserved fields
  are rejected like edits on a copy.
- Audit: a client IP that cannot be validated is recorded as `ip_hash: null`
  instead of losing the event, and a request whose view logs the user out is
  recorded and attributed to the user it arrived with.

### Added

- `SESSION_ARMOR_STATE_KEY_FALLBACKS` for graceful key rotation: retired keys only
  verify existing state, which is then re-signed with the current key. When it is
  unset, a state key that follows `SECRET_KEY` honours `SECRET_KEY_FALLBACKS`.
- `SessionSecurityMiddleware.establish(request, user=None)` binds a session during
  the login request.
- `SessionSecurityMiddleware.refresh_assurance(request, user=None)` re-verifies
  the session and re-issues trusted evidence right before a late authorization
  decision, and `rebaseline_claims(..., refresh_assurance=True)` does the same
  after a claim rebaseline, so integrations never build `SessionAssurance`.
- `SessionSecurityMiddleware.has_state()`, `discard_state()` and
  `binding_digests()` replace reading the private `_sa_*`/`_ss_*` keys and
  re-deriving per-factor diagnostics.
- `GateMiddleware.error_cache_ttl` caps how long a rejection from `on_error()` is
  reused, `follow_session_exemptions` lets a gate follow SessionArmor's own
  exemptions, and `get_cached_decision()` returns the last stored gate result.
- `AuditMiddleware.get_audit_path()` keeps secrets carried in URL paths out of
  audit records; the returned path stays reserved evidence.

### Changed

- A request without a User-Agent is bound to an explicit "absent" marker instead
  of failing evaluation; a session started with a User-Agent still ends with
  `fingerprint_mismatch` if the header disappears.
- IPv4-mapped IPv6 peers (`::ffff:a.b.c.d`) are returned and matched in IPv4
  form. Dual-stack deployments see one `fingerprint_mismatch` per live session and
  new audit `ip_hash` values for those clients after upgrading;
  `::ffff:0:0/96` is rejected as a catch-all CIDR.
- With a non-zero `SESSION_ARMOR_TRUSTED_PROXY_DEPTH`, `get_client_ip` reads only
  the client entry and the trusted hops, and forwarded entries may carry a port.
- `GateMiddleware` no longer converts exceptions from the view or inner
  middleware into `gate_evaluation_error` rejections; only gate evaluation fails
  closed.
- Evidence never reports `established_at`/`last_activity_at` later than its
  `verified_at` when another instance's clock ran ahead, so AccessGate no longer
  denies those sessions with `invalid_session_timeline`.
- HMAC subkeys are cached per key and purpose, and audit events the logger would
  drop are validated but not rendered; stored MACs and emitted lines are
  unchanged.
- Django hooks declare `HttpResponseBase` return types; the branch-coverage gate
  is 83% with new fail-closed regression tests, and a bridge test runs real
  evidence through AccessGate (the `dev` extra installs AccessGate).
- Release workflows stay manually dispatched but refuse refs other than `main`
  or `v<version>`, run lint, type checks and tests first, and build with the
  hash-locked tools in `requirements/build.txt`.

### Fixed

- Contained session-evaluation and re-verification errors are logged at WARNING
  with a traceback on `session_armor.session`; an exception from `on_timeout()` is
  logged and no longer replaces the timeout reason; a malformed
  `SESSION_ARMOR_STATE_KEY_FALLBACKS` is reported on the first request.
- `on_violation()` runs once even when terminating the session fails.
- The default `get_login_url()` honours a lazy `LOGIN_URL` such as
  `reverse_lazy(...)`.
- Gates with `requires_auth = False` no longer reject every anonymous request.
- `GateDecision` applies the string-length and finite-number checks to list items
  in `context`.
- Audit entries over 16,384 characters are re-rendered with only the reserved and
  identity fields and `truncated: true` instead of being cut into invalid JSON.
- The MCP server writes ASCII-only JSON, reads stdin as UTF-8 under any locale,
  answers unserializable responses with -32603 and invalid UTF-8 with -32700
  instead of exiting, omits `outputSchema` when a tool defines none, answers
  `ping`, and rejects a `null` request id; its contract lists every setting the
  package reads.
- The `get_client_ip` docstring, the README "check once" gate example and the
  SECURITY.md support table match the code and the 0.5.x line.

## [0.5.0] - 2026-08-16

### Changed

- Split the dependency-free assurance and gate-decision contracts from the
  optional Django middleware adapter.
- Moved Django middleware imports to `session_armor.adapters.django` and made
  Django installable through the `SessionArmor[django]` extra.
- Removed the old root and module-level middleware imports so framework
  boundaries remain explicit.

### Fixed

- Use Django session mapping views when inspecting session keys, avoiding
  `KeyError: 0` during real `SessionStore` initialization and validation.

## [0.4.0] - 2026-08-15 (not published to PyPI; included in 0.5.0)

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

## [0.3.0] - 2026-07-15 (not published to PyPI; included in 0.5.0)

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

## [0.2.0] - 2026-06-12 (not published to PyPI; included in 0.5.0)

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

[Unreleased]: https://github.com/Tunet-xyz/session_armor/compare/v1.0.0...HEAD
[1.0.0]: https://github.com/Tunet-xyz/session_armor/releases/tag/v1.0.0
[0.5.0]: https://github.com/Tunet-xyz/session_armor/releases/tag/v0.5.0
[0.1.0]: https://pypi.org/project/SessionArmor/0.1.0/
