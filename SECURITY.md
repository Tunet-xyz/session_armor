# Security policy

## Supported versions

| Version | Supported          |
| ------- | ------------------ |
| 1.0.x   | :white_check_mark: |
| < 1.0   | :x:                |

Security fixes ship as new 1.0.x releases on
[PyPI](https://pypi.org/project/SessionArmor/). Earlier releases on PyPI (0.1.0
and 0.5.0) are not supported; upgrade to 1.0.x.

## Reporting a vulnerability

Do not report a suspected vulnerability in a public issue, pull request, or
discussion. Report it privately in either of these ways:

- On GitHub, open the repository's **Security** tab and choose
  **Report a vulnerability**
  ([direct link](https://github.com/Tunet-xyz/session_armor/security/advisories/new)).
- Email **alex@tunet.xyz**.

Include a description, the affected versions, reproduction steps, the potential
impact, and any suggested mitigation. Use synthetic examples; do not send
credentials, personal data, or production samples.

## Response targets

We aim to acknowledge reports within 48 hours and provide an initial assessment
within five business days. Targets begin when severity is confirmed:

| Severity | Containment/mitigation target | Fix target |
| --- | --- | --- |
| Critical | 24 hours | 7 days |
| High | 3 business days | 14 days |
| Moderate | 10 business days | 30 days |
| Low | 30 days | 90 days |

These are maximum targets, not a promise to delay urgent fixes. If a complete
fix needs longer, we will prioritize a safe mitigation, coordinate disclosure,
and communicate a revised timeline privately. Please allow a reasonable period
for remediation before public disclosure. We will request a CVE and publish a
GitHub security advisory when impact warrants it.

## Scope

### In scope

- Session fixation or hijacking bypasses.
- Fingerprint binding bypasses.
- Log injection through a sanitization bypass.
- `X-Forwarded-For` spoofing past the trusted proxy depth and CIDR controls.
- Any bypass of gate middleware security checks.
- Session-assurance confusion, subject mismatch, or stale-evidence acceptance.
- Malformed cached or session state that produces an authenticated
  pass-through.
- Local MCP server output that exposes supplied settings or session data.

### Out of scope

- Vulnerabilities in Django itself; report them to the Django security team.
- Deployment choices the documentation leaves to the application, such as
  middleware order, proxy settings, and key custody.
- Issues that require physical access to the server.
- Social engineering attacks.

## Secure use

- Work through the deployment assumptions and the release and rollout checklist
  in the [security model](docs/security-model.md) before deploying.
- Keep HTTPS, secure cookie settings, CSRF protection, authorization, and MFA in
  place; SessionArmor adds to them and does not replace them.
- Set a dedicated `SESSION_ARMOR_STATE_KEY` (rotate it with
  `SESSION_ARMOR_STATE_KEY_FALLBACKS`) and `SESSION_ARMOR_AUDIT_PEPPER`.
- Trust `X-Forwarded-For` only by setting both
  `SESSION_ARMOR_TRUSTED_PROXY_DEPTH` and `SESSION_ARMOR_TRUSTED_PROXY_CIDRS` to
  match your proxies.
- Treat fingerprint binding as a replay signal, not proof of device identity,
  and use TTL gates rather than sticky passes where access can be revoked.

The [threat model](docs/THREAT_MODEL.md),
[security assurance case](docs/SECURITY_ASSURANCE.md),
[audit scope](docs/AUDIT_SCOPE.md), and
[secure development](docs/SECURE_DEVELOPMENT.md) documents describe the design
assumptions, evidence, and residual risks in more detail.

## Releases and advisories

Security fixes are released from a reviewed commit on `main` through the
owner-approved trusted-publishing workflow described in
[docs/RELEASE.md](docs/RELEASE.md). Workflows run only when the owner starts
them, and PyPI uploads use short-lived OIDC credentials from a protected
environment. Stable API changes follow [VERSIONING.md](VERSIONING.md); a
security fix may intentionally reject previously accepted ambiguous input, with
the compatibility and migration impact explained in the release notes. Pin and
verify release artifacts, watch this repository's security advisories, test
your integration, and upgrade supported versions promptly.
