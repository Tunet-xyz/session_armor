# SessionArmor secure development

SessionArmor applies the intent of the NIST Secure Software Development Framework
(SSDF) to a small session-security library.

## Practices

- **Prepare:** maintain the threat model, ownership boundaries, disclosure
  process, protected CI permissions, and documented release criteria.
- **Protect:** require least-privilege workflows, commit-pinned actions, hashed
  release tooling, trusted publishing, protected environments, and reviewed
  changes on `main`.
- **Produce:** add an adversarial regression test before fixing a bypass or
  confusion bug, keep extension outputs explicitly typed, bounded, and safe to
  serialize, use strict typing and linting, and test every fail-closed path.
- **Respond:** triage privately, contain critical issues rapidly, revoke or
  rotate affected trust, issue patched releases and advisories, and capture
  lessons in tests and the threat model.

## Security-sensitive changes

Every security-relevant change must identify the affected assets and trust
boundaries, include negative tests, and consider compatibility and migration.
No generated or AI-assisted change is exempt from human review and the same
checks. Do not weaken a bound, error mode, audit behavior, signature check, or
release gate solely to preserve compatibility.

Treat middleware ordering, exempt paths, proxy trust, state keys, audit
hooks, gate skips, and sticky passes as security-sensitive review areas.

- Never log raw cookies, tokens, fingerprint inputs, claim sets, session
  nonces, state keys, or audit peppers.
- Do not make network or database failures pass gates. Recovery endpoints
  must be narrowly exempt and independently authenticated where appropriate.
- A `SessionAssurancePolicy` success is not an authorization grant.
- Run the tests, Ruff, mypy, Bandit, the dependency audit, coverage, the
  package build, and artifact metadata checks before release (see the
  [release procedure](RELEASE.md)).
- Security claims in documentation must identify deployment assumptions and
  residual risks. Passing this repository's tests is evidence about the
  package, not a certification of a consuming system.

## Repository controls

These GitHub settings were in place on 2026-11-09:

- `main` accepts pushes only from the owner and rejects force pushes and
  deletion. Other changes need a pull request approved by the code owner, with
  stale approvals dismissed and conversations resolved.
- Release tags (`v*`) can be created only by repository administrators, and no
  one can move or delete them.
- The `pypi` environment accepts only `main` and `v*` tags, requires the
  owner's approval, and does not let administrators bypass it. PyPI uploads use
  Trusted Publishing with short-lived OIDC credentials.
- Every workflow is manual (`workflow_dispatch`) and runs only when the owner
  starts it, with actions pinned to full commit SHAs and read-only default
  permissions. Pull requests, issues, and comments cannot start a workflow.
- Secret scanning with push protection, Dependabot alerts and security updates,
  and private vulnerability reporting are on.

Known gaps: the project has one maintainer, so no second person reviews the
owner's changes, and the owner can push to `main` directly. No status checks
are required, because CI runs only when the owner starts it, and commits are
not required to be signed. Export these settings with each audit.
