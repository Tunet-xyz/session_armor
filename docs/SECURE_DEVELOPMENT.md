# Secure development

- Treat middleware ordering, exempt paths, proxy trust, state keys, audit hooks,
  gate skips, and sticky passes as security-sensitive review areas.
- Add an adversarial regression test before fixing a bypass or confusion bug.
- Extension outputs must be explicitly typed, bounded, and safe to serialize.
- Never log raw cookies, tokens, fingerprint inputs, claim sets, session nonces,
  state keys, or audit peppers.
- Do not make network/database failures pass gates. Recovery endpoints must be
  narrowly exempt and independently authenticated where appropriate.
- A `SessionAssurancePolicy` success is not an authorization grant.
- Run tests, Ruff, mypy, Bandit, dependency audit, coverage, package build, and
  artifact metadata checks before release.

Security claims in documentation must identify deployment assumptions and
residual risks. Passing this repository's tests is evidence about the package,
not a certification of a consuming system.
