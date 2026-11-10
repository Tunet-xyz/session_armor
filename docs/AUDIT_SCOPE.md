# SessionArmor audit scope

An assessment must name an immutable Git commit and the exact wheel and sdist
SHA-256 digests. Findings against a moving branch or an unverified local build
are not release evidence.

## In scope

- All code under `src/session_armor`: the assurance contracts, gate decisions,
  the Django session, gate, and audit middleware, and the MCP server.
- The packaged MCP contract and the documented public extension hooks.
- Build, dependency, and release configuration.

## Out of scope unless separately commissioned

- Django itself, authentication-provider token validation, TLS and edge
  configuration, object authorization policies, SIEM durability, and production
  secret rotation. These exclusions are dependencies, not assertions that the
  risks do not exist.
- The consumer's middleware ordering, identity semantics, session and log
  backends, ingress topology, key custody, retention, and monitoring, which
  belong to the consumer's own assessment.

## Review entry points

Start with the [threat model](THREAT_MODEL.md), the
[security model](security-model.md), and the
[security assurance case](SECURITY_ASSURANCE.md). The highest-priority review
surfaces are session termination and flush ordering, the termination audit
event, timestamp validation, HMAC framing and domain separation, proxy-chain
traversal, gate cache identity and version binding, audit reserved-field
handling, and the SessionArmor–AccessGate context bridge. Record tool versions,
and distinguish automated findings from manual design conclusions.
