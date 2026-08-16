# Audit scope

The security review boundary includes all code under `src/session_armor`, the
packaged MCP contract, build/release configuration, and the documented public
extension hooks. Consumer middleware ordering, identity semantics, session/log
backends, ingress topology, key custody, retention, and monitoring remain in the
consumer assessment scope.

High-priority review surfaces are session termination and flush ordering,
timestamp validation, HMAC framing/domain separation, proxy-chain traversal,
gate cache identity/version binding, audit reserved-field handling, and the
SessionArmor–AccessGate context bridge.

Excluded from a package-only audit are Django itself, authentication-provider
token validation, TLS/edge configuration, object authorization policies, SIEM
durability, and production secret rotation. Those exclusions are dependencies,
not assertions that the risks do not exist.
