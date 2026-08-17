# AccessGate integration

SessionArmor establishes session trust; AccessGate decides permissions. Neither
product silently assumes the other's job.

Install the optional adapters and import each framework integration explicitly:

```bash
pip install "SessionArmor[django]" "AccessGate[django]"
```

```python
from session_armor.adapters.django import SessionSecurityMiddleware
from access_gate.adapters.django import DjangoAuthorizer
```

1. Django session and authentication middleware establish `request.session` and
   `request.user`.
2. `SessionSecurityMiddleware` validates continuity, time bounds, claim binding,
   and state integrity, then attaches immutable `request.session_assurance`.
3. AccessGate's `default_context_resolver()` serializes that evidence under the
   `session_assurance` context key.
4. `SessionAssurancePolicy` denies missing, malformed, stale, future-dated,
   unbound, or subject-mismatched evidence. On success it abstains.
5. Application AccessGate policies must still produce an allow.

```python
engine = AuthorizationEngine([
    SessionAssurancePolicy(actions={"case.read"}),
    TenantBoundaryPolicy(actions={"case.read"}),
    RolePolicy({"case_reader"}, actions={"case.read"}),
])
```

The default maximum verification age is 30 seconds and the middleware emits
evidence on every evaluated request. Do not reconstruct assurance from `_sa_*`
session keys, accept an evidence mapping from the client, or copy it between
requests. Tests should include missing evidence, wrong subject, stale evidence,
disabled claim binding, no continuity factors, malformed serializers, and a
valid session that still lacks application permission.
