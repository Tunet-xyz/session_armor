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

`SessionAssurancePolicy` also requires AccessGate's `Subject.identifier` to equal
the evidence's `subject_identifier`, or it denies with `subject_mismatch`.
SessionArmor's `get_subject_identifier()` uses `user.sub`, then `pk`, then `id`;
AccessGate's `default_subject_resolver()` uses `pk`, then `id`. For a user model
with a `sub` claim, give `DjangoAuthorizer` a subject resolver that uses the
same value, or override `get_subject_identifier()` to return the primary key:

```python
from access_gate import Subject


def resolve_subject(request):
    user = request.user
    if user.is_authenticated is not True:
        return Subject("", authenticated=False)
    return Subject(str(user.sub), roles=frozenset(user.groups.values_list("name", flat=True)))


authorizer = DjangoAuthorizer(engine, subject_resolver=resolve_subject)
```

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

By default `SessionAssurancePolicy` also requires continuity binding and claim
binding (`require_binding=True`, `require_claim_binding=True`). Evidence from a
deployment with no continuity factors, or with
`SESSION_ARMOR_DETECT_CLAIM_DRIFT = False` (evidence `claims_bound` is then
false), is denied with `binding_required` or `claim_binding_required` on every
request. Relax those arguments only as a reviewed, deliberate choice.

Evidence timestamps never exceed `verified_at`. State written by an instance
whose clock runs ahead (within `SESSION_ARMOR_CLOCK_SKEW`) is reported at the
verifying instance's time, so `SessionAssurancePolicy(clock_skew=...)` does not
have to match `SESSION_ARMOR_CLOCK_SKEW`.

## Long requests

Evidence is verified when `SessionSecurityMiddleware` runs. When slow
middleware or view work can push an authorization decision past
`max_verification_age`, re-verify right before deciding rather than widening the
window:

```python
def context(request):
    MySessionSecurity(lambda request: None).refresh_assurance(request)
    return default_context_resolver(request)

authorizer = DjangoAuthorizer(engine=engine, context_resolver=context)
```

`refresh_assurance()` re-runs the timeout, integrity, continuity and claim
checks with the current clock and re-issues the evidence. It only refreshes
evidence the middleware already trusts, and it never writes or flushes the
session: a violation leaves `UNVERIFIED` evidence (AccessGate denies) and the
next request terminates the session.

## Schema compatibility

`session-armor.assurance/v1` (`ASSURANCE_SCHEMA`) is a compatibility contract:
AccessGate matches it literally and denies any other value. It changes only in
a minor release whose notes name the AccessGate release that accepts the new
schema, so pin both packages below their next minor version.

## Testing with a fake clock

`SessionAssurancePolicy` binds `time.time` when AccessGate is imported. A test
that patches SessionArmor's clock
(`session_armor.adapters.django.session.time.time`) must pass the same fake
clock as `SessionAssurancePolicy(clock=...)`, or the two libraries disagree
about the current time and fresh evidence is denied as stale or future-dated.
