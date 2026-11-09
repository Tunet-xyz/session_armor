# SessionArmor security assurance case

This document links SessionArmor's security claims to repository evidence.
Passing evidence increases confidence; it is not an independent audit or a
certification, and it does not establish that every deployment is secure.

## Claims and evidence

| Claim | Implementation | Automated evidence |
| --- | --- | --- |
| Sessions end on continuity, expiry, or claim violations | `adapters/django/session.py` | `tests/test_session.py`, `tests/test_fail_closed_paths.py` |
| Malformed state and extension failures fail closed | session and gate middleware | `tests/test_fail_closed_paths.py` |
| Forwarded headers are trusted only through configured hops and CIDRs | `adapters/django/utils.py` | `tests/test_utils.py`, `tests/test_fail_closed_paths.py` |
| Gate decisions are typed, identity-bound, and bounded in time | `adapters/django/gate.py`, `decisions.py` | `tests/test_gate.py` |
| Audit events are structured and sanitized | `adapters/django/audit.py` | `tests/test_audit.py`, `tests/test_utils.py` |
| Assurance evidence is versioned, subject-bound, and fresh | `assurance.py` | `tests/test_assurance.py`, `tests/test_accessgate_bridge.py` |
| The MCP server is bounded and read-only | `mcp/server.py` | `tests/test_mcp_server.py` |
| Release metadata and build inputs agree | `pyproject.toml`, `requirements/`, release tools | `tests/test_release_tools.py`, `tests/test_package.py` |

## Evidence commands

Run from a clean checkout of the revision being assessed:

```bash
python -m pip install -e ".[dev]"
ruff check src tests tools
mypy src/session_armor --ignore-missing-imports
bandit -r src/session_armor tools
pip-audit
pytest --cov=session_armor --cov-branch --cov-report=term-missing
```

## Workflow evidence

The GitHub workflows are manual: only the owner starts them, and none runs on
a schedule (Dependabot checks dependencies weekly). Record which of them ran
for the assessed commit.

| Workflow | What it runs |
| --- | --- |
| `tests.yaml` | Ruff, mypy, and pytest with branch coverage on Python 3.10–3.13 with Django 4.2 and 5.2 |
| `security.yaml` | Bandit and a dependency audit |
| `assurance.yaml` | The adversarial, MCP, and release suites, a package build with an SBOM, and a `py.typed` check |
| `codeql.yml` | CodeQL with the security-extended queries |
| `scorecard.yml` | OpenSSF Scorecard |
| `publish.yaml` | Verification, a hash-locked build with an SBOM and checksums, and PyPI publication with PEP 740 attestations |

Keep the workflow URLs and logs, commit SHA, release checksums, SBOM, and PyPI
provenance as the evidence bundle; workflow artifacts expire.

## Manual evidence still required

- Independent design review and targeted penetration testing before
  high-impact deployment.
- Consumer tests of the exact middleware ordering, proxy path, session backend,
  identity claims, AccessGate policy set, audit sink, and failure and recovery
  paths.
- Repository settings from GitHub (see
  [secure development](SECURE_DEVELOPMENT.md#repository-controls)).
