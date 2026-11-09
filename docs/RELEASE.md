# Release procedure

Follow the shared [versioning policy](../VERSIONING.md). The GitHub Actions
workflows are manual-only: only the owner (`@bezu-1`) starts, reruns, or
re-enables them, and only the owner approves the protected `pypi` environment.
Agents run the equivalent checks locally and never dispatch, rerun, re-enable,
or approve a workflow. Pull requests, issues, comments, and mentions never
start one.

## 1. Prepare

1. Confirm one release identity: `version` in `pyproject.toml`,
   `session_armor.__version__`, `server.version` in both copies of the MCP
   contract (`mcp/agent-contract.json` and
   `src/session_armor/mcp/agent-contract.json`), the dated `CHANGELOG.md`
   entry, and the supported-versions table in `SECURITY.md`.
2. Review the compatibility impact, migration notes, documentation, consumer
   version pins, and the integration dependency ranges.

## 2. Verify

Run the checks the workflows run: Python 3.10–3.13 with Django 5.2, Python
3.12–3.13 with Django 6.1, and Django 4.2 at the declared floors, plus the
consumer integration suites:

```bash
python -m pip install -e ".[dev]"
ruff check src tests tools
mypy src/session_armor --ignore-missing-imports
bandit -r src/session_armor tools
pip-audit
pytest --cov=session_armor --cov-branch --cov-report=term-missing
```

Record any check you could not run.

## 3. Build

```bash
python -m pip install --require-hashes -r requirements/build.txt
export SOURCE_DATE_EPOCH="$(git show -s --format=%ct HEAD)"
python -m build --no-isolation
python -m twine check dist/*
```

The workflow does not inspect the archives, so do it yourself: the sdist must
include the policy, documentation, tests, and build inputs, and the wheel the
MIT license, `py.typed`, and the public MCP contract. Record SHA-256 checksums,
and smoke-test the exact wheel in a clean environment.

## 4. Publish

1. Commit and push the verified source under the owner's authorization, then
   create an annotated `v<version>` tag on that exact commit. Only repository
   administrators can create `v*` tags, and nobody can move or delete one.
2. The owner starts `publish.yaml` from `main` or that tag; it stops on any
   other ref, including a tag that does not match the package version. Dispatch
   from the tag for a release. The workflow verifies the source, builds once
   with the hash-locked tools, runs `twine check`, writes an SBOM that
   `pyspdxtools` validates, and writes `SHA256SUMS` (with `dist/` paths).
3. The upload job runs in the `pypi` environment, which only `main` and `v*`
   tags may use and which needs the owner's approval; administrators cannot
   bypass it, and agents cannot give that approval. PyPI Trusted Publishing
   gives the job a short-lived OIDC token, so no long-lived PyPI token exists.
   The trusted publisher must name `Tunet-xyz/session_armor`, `publish.yaml`,
   and the `pypi` environment; otherwise a workflow edited on another branch
   could publish.

Do not publish when a check was skipped without a recorded reason, evidence is
missing, the checkout is dirty, the tag and version disagree, or a security
finding is unresolved. A rerun must start from the same commit or from a new,
reviewed release candidate.

## 5. After publication

Verify the PyPI files against `SHA256SUMS` and their PEP 740 attestations, and
keep the SBOM and checksums, because workflow artifacts expire. Install the
published wheel in a clean environment and run a smoke test. Roll consumers
through staged deployment with session-termination, gate-rejection,
audit-failure, and AccessGate assurance-denial observability. A prepared or
tagged version is not a release until it is on PyPI.

Then update anything that described the publication as pending, such as the
changelog heading or the README's release status.

Never put PyPI credentials, agent tokens, state keys, audit peppers, production
session samples, or authentication tokens in release artifacts or workflow
logs. Never move a release tag, overwrite PyPI files, or reuse a published
version; fix a bad release with a new version.
