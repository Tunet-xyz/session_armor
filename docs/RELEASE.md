# Release procedure

Apply the shared [versioning policy](../VERSIONING.md). GitHub Actions are
manual-only and may be started only by the owner; agents run the equivalent
checks locally and never dispatch, rerun, re-enable, or approve a workflow.

1. Confirm the version in `pyproject.toml`, `session_armor.__version__`, MCP
   contract, changelog, supported-version table, and consumer pins agree.
2. Run the complete test matrix, Ruff, mypy, Bandit, dependency audit, coverage,
   package metadata tests, and consumer integration suites.
3. Build wheel and sdist with the hash-locked release tools; do not rebuild
   between review and publication. Verify that the sdist includes the policy,
   documentation, tests, and build inputs, and the wheel includes the MIT license,
   `py.typed`, and public MCP contract.
4. Validate metadata, inspect wheel/sdist contents, generate SHA-256 hashes and
   an SBOM, and retain them with the workflow evidence.
5. Publish only from a protected GitHub release environment using PyPI Trusted
   Publishing. The release tag must exactly match the package version. The
   PyPI trusted publisher must name the `pypi` environment, and that environment
   must allow only `main` and `v*` tags; otherwise a workflow edited on another
   branch can publish. Require `bezu-1` to approve the environment deployment;
   agents cannot supply that approval. Confirm the immutable `v<version>` tag
   identifies the reviewed commit before the owner starts publishing.
6. Install the published wheel in a clean environment and run a smoke test.
7. Roll consumers through staged deployment with session-termination, gate
   rejection, audit failure, and AccessGate assurance-denial observability.

Never place PyPI credentials, state keys, audit peppers, production session
samples, or authentication tokens in release artifacts or workflow logs.
