# Release procedure

1. Confirm the version in `pyproject.toml`, `session_armor.__version__`, MCP
   contract, changelog, supported-version table, and consumer pins agree.
2. Run the complete test matrix, Ruff, mypy, Bandit, dependency audit, coverage,
   package metadata tests, and consumer integration suites.
3. Build wheel and sdist once in the release workflow; do not rebuild between
   review and publication.
4. Validate metadata, inspect wheel/sdist contents, generate SHA-256 hashes and
   an SBOM, and retain them with the workflow evidence.
5. Publish only from a protected GitHub release environment using PyPI Trusted
   Publishing. The release tag must exactly match the package version.
6. Install the published wheel in a clean environment and run a smoke test.
7. Roll consumers through staged deployment with session-termination, gate
   rejection, audit failure, and AccessGate assurance-denial observability.

Never place PyPI credentials, state keys, audit peppers, production session
samples, or authentication tokens in release artifacts or workflow logs.
