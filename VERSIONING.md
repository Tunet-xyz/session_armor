# Versioning and releases

SessionArmor, AccessGate, GeoCanon, and SwapLayer share this policy. Each package
has its own version and release cadence; a change in one does not force releases
of the others. The first stable release of each is **1.0.0**.

## Choosing a version

Use [Semantic Versioning 2.0.0](https://semver.org/spec/v2.0.0.html):

| Change | Version | Examples |
| --- | --- | --- |
| Compatible correction | PATCH (`1.0.1`) | Fix a defect without changing the documented contract; correct documentation or bundled data while preserving existing semantics. |
| Compatible addition | MINOR (`1.1.0`) | Add a public API, optional provider, configuration option, or data surface; deprecate an API with migration guidance. |
| Incompatible change | MAJOR (`2.0.0`) | Remove/rename an API, change return shapes or defaults incompatibly, drop supported Python/framework versions, or change a wire contract incompatibly. |

The stable contract includes documented exports and signatures, configuration,
exceptions, return shapes, adapter behavior, entry points, and serialized formats.
Private names are implementation details. Provider availability and upstream
datasets are external dependencies; document their limits and compatibility.
Review security fixes for compatibility too: explain tightened validation and
migration impact rather than silently calling a breaking change a patch.

Use Python/PEP 440 prereleases such as `1.1.0a1`, `1.1.0b1`, and `1.1.0rc1`.
Do not use SemVer's hyphen syntax for Python package prereleases. Prereleases
require explicit installation or `--pre` and must be labelled in release notes.
Schema identifiers have their own compatibility versions; do not increment an
assurance/policy/MCP protocol schema merely because the package version changes.

## One release identity

`[project].version` in `pyproject.toml` is authoritative. In the same change, align:

- The package's public `__version__`.
- Every public agent contract's `server.version`, in the checkout and wheel.
- The dated `CHANGELOG.md` entry and security support table.
- Version assertions, examples that intentionally pin the current release, and
  reviewed integration dependency ranges.

Preserve historical changelog entries and old-version regression fixtures.
Use an annotated Git tag `v<package version>` on the exact verified commit.
Never move a release tag, overwrite PyPI files, reuse a published version, or
silently rebuild reviewed artifacts. Correct a published release with a new
version; yank an unsafe version when appropriate and explain the replacement.

## Verification and publication

1. Start from the current `main`, keep unrelated changes intact, and review the
   diff.
2. Update API/configuration documentation and migration notes with the code.
3. Run relevant tests, advertised Python/framework compatibility checks, lint,
   type checks, static security analysis, and dependency auditing. Record skips
   and unavailable checks honestly. Exercise any affected user interface, such
   as Django admin pages, in an isolated browser profile that holds no personal
   sign-ins; library-only changes have no standalone UI.
4. Inspect source and history for secrets. Check MIT metadata, the packaged
   license, third-party notices, wheel/sdist contents, and clean-install imports.
5. Build wheel and sdist, run `python -m twine check`, retain SHA-256 checksums
   and available SBOM/provenance evidence, and smoke-test the exact wheel.
6. Commit and push only verified changes, and only with the authorization of
   the person you work for. External contributions require the owner's approval
   before merge. A release request authorizes preparing the release; it does not
   authorize an agent to approve a protected deployment on the owner's behalf.
7. GitHub Actions entry points are **manual-only** (`workflow_dispatch`), and
   their jobs run only when the owner (`@bezu-1`) started them. Only the owner
   may start, rerun, or re-enable them; agents run the equivalent checks
   locally. PRs, pushes, issues, comments, mentions, and schedules cannot
   authorize agent work or repository workflow execution. GitHub Apps installed
   on the organization keep their own installation permissions, which
   repository instructions do not restrict. Do not introduce
   `pull_request_target` or untrusted checkout execution with credentials.
8. Prefer PyPI Trusted Publishing bound to this repository, `publish.yaml`, and
   the owner-approved `pypi` environment. Restrict deployment refs to `main` or
   matching protected release tags. Never put an agent token or long-lived
   publishing credential in a public workflow, artifact, example, or log.
9. Verify the published version, hashes, metadata, links, and clean installation
   before announcing availability. A prepared version is not a published release.

Repository write access, review approval, agent execution, and publishing are
separate permissions. Public source and a public MCP contract grant none of the
maintainer's credentials, agent accounts, paid execution, or production access.
