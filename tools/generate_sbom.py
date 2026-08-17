"""Generate a deterministic SPDX 2.3 SBOM for SessionArmor artifacts."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import subprocess  # nosec B404
from datetime import datetime, timezone
from pathlib import Path
from typing import cast

try:
    import tomllib
except ModuleNotFoundError:  # pragma: no cover
    import tomli as tomllib


def _digest(path: Path, algorithm: str) -> str:
    digest = hashlib.new(algorithm, usedforsecurity=algorithm != "sha1")
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _revision(root: Path) -> str:
    configured = os.environ.get("GITHUB_SHA")
    if configured:
        return configured
    git_executable = shutil.which("git")
    if git_executable is None:
        raise RuntimeError("git is required when GITHUB_SHA is not set")
    result = subprocess.run(  # nosec B603
        [git_executable, "-c", f"safe.directory={root.as_posix()}", "rev-parse", "HEAD"],
        cwd=root,
        check=True,
        capture_output=True,
        text=True,
    )
    return result.stdout.strip()


def generate_sbom(root: Path, dist: Path) -> dict[str, object]:
    root = root.resolve()
    dist = dist.resolve()
    with (root / "pyproject.toml").open("rb") as handle:
        project = cast(dict[str, object], tomllib.load(handle)["project"])
    name = str(project["name"])
    version = str(project["version"])
    revision = _revision(root)
    artifacts = sorted(path for path in dist.iterdir() if path.suffix in {".whl", ".gz"})
    if not artifacts:
        raise ValueError("No wheel or source distribution artifacts were found.")

    files: list[dict[str, object]] = []
    relationships: list[dict[str, str]] = [
        {
            "spdxElementId": "SPDXRef-DOCUMENT",
            "relationshipType": "DESCRIBES",
            "relatedSpdxElement": "SPDXRef-Package-SessionArmor",
        }
    ]
    verification_values: list[str] = []
    for index, artifact in enumerate(artifacts, start=1):
        file_id = f"SPDXRef-Artifact-{index}"
        sha1 = _digest(artifact, "sha1")
        verification_values.append(sha1)
        files.append(
            {
                "SPDXID": file_id,
                "fileName": artifact.name,
                "checksums": [
                    {"algorithm": "SHA256", "checksumValue": _digest(artifact, "sha256")},
                    {"algorithm": "SHA1", "checksumValue": sha1},
                ],
                "licenseConcluded": "NOASSERTION",
                "copyrightText": "NOASSERTION",
            }
        )
        relationships.append(
            {
                "spdxElementId": "SPDXRef-Package-SessionArmor",
                "relationshipType": "CONTAINS",
                "relatedSpdxElement": file_id,
            }
        )

    epoch = int(os.environ.get("SOURCE_DATE_EPOCH", "0"))
    created = datetime.fromtimestamp(epoch, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    return {
        "spdxVersion": "SPDX-2.3",
        "dataLicense": "CC0-1.0",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": f"{name}-{version}",
        "documentNamespace": (
            f"https://github.com/Tunet-xyz/session_armor/sbom/{version}/{revision}"
        ),
        "creationInfo": {
            "created": created,
            "creators": ["Tool: session-armor-sbom/1"],
        },
        "documentDescribes": ["SPDXRef-Package-SessionArmor"],
        "packages": [
            {
                "SPDXID": "SPDXRef-Package-SessionArmor",
                "name": name,
                "versionInfo": version,
                "downloadLocation": "NOASSERTION",
                "filesAnalyzed": True,
                "packageVerificationCode": {
                    "packageVerificationCodeValue": hashlib.sha1(
                        "".join(sorted(verification_values)).encode("ascii"),
                        usedforsecurity=False,
                    ).hexdigest()
                },
                "licenseConcluded": "MIT",
                "licenseDeclared": "MIT",
                "copyrightText": "NOASSERTION",
                "supplier": "Organization: Tunet Ltd",
                "externalRefs": [
                    {
                        "referenceCategory": "PACKAGE-MANAGER",
                        "referenceType": "purl",
                        "referenceLocator": f"pkg:pypi/{name.lower()}@{version}",
                    }
                ],
            }
        ],
        "files": files,
        "relationships": relationships,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path.cwd())
    parser.add_argument("--dist", type=Path, default=Path("dist"))
    parser.add_argument(
        "--output", type=Path, default=Path("release-evidence/sessionarmor.spdx.json")
    )
    args = parser.parse_args()
    sbom = generate_sbom(args.root, args.dist)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(sbom, indent=2, sort_keys=True) + "\n", encoding="utf-8", newline="\n"
    )


if __name__ == "__main__":
    main()
