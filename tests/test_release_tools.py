from __future__ import annotations

import re
from pathlib import Path

import pytest

import session_armor
from tools.generate_sbom import generate_sbom


def test_sbom_describes_exact_release_artifacts(tmp_path: Path, monkeypatch) -> None:
    dist = tmp_path / "dist"
    dist.mkdir()
    (dist / "sessionarmor-0.5.0-py3-none-any.whl").write_bytes(b"wheel")
    (dist / "sessionarmor-0.5.0.tar.gz").write_bytes(b"sdist")
    monkeypatch.setenv("GITHUB_SHA", "a" * 40)
    monkeypatch.setenv("SOURCE_DATE_EPOCH", "0")

    sbom = generate_sbom(Path(__file__).parents[1], dist)

    assert sbom["documentDescribes"] == ["SPDXRef-Package-SessionArmor"]
    assert len(sbom["files"]) == 2
    assert all(len(item["checksums"][0]["checksumValue"]) == 64 for item in sbom["files"])


def test_release_build_tools_are_hash_locked() -> None:
    requirements = Path(__file__).parents[1] / "requirements"
    pins = [
        line.strip()
        for line in (requirements / "build.in").read_text().splitlines()
        if line.strip() and not line.startswith("#")
    ]
    lock = (requirements / "build.txt").read_text()

    for pin in pins:
        assert re.search(rf"^{re.escape(pin)} \\\n    --hash=sha256:[0-9a-f]{{64}}", lock, re.M), pin


def test_release_build_uses_the_locked_backend() -> None:
    root = Path(__file__).parents[1]
    if not (root / ".github").is_dir():
        pytest.skip("the release workflows are not shipped in the sdist")
    workflow = (root / ".github" / "workflows" / "publish.yaml").read_text()
    builds = re.findall(r"python -m build\b[^\n]*", workflow)
    lock = (root / "requirements" / "build.txt").read_text()
    pyproject = (root / "pyproject.toml").read_text()
    requires = re.search(r"^requires = \[(.*)\]$", pyproject, re.M)
    backend = re.findall(r'"([A-Za-z0-9_.-]+)', requires.group(1)) if requires else []

    # An isolated build installs pyproject's build requirements from PyPI, bypassing the lock.
    assert builds and all("--no-isolation" in command for command in builds), builds
    assert backend
    for name in backend:
        assert re.search(rf"^{re.escape(name)}==\S+ \\\n    --hash=sha256:", lock, re.M), name


def test_security_policy_lists_the_current_release_line() -> None:
    security = (Path(__file__).parents[1] / "SECURITY.md").read_text()
    release_line = ".".join(session_armor.__version__.split(".")[:2])

    assert re.search(rf"^\| {re.escape(release_line)}\.x .*\| :white_check_mark: \|$", security, re.M)
