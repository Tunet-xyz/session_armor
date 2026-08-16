from __future__ import annotations

from pathlib import Path

from tools.generate_sbom import generate_sbom


def test_sbom_describes_exact_release_artifacts(tmp_path: Path, monkeypatch) -> None:
    dist = tmp_path / "dist"
    dist.mkdir()
    (dist / "sessionarmor-0.4.0-py3-none-any.whl").write_bytes(b"wheel")
    (dist / "sessionarmor-0.4.0.tar.gz").write_bytes(b"sdist")
    monkeypatch.setenv("GITHUB_SHA", "a" * 40)
    monkeypatch.setenv("SOURCE_DATE_EPOCH", "0")

    sbom = generate_sbom(Path(__file__).parents[1], dist)

    assert sbom["documentDescribes"] == ["SPDXRef-Package-SessionArmor"]
    assert len(sbom["files"]) == 2
    assert all(len(item["checksums"][0]["checksumValue"]) == 64 for item in sbom["files"])
