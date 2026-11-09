"""A release must have one identity across metadata and both MCP contracts."""

import json
import re
from pathlib import Path

import session_armor


def test_package_version_matches_release():
    root = Path(__file__).resolve().parents[1]
    version = session_armor.__version__
    assert re.search(rf'^version = "{re.escape(version)}"$', (root / "pyproject.toml").read_text(), re.M)
    packaged = root / "src/session_armor/mcp/agent-contract.json"
    assert json.loads(packaged.read_text())["server"]["version"] == version
    checkout = root / "mcp/agent-contract.json"
    if checkout.exists():
        assert checkout.read_bytes() == packaged.read_bytes()
