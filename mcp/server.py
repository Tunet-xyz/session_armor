"""Run the packaged SessionArmor MCP server from a source checkout."""

from __future__ import annotations

import sys
from pathlib import Path

SOURCE_ROOT = Path(__file__).resolve().parents[1] / "src"
sys.path.insert(0, str(SOURCE_ROOT))

from session_armor.mcp.server import main  # noqa: E402

if __name__ == "__main__":
    main()
