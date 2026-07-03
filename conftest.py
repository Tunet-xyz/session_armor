import os
import sys
from pathlib import Path

# Ensure repo root is on sys.path so 'tests.settings' is importable
repo_root = str(Path(__file__).resolve().parent)
if repo_root not in sys.path:
    sys.path.insert(0, repo_root)

import django  # noqa: E402


def pytest_configure():
    os.environ.setdefault("DJANGO_SETTINGS_MODULE", "tests.settings")
    django.setup()
