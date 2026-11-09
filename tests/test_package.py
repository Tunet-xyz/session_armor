import subprocess
import sys
from pathlib import Path
from typing import get_type_hints

from django.http.response import HttpResponseBase

from session_armor import GateDecision, SessionAssurance
from session_armor.adapters.django import (
    AuditMiddleware,
    GateMiddleware,
    SessionSecurityMiddleware,
)


def test_django_hooks_declare_their_response_contracts():
    assert get_type_hints(GateMiddleware.on_reject)["return"] is HttpResponseBase
    assert get_type_hints(SessionSecurityMiddleware.on_violation)["return"] == (
        HttpResponseBase | None
    )
    for middleware in (AuditMiddleware, GateMiddleware, SessionSecurityMiddleware):
        assert get_type_hints(middleware.__call__)["return"] is HttpResponseBase


def test_public_api_separates_core_contracts_from_django_adapter():
    assert GateDecision.__module__ == "session_armor.decisions"
    assert SessionAssurance.__module__ == "session_armor.assurance"
    assert AuditMiddleware.__module__ == "session_armor.adapters.django.audit"
    assert GateMiddleware.__module__ == "session_armor.adapters.django.gate"
    assert SessionSecurityMiddleware.__module__ == "session_armor.adapters.django.session"


def test_core_import_does_not_require_django():
    source = Path(__file__).resolve().parents[1] / "src"
    script = f"""
import builtins
import sys
sys.path.insert(0, {str(source)!r})
original_import = builtins.__import__
def guarded_import(name, *args, **kwargs):
    if name == 'django' or name.startswith('django.'):
        raise AssertionError('SessionArmor core imported Django')
    return original_import(name, *args, **kwargs)
builtins.__import__ = guarded_import
from session_armor import GateDecision, SessionAssurance
assert GateDecision.allow().passed
assert SessionAssurance.unverified('test').trusted is False
"""
    subprocess.run([sys.executable, "-c", script], check=True)
