"""
Human-readable output and gating.

The renderer is a view, never a second opinion. These tests exist mostly to stop
it from becoming one — the tempting failure is to make the terminal output calmer
than the manifest, which would quietly reintroduce the exact problem this format
was written to prevent.
"""
import io
import json

import pytest

from blastcheck.core import build_manifest, load_plan
from blastcheck.render import FAIL_ON_LEVELS, gate_exit_code, render, supports_colour

DID = "/subscriptions/0/rg/providers/Microsoft.Compute/disks/d"


def _m(**kw):
    plan = load_plan(json.dumps({"format_version": "1.2", "resource_changes": [
        {"address": "azurerm_network_security_rule.rdp", "type": "azurerm_network_security_rule",
         "name": "rdp", "change": {"actions": ["create"], "before": None, "after": {
             "direction": "Inbound", "access": "Allow", "source_address_prefix": "0.0.0.0/0",
             "destination_port_range": "3389"}}},
        {"address": "azurerm_managed_disk.d", "type": "azurerm_managed_disk", "name": "d",
         "change": {"actions": ["update"], "before": {"id": DID, "disk_size_gb": 512},
                    "after": {"id": DID, "disk_size_gb": 1024}}},
    ]}))
    return build_manifest(plan, **kw)


def _text(manifest):
    return render(manifest, io.StringIO(), colour=False)


# ── The renderer must not soften the manifest ────────────────────────────────

def test_the_verdict_appears_verbatim():
    m = _m()
    out = _text(m)
    assert m["verdict"]["decision"] in out


def test_unknown_is_as_visible_as_blocked():
    """A renderer that quietly de-emphasises the unknowns has reintroduced the
    failure the format exists to prevent."""
    out = _text(_m())
    assert "BLOCKED" in out and "UNKNOWN" in out


def test_a_finding_keeps_the_manifests_own_words():
    out = _text(_m())
    assert "0.0.0.0/0" in out and "3389" in out
    assert "cannot be reduced" in out


def test_a_low_confidence_finding_is_labelled_as_a_guess():
    """A heuristic and a determination must not look identical in a terminal."""
    plan = load_plan(json.dumps({"format_version": "1.2", "resource_changes": [
        {"address": "google_sql_database_instance.m", "type": "google_sql_database_instance",
         "name": "m", "change": {"actions": ["update"],
                                 "before": {"deletion_protection": True},
                                 "after": {"deletion_protection": False}}}]}))
    out = _text(build_manifest(plan))
    assert "pattern match, not a determination" in out


def test_baseline_unknowns_are_summarised_not_repeated():
    """In a plan-only run every change carries the same three baseline unknowns.
    Printing them per change buries the real findings under identical text —
    which is exactly what the first version of this renderer did."""
    out = _text(_m())
    assert out.count("Whether this resource currently serves traffic") <= 1


def test_the_footer_says_state_was_never_verified():
    out = _text(_m())
    assert "--live" in out


def test_rendering_never_raises_on_a_sparse_manifest():
    """A consumer may hand this a manifest from another producer."""
    assert render({}, io.StringIO(), colour=False)
    assert render({"changes": [], "verdict": {"decision": "safe"}}, io.StringIO(), colour=False)


# ── Colour ───────────────────────────────────────────────────────────────────

def test_no_colour_when_not_a_terminal():
    assert supports_colour(io.StringIO()) is False


def test_no_color_env_var_is_honoured(monkeypatch):
    monkeypatch.setenv("NO_COLOR", "1")
    class Tty(io.StringIO):
        def isatty(self): return True
    assert supports_colour(Tty()) is False


def test_severity_is_never_conveyed_by_colour_alone():
    """Anyone reading a CI log without ANSI support must still see the word."""
    assert "BLOCKED" in _text(_m())


# ── Gating ───────────────────────────────────────────────────────────────────

@pytest.mark.parametrize("decision,level,expected", [
    ("blocked", "never", 0),      # the default: blastcheck stays a producer
    ("blocked", "blocked", 2),
    ("unknown", "blocked", 0),    # a threshold means what it says
    ("unknown", "unknown", 2),
    ("caution", "unknown", 0),
    ("caution", "caution", 2),
    ("safe", "caution", 0),
])
def test_fail_on_thresholds(decision, level, expected):
    assert gate_exit_code({"verdict": {"decision": decision}}, level) == expected


def test_the_default_never_fails_the_command():
    """blastcheck is a producer. What a verdict should do to a pipeline is the
    operator's policy, expressed with --fail-on, not the tool's decision."""
    assert gate_exit_code(_m(), "never") == 0


def test_gate_exit_code_is_two_not_one():
    """1 already means blastcheck could not run. A pipeline must be able to tell
    'this plan is dangerous' from 'the tool is broken'."""
    assert gate_exit_code({"verdict": {"decision": "blocked"}}, "blocked") == 2


def test_an_unrecognised_level_does_not_fail_open_or_crash():
    assert gate_exit_code({"verdict": {"decision": "blocked"}}, "nonsense") == 0
    assert "never" in FAIL_ON_LEVELS
