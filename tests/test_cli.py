"""
The command-line surface: how the tool is actually met.

These test the parts a first-time user hits before they read anything — the
arguments they guess at, the file they hand over, and what happens when a config
file says to ignore something.
"""
import json
import os
import pathlib

import pytest

from blastcheck.config import Config, apply_ignores, load_config
from blastcheck.core import build_manifest, load_plan
from blastcheck.plans import PlanReadError, read_plan_text
from blastcheck.render import render_rules

PLAN = {"format_version": "1.2", "resource_changes": [
    {"address": "azurerm_network_security_rule.rdp", "type": "azurerm_network_security_rule",
     "name": "rdp", "change": {"actions": ["create"], "before": None, "after": {
         "direction": "Inbound", "access": "Allow", "source_address_prefix": "0.0.0.0/0",
         "destination_port_range": "3389"}}},
    {"address": "azurerm_managed_disk.d", "type": "azurerm_managed_disk", "name": "d",
     "change": {"actions": ["update"], "before": {"disk_size_gb": 512},
                "after": {"disk_size_gb": 1024}}},
]}


# ── Reading whatever the user hands over ─────────────────────────────────────

def test_a_json_plan_is_read_directly(tmp_path):
    p = tmp_path / "plan.json"
    p.write_text(json.dumps(PLAN))
    text, note = read_plan_text(str(p))
    assert note is None and json.loads(text)["format_version"] == "1.2"


def test_a_binary_plan_without_terraform_says_what_to_do(tmp_path, monkeypatch):
    """Being told 'no resource_changes array' because you handed over a saved
    plan is a poor first experience. The message must name the fix."""
    monkeypatch.setenv("PATH", str(tmp_path))   # no tofu, no terraform
    p = tmp_path / "tfplan"
    p.write_bytes(b"\x50\x4b\x03\x04binary terraform plan")
    with pytest.raises(PlanReadError) as e:
        read_plan_text(str(p))
    assert "terraform show -json" in str(e.value)


def test_a_missing_file_is_a_clear_error(tmp_path):
    with pytest.raises(PlanReadError) as e:
        read_plan_text(str(tmp_path / "nope.json"))
    assert "cannot read plan" in str(e.value)


# ── Config ───────────────────────────────────────────────────────────────────

def test_config_is_found_by_searching_upward(tmp_path):
    """It belongs to the repository, not to whichever subdirectory a pipeline
    happened to run from."""
    (tmp_path / ".blastcheck.json").write_text(json.dumps({"fail_on": "blocked"}))
    deep = tmp_path / "envs" / "prod"
    deep.mkdir(parents=True)
    assert load_config(deep).fail_on == "blocked"


def test_an_unreadable_config_does_not_stop_the_run(tmp_path):
    (tmp_path / ".blastcheck.json").write_text("{not json")
    c = load_config(tmp_path)
    assert c.errors and c.fail_on is None


def test_no_config_anywhere_is_not_an_error(tmp_path):
    c = load_config(tmp_path)
    assert not c and not c.errors


# ── Ignores keep the finding ─────────────────────────────────────────────────

def test_an_ignore_lowers_severity_but_keeps_the_finding():
    """A config that could make a finding VANISH would be the most effective way
    yet invented to produce a false `safe`, invisible to whoever reads the
    manifest later."""
    m = build_manifest(load_plan(json.dumps(PLAN)))
    before = [c for c in m["changes"] if c["address"] == "azurerm_network_security_rule.rdp"][0]
    assert before["severity"] == "blocking"
    concerns_before = len(before["security_posture"]["concerns"])

    m = apply_ignores(m, Config({"ignore": ["azurerm_network_security_rule.*"]}, "test"))
    after = [c for c in m["changes"] if c["address"] == "azurerm_network_security_rule.rdp"][0]
    assert after["severity"] == "informational"
    assert len(after["security_posture"]["concerns"]) == concerns_before   # untouched
    assert "Ignored by configuration" in after["rationale"]


def test_an_ignore_is_recorded_with_the_pattern_that_caused_it():
    m = apply_ignores(build_manifest(load_plan(json.dumps(PLAN))),
                      Config({"ignore": ["azurerm_network_security_rule.*"]}, "/repo/.blastcheck.json"))
    rec = m["extensions"]["ignored"]["azurerm_network_security_rule.rdp"]
    assert rec["pattern"] == "azurerm_network_security_rule.*"
    assert rec["original_severity"] == "blocking"
    assert m["extensions"]["config_source"] == "/repo/.blastcheck.json"


def test_the_verdict_is_recomputed_after_an_ignore():
    """Otherwise the summary contradicts the changes it summarises."""
    m = build_manifest(load_plan(json.dumps(PLAN)))
    assert m["verdict"]["decision"] == "blocked"
    m = apply_ignores(m, Config({"ignore": ["azurerm_network_security_rule.*"]}, "test"))
    assert m["verdict"]["decision"] != "blocked"


def test_ignoring_something_harmless_changes_nothing():
    m = build_manifest(load_plan(json.dumps(PLAN)))
    out = apply_ignores(m, Config({"ignore": ["nothing.matches.this"]}, "test"))
    assert "ignored" not in (out.get("extensions") or {})


# ── `blastcheck rules` ───────────────────────────────────────────────────────

def test_rules_reports_what_this_build_knows():
    out = render_rules(colour=False)
    assert "Provider packs" in out
    assert "aws" in out and "azurerm" in out
    assert "one-way" in out.lower()
    # The layer boundary must be explicit: an absent type is still assessed.
    assert "Nothing is" in out and "skipped" in out
