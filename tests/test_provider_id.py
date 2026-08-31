"""provider_id (spec v0.2.0): opt-in emission, absence semantics, privacy.

The privacy tests are the contract of the --include-provider-ids flag:
without it, not one provider identifier reaches the output. Never weaken
them to make a change pass.

Also home of the strict-variant self-validation: the published schema is
deliberately permissive (additionalProperties: true on extensible
objects, so older consumers accept newer minors), which means it no
longer catches producer typos. A producer emits only fields it knows, so
we validate every emitted manifest against a mechanically-derived STRICT
variant of the vendored schema as well.
"""
import copy
import json
import pathlib
from datetime import datetime, timezone

import pytest
from jsonschema import Draft202012Validator

from blastcheck import schema_path
from blastcheck.cli import main
from blastcheck.core import build_manifest, load_plan

ROOT = pathlib.Path(__file__).resolve().parent.parent
FIXTURES = ROOT / "tests" / "fixtures"
NOW = datetime(2026, 8, 26, 16, 0, 0, tzinfo=timezone.utc)

SCHEMA = json.loads(schema_path().read_text())
VALIDATOR = Draft202012Validator(SCHEMA)


def _strictify(node):
    """Derive the producer self-validation variant: close every object
    except `extensions` (the one place unknown keys are legitimate)."""
    if isinstance(node, dict):
        if "properties" in node and node.get("type") == "object":
            node["additionalProperties"] = False
        for key, value in node.items():
            if key == "extensions":
                continue
            _strictify(value)
    elif isinstance(node, list):
        for item in node:
            _strictify(item)
    return node


STRICT = _strictify(copy.deepcopy(SCHEMA))
STRICT["properties"]["extensions"]["additionalProperties"] = True
Draft202012Validator.check_schema(STRICT)
STRICT_VALIDATOR = Draft202012Validator(STRICT)


def _manifest(fixture, **kwargs):
    plan = load_plan((FIXTURES / fixture).read_text())
    return build_manifest(plan, now=NOW, **kwargs)


def _change(manifest, addr):
    return next(c for c in manifest["changes"] if c["address"] == addr)


ALL_FIXTURES = sorted(p.name for p in FIXTURES.glob("*.json"))

# Every before.id value present in the fixture corpus. If any of these
# strings appears in a flag-off manifest, an identifier leaked.
FIXTURE_IDS = [
    "/subscriptions/aaaabbbb-cccc-dddd-eeee-ffff00001111",
    "i-0abc123def456",
    "opaque-12345",
]


# -- Privacy: the flag's contract ------------------------------------------

@pytest.mark.parametrize("fixture", ALL_FIXTURES)
def test_no_provider_id_without_the_flag(fixture):
    text = json.dumps(_manifest(fixture))
    assert '"provider_id"' not in text


def test_no_identifier_value_leaks_without_the_flag():
    text = json.dumps(_manifest("provider-ids.json"))
    for value in FIXTURE_IDS:
        assert value not in text, f"identifier leaked without the flag: {value}"


def test_default_output_identical_to_explicit_flag_off():
    on_default = json.dumps(_manifest("provider-ids.json"), sort_keys=True)
    explicit = json.dumps(_manifest("provider-ids.json",
                                    include_provider_ids=False), sort_keys=True)
    assert on_default == explicit


def test_cli_does_not_leak_without_flag(tmp_path, capsys):
    out = tmp_path / "manifest.json"
    src = FIXTURES / "provider-ids.json"
    import sys
    old = sys.stdout
    try:
        with open(out, "w") as f:
            sys.stdout = f
            main([str(src), "--json"])
    finally:
        sys.stdout = old
    text = out.read_text()
    assert '"provider_id"' not in text


# -- Emission under the flag -----------------------------------------------

def test_delete_and_update_carry_before_id_verbatim():
    m = _manifest("provider-ids.json", include_provider_ids=True)
    disk = _change(m, "azurerm_managed_disk.doomed")
    assert disk["provider_id"] == FIXTURE_IDS[0] + \
        "/resourceGroups/rg-data/providers/Microsoft.Compute/disks/doomed"
    web = _change(m, "aws_instance.web")
    assert web["provider_id"] == "i-0abc123def456"


def test_create_has_no_provider_id_and_no_failure_evidence():
    """Absence on a pure create is inherent (the resource does not exist
    yet), NOT a resolution failure - so no evidence entry either."""
    m = _manifest("provider-ids.json", include_provider_ids=True)
    fresh = _change(m, "azurerm_network_interface.fresh")
    assert "provider_id" not in fresh
    pid_notes = [e for e in m["evidence"]
                 if "provider id not emitted" in e.get("observation", "")
                 and "fresh" in e.get("query", "")]
    assert not pid_notes


def test_existing_resource_without_id_gets_evidence_reason():
    m = _manifest("provider-ids.json", include_provider_ids=True)
    ch = _change(m, "azurerm_managed_disk.no_recorded_id")
    assert "provider_id" not in ch
    notes = [e for e in m["evidence"]
             if "provider id not emitted" in e.get("observation", "")
             and "no_recorded_id" in e.get("query", "")]
    assert len(notes) == 1
    assert "absent" in notes[0]["observation"]


def test_both_or_neither_with_provider():
    """An id whose kind is unknown is not a safe join key: no
    provider_name in the plan -> the id is withheld, with the reason."""
    m = _manifest("provider-ids.json", include_provider_ids=True)
    orphan = _change(m, "mystery_resource.orphan")
    assert "provider" not in orphan
    assert "provider_id" not in orphan
    notes = [e for e in m["evidence"]
             if "provider id not emitted" in e.get("observation", "")
             and "orphan" in e.get("query", "")]
    assert len(notes) == 1
    assert "provider_name" in notes[0]["observation"]
    for ch in m["changes"]:
        if "provider_id" in ch:
            assert "provider" in ch


# -- Version and schema conformance in both modes --------------------------

@pytest.mark.parametrize("flag", [False, True])
def test_schema_version_and_validation_both_modes(flag):
    m = _manifest("provider-ids.json", include_provider_ids=flag)
    assert m["schema_version"] == "0.2.0"
    errors = sorted(VALIDATOR.iter_errors(m), key=str)
    assert not errors, errors[0].message


@pytest.mark.parametrize("fixture", ALL_FIXTURES)
@pytest.mark.parametrize("flag", [False, True])
def test_strict_variant_self_validation(fixture, flag):
    """Producer typo canary: our own output must also pass the CLOSED
    variant of the schema, since we emit only fields we know."""
    m = _manifest(fixture, include_provider_ids=flag)
    errors = sorted(STRICT_VALIDATOR.iter_errors(m), key=str)
    assert not errors, errors[0].message


def test_strict_variant_actually_bites():
    m = _manifest("provider-ids.json")
    m["changes"][0]["provider_idd"] = "typo"
    assert list(STRICT_VALIDATOR.iter_errors(m))
    assert not list(VALIDATOR.iter_errors(m))  # permissive one ignores it
