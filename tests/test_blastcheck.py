"""
blastcheck tests. The primary job of this suite is the reason Part 2 exists:
prove that blastcheck emits Impact Manifests that VALIDATE against the schema,
on realistic `terraform show -json` data. The verdict assertions are secondary —
they check the reasoning is defensible, not just well-formed.

If a manifest fails schema validation here, that is exactly the signal we want:
either blastcheck is wrong, or the schema is wrong against real plan shapes.
"""
import json
import pathlib
from datetime import datetime, timezone

import pytest
from jsonschema import Draft202012Validator

from blastcheck.core import build_manifest, load_plan, PlanError, _action
from blastcheck import schema_path

ROOT = pathlib.Path(__file__).resolve().parent.parent
SCHEMA = json.loads(schema_path().read_text())
FIXTURES = ROOT / "tests" / "fixtures"
NOW = datetime(2026, 8, 26, 16, 0, 0, tzinfo=timezone.utc)  # fixed for determinism

Draft202012Validator.check_schema(SCHEMA)
VALIDATOR = Draft202012Validator(SCHEMA)


def _manifest(fixture):
    plan = load_plan((FIXTURES / fixture).read_text())
    return build_manifest(plan, now=NOW)


def _change(manifest, addr):
    return next(c for c in manifest["changes"] if c["address"] == addr)


# ── The point of this phase: every output validates against the schema ───────

@pytest.mark.parametrize("fixture", sorted(p.name for p in FIXTURES.glob("*.json")))
def test_output_validates_against_schema(fixture):
    manifest = _manifest(fixture)
    errors = sorted(VALIDATOR.iter_errors(manifest), key=str)
    assert not errors, "\n".join(f"{list(e.path)}: {e.message}" for e in errors[:8])


# ── Verdict reasoning is defensible ──────────────────────────────────────────

def test_data_bearing_delete_is_not_certifiable():
    """Deleting a disk offline: recoverability is unknown, so the change is not
    certifiable and the plan verdict must not be safe."""
    m = _manifest("disk-delete.json")
    ch = _change(m, "azurerm_managed_disk.data")
    assert ch["data_durability"]["value"] == "unknown"
    assert ch["severity"] == "unknown"
    assert m["verdict"]["decision"] in ("unknown", "blocked")
    assert m["verdict"]["unknowns_present"] is True


def test_disk_grow_is_irreversible_from_plan_alone():
    """A managed-disk grow is irreversible (Azure can't shrink) — derivable from
    the plan without any live state. Note the change is still `unknown` overall,
    not `caution`: a grow can require deallocating the attached VM, so the
    availability impact genuinely can't be determined offline. Two honest facts
    at once — a plan-visible irreversibility and a live-only availability gap."""
    m = _manifest("disk-grow.json")
    ch = _change(m, "azurerm_managed_disk.sql")
    assert ch["reversibility"]["value"] == "irreversible"
    assert "cannot be shrunk" in ch["reversibility"]["cost"]
    assert ch["availability_impact"]["value"] == "unknown"
    assert ch["severity"] == "unknown"


def test_disk_grow_with_computed_size_is_unknown_not_reversible():
    """REGRESSION. The disk size is frequently a variable or a computed value,
    in which case Terraform puts it in `after_unknown` and leaves `after` null.
    Reading `after` alone made this look like "no size change" and returned
    `reversible` at high confidence — an affirmative wrong answer about the one
    irreversibility this tool claims to catch. An unreadable field must produce
    `unknown`, never a fall-through to the benign value."""
    m = _manifest("disk-grow-computed.json")
    ch = _change(m, "azurerm_managed_disk.data")
    assert ch["reversibility"]["value"] == "unknown"
    assert "after_unknown" in ch["reversibility"]["rationale"]
    assert ch["cost_delta"]["direction"] == "unknown"
    assert m["verdict"]["decision"] != "safe"


def test_inline_nsg_rule_opening_rdp_widens_security():
    """REGRESSION. Azure lets the same rule be written as a standalone
    `azurerm_network_security_rule` resource OR as an inline `security_rule`
    block on the NSG. Only the first was inspected, so an NSG update opening
    RDP to 0.0.0.0/0 inline reported `unchanged`."""
    m = _manifest("nsg-inline-rule-open.json")
    ch = _change(m, "azurerm_network_security_group.web")
    assert ch["security_posture"]["value"] == "widened"
    assert any("rdp" in c["detail"] for c in ch["security_posture"]["concerns"])
    assert ch["severity"] == "blocking"
    assert m["verdict"]["decision"] == "blocked"


def test_preexisting_open_inline_rule_is_not_flagged_as_new():
    """The 443 rule in that fixture was already open before the change. Only
    NEWLY opened rules are this plan's doing; flagging pre-existing ones would
    make every subsequent NSG edit look like a fresh exposure."""
    m = _manifest("nsg-inline-rule-open.json")
    concerns = _change(m, "azurerm_network_security_group.web")["security_posture"]["concerns"]
    assert len(concerns) == 1
    assert "https" not in concerns[0]["detail"]


def test_storage_firewall_default_deny_to_allow_widens_security():
    """A firewall flipping default_action Deny -> Allow exposes the account as
    effectively as the public-access flag."""
    m = _manifest("storage-firewall-opened.json")
    ch = _change(m, "azurerm_storage_account.data")
    assert ch["security_posture"]["value"] == "widened"
    assert any("default_action" in c["detail"] for c in ch["security_posture"]["concerns"])


def test_redacted_field_is_unknown_not_unchanged():
    """`after_sensitive` redacts a value the same way `after_unknown` withholds
    one: `after` is null either way. A redacted security-relevant field must not
    read as 'no change found'."""
    plan = load_plan(json.dumps({"format_version": "1.2", "resource_changes": [
        {"address": "azurerm_storage_account.s", "type": "azurerm_storage_account", "name": "s",
         "change": {"actions": ["update"],
                    "before": {"public_network_access_enabled": False},
                    "after": {"public_network_access_enabled": None},
                    "after_sensitive": {"public_network_access_enabled": True}}}
    ]}))
    m = build_manifest(plan, now=NOW)
    ch = _change(m, "azurerm_storage_account.s")
    assert ch["security_posture"]["value"] == "unknown"
    assert "redacted" in ch["security_posture"]["rationale"]


def test_open_inbound_rule_widens_security_and_blocks():
    m = _manifest("nsg-rule-open.json")
    ch = _change(m, "azurerm_network_security_rule.rdp")
    assert ch["security_posture"]["value"] == "widened"
    assert any(c["kind"] == "exposure" for c in ch["security_posture"]["concerns"])
    assert ch["severity"] == "blocking"
    assert m["verdict"]["decision"] == "blocked"


def test_public_storage_account_widens_security():
    m = _manifest("storage-public.json")
    ch = _change(m, "azurerm_storage_account.archive")
    assert ch["security_posture"]["value"] == "widened"


def test_benign_create_is_caution_not_safe_offline():
    """Even a benign NSG create cannot be `safe` from a plan alone: state was
    never verified. blastcheck must say `caution`, never `safe`."""
    m = _manifest("nsg-create.json")
    ch = _change(m, "azurerm_network_security_group.web")
    assert ch["severity"] == "informational"
    assert m["verdict"]["decision"] == "caution"


def test_blastcheck_never_emits_safe_offline():
    """Structural guarantee of a plan-only producer: no fixture yields `safe`."""
    for fixture in FIXTURES.glob("*.json"):
        assert build_manifest(load_plan(fixture.read_text()), now=NOW)["verdict"]["decision"] != "safe"


def test_state_confidence_always_not_verified_offline():
    m = _manifest("disk-grow.json")
    assert _change(m, "azurerm_managed_disk.sql")["state_confidence"]["value"] == "not_verified"


def test_every_change_is_assessed_even_without_a_precise_rule():
    """Nothing is skipped for being an unfamiliar type any more. A real 55-change
    AWS plan used to produce 'no supported resource changes found' with every
    test in this file passing, which is the failure mode this replaced."""
    m = _manifest("mixed-with-unsupported.json")
    addrs = sorted(c["address"] for c in m["changes"])
    assert addrs == ["azurerm_managed_disk.data", "azurerm_resource_group.rg"]
    # The manifest still says HOW each verdict was reached.
    depth = m["extensions"]["assessment"]
    assert depth["azurerm_managed_disk.data"] == "precise"
    assert depth["azurerm_resource_group.rg"] == "structural"
    assert "skipped" not in m.get("extensions", {})


def test_replace_actions_carried_verbatim():
    m = _manifest("replace.json")
    ch = _change(m, "azurerm_storage_account.s")
    assert ch["actions"] == ["delete", "create"]  # verbatim, not collapsed
    assert _action(["delete", "create"]) == "replace"  # internal reduction


# ── Error handling ───────────────────────────────────────────────────────────

def test_non_json_input_raises():
    with pytest.raises(PlanError):
        load_plan("not json")


def test_missing_resource_changes_raises():
    with pytest.raises(PlanError):
        load_plan(json.dumps({"format_version": "1.2"}))


def test_a_plan_of_only_unfamiliar_types_still_produces_a_manifest():
    """The old behaviour was to raise. That made blastcheck useless on any plan
    outside its narrow type list, which is most real plans."""
    plan = load_plan(json.dumps({"resource_changes": [
        {"address": "azurerm_resource_group.a", "type": "azurerm_resource_group",
         "name": "a", "change": {"actions": ["create"], "before": None, "after": {}}}
    ]}))
    m = build_manifest(plan, now=NOW)
    assert len(m["changes"]) == 1
    assert not sorted(VALIDATOR.iter_errors(m), key=str)


def test_a_plan_with_nothing_mutating_still_raises():
    """A plan of pure no-ops and data reads genuinely has nothing to assess."""
    plan = load_plan(json.dumps({"resource_changes": [
        {"address": "azurerm_resource_group.a", "type": "azurerm_resource_group",
         "name": "a", "change": {"actions": ["no-op"], "before": {}, "after": {}}}
    ]}))
    with pytest.raises(PlanError):
        build_manifest(plan, now=NOW)


# ── Drift, read from Terraform's own refresh ─────────────────────────────────

def test_drift_on_a_planned_resource_blocks():
    """The outage shape. `terraform plan` refreshes by default and records what
    it found in `resource_drift`. A resource in BOTH resource_drift and
    resource_changes means the plan is about to modify something that had
    already moved out from under it — internally consistent, reads as routine,
    and computed against a description that stopped being true."""
    m = _manifest("drift-on-planned-resource.json")
    ch = _change(m, "azurerm_managed_disk.sql_data")
    assert ch["state_confidence"]["value"] == "drift_detected"
    assert ch["state_confidence"]["verified_against_live"] is True
    assert ch["state_confidence"]["confidence"] == "high"
    assert ch["severity"] == "blocking"
    assert m["verdict"]["decision"] == "blocked"
    assert "drifted" in m["verdict"]["rationale"]


def test_drift_evidence_names_the_values_and_its_origin():
    """A reader must be able to see WHAT moved, and know the live read was
    Terraform's, not blastcheck's."""
    m = _manifest("drift-on-planned-resource.json")
    live = [e for e in m["evidence"] if e["source"] == "live_state"]
    assert len(live) == 1
    assert "512" in live[0]["observation"] and "1024" in live[0]["observation"]
    assert "resource_drift" in live[0]["query"]
    # blastcheck itself still never queried anything.
    assert m["producer"]["access"]["live_state"] == "not_attempted"


def test_undrifted_resource_in_a_drifted_plan_stays_not_verified():
    """Drift on one resource says nothing about another. Absence of a drift
    entry is ambiguous — refresh may have found nothing, or may not have run."""
    m = _manifest("drift-on-planned-resource.json")
    ch = _change(m, "azurerm_network_security_group.clean")
    assert ch["state_confidence"]["value"] == "not_verified"
    assert ch["severity"] == "informational"


def test_drift_outside_the_plan_is_recorded_not_dropped():
    """A drifted resource this plan does not touch gets no changes[] entry —
    it is not a change — but the reader should still learn the estate moved."""
    m = _manifest("drift-on-planned-resource.json")
    assert m["extensions"]["drift_outside_this_plan"] == ["azurerm_storage_account.untouched"]
    assert all(c["address"] != "azurerm_storage_account.untouched" for c in m["changes"])


def test_plans_without_drift_data_are_unchanged():
    """Every pre-existing fixture has no resource_drift key at all. None of them
    may start claiming a state determination they cannot support."""
    for fixture in FIXTURES.glob("*.json"):
        if fixture.name == "drift-on-planned-resource.json":
            continue
        m = build_manifest(load_plan(fixture.read_text()), now=NOW)
        for c in m["changes"]:
            assert c["state_confidence"]["value"] == "not_verified"


def test_errored_and_incomplete_plans_are_flagged():
    plan = load_plan(json.dumps({
        "format_version": "1.2", "errored": True, "complete": False,
        "resource_changes": [
            {"address": "azurerm_managed_disk.d", "type": "azurerm_managed_disk", "name": "d",
             "change": {"actions": ["delete"], "before": {"disk_size_gb": 100}, "after": None}}
        ]}))
    m = build_manifest(plan, now=NOW)
    assert m["extensions"]["plan_errored"] is True
    assert m["extensions"]["plan_incomplete"] is True


# ── Layer 0 and Layer 1: providers with no precise rules ─────────────────────

def test_aws_and_gcp_are_assessed_without_provider_rules():
    """blastcheck has no AWS or GCP rules at all. It must still produce useful
    output, because 'no supported resource changes found' on a real plan is a
    useless answer however correct the tool is about plans it does understand."""
    m = _manifest("aws-no-precise-rules.json")
    assert len(m["changes"]) == 8
    assert all(v != "precise" for v in m["extensions"]["assessment"].values())
    assert not sorted(VALIDATOR.iter_errors(m), key=str)


def test_heuristic_findings_are_marked_as_guesses():
    """A pattern match must be visibly a pattern match: low confidence, evidence
    tagged `heuristic`, and severity `caution` rather than `blocking`. Grading a
    guess as blocking is how a tool teaches people to ignore it."""
    m = _manifest("aws-no-precise-rules.json")
    ch = _change(m, "aws_db_instance.prod")
    sp = ch["security_posture"]
    assert sp["value"] == "widened"
    assert sp["confidence"] == "low"
    assert ch["severity"] == "caution"
    details = " ".join(c["detail"] for c in sp["concerns"])
    assert "publicly_accessible" in details
    assert "storage_encrypted" in details
    assert "skip_final_snapshot" in details
    assert any(e["source"] == "heuristic" for e in m["evidence"])


def test_public_acl_and_force_destroy_are_caught_generically():
    m = _manifest("aws-no-precise-rules.json")
    details = " ".join(c["detail"] for c in
                       _change(m, "aws_s3_bucket.public_data")["security_posture"]["concerns"])
    assert "public-read" in details and "force_destroy" in details


def test_inbound_open_cidr_flagged_outbound_and_routes_are_not():
    """The single most important precision rule in the heuristic layer. Egress to
    0.0.0.0/0 and a default route ARE 0.0.0.0/0 by definition; flagging them
    fires on nearly every plan ever written and destroys trust in the output."""
    m = _manifest("aws-no-precise-rules.json")
    assert _change(m, "aws_security_group_rule.ssh_in")["security_posture"]["value"] == "widened"
    assert _change(m, "aws_security_group_rule.all_out")["security_posture"]["value"] != "widened"
    assert _change(m, "aws_route.default")["security_posture"]["value"] != "widened"


def test_data_bearing_inferred_from_type_name():
    """`aws_dynamodb_table` holds data; `aws_route_table` does not, despite both
    ending in _table. An unanchored pattern gets this wrong."""
    m = _manifest("aws-no-precise-rules.json")
    dynamo = _change(m, "aws_dynamodb_table.sessions")["data_durability"]
    assert dynamo["value"] == "unknown"
    assert "at_risk" in dynamo
    rtb = _change(m, "aws_route_table.public")["data_durability"]
    assert rtb["value"] == "unknown"      # a delete is never assumed benign
    assert "at_risk" not in rtb           # but it is not claimed to hold data


def test_deletion_protection_removal_is_caught_on_a_third_provider():
    """No Google rules exist either. The pattern is the attribute name."""
    m = _manifest("aws-no-precise-rules.json")
    details = " ".join(c["detail"] for c in
                       _change(m, "google_sql_database_instance.main")["security_posture"]["concerns"])
    assert "deletion_protection" in details
