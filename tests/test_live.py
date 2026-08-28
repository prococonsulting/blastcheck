"""
Live-state probes.

The probes are tested through injected fakes rather than against a real cloud,
which is deliberate and not a compromise: the behaviour that matters here is what
blastcheck does with an answer, a refusal, a timeout, and a lie. A real cloud
gives you one of those on a good day and none of them on demand.

`AzureCliProber` takes its subprocess runner as a constructor argument for
exactly this reason, so every failure path below is exercised with the real
command-construction and parsing code, only the process boundary faked.
"""
import json
import pathlib

import pytest
from jsonschema import Draft202012Validator

from blastcheck import schema_path
from blastcheck.core import build_manifest, load_plan
from blastcheck.live import AzureCliProber, Observation, Prober, probe_plan, prober_for

VALIDATOR = Draft202012Validator(json.loads(schema_path().read_text()))
FIXTURES = pathlib.Path(__file__).resolve().parent / "fixtures"

DISK_ID = ("/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg"
           "/providers/Microsoft.Compute/disks/sql-data-01")


def _plan(before=None, actions=("update",), after=None, rtype="azurerm_managed_disk"):
    return load_plan(json.dumps({
        "format_version": "1.2",
        "resource_changes": [{
            "address": f"{rtype}.d", "type": rtype, "name": "d",
            "change": {"actions": list(actions),
                       "before": before if before is not None else {"id": DISK_ID, "disk_size_gb": 512},
                       "after": after if after is not None else {"id": DISK_ID, "disk_size_gb": 512},
                       "after_unknown": {}, "after_sensitive": {}},
        }],
    }))


class FakeProber(Prober):
    """Returns whatever the test tells it to."""
    name = "fake"

    def __init__(self, obs): self._obs = obs
    def available(self): return None
    def probe(self, rc): return self._obs


def _fake_az(responses):
    """A subprocess runner returning canned (returncode, stdout, stderr)."""
    def run(args, timeout):
        for match, resp in responses:
            if match in " ".join(args):
                return resp
        return (0, "{}", "")
    return run


# ── The claim that matters: `safe` is reachable, and only when earned ────────

def test_safe_requires_a_live_read_that_matched():
    """The whole point of this feature. Nothing dangerous, nothing undetermined,
    AND state verified against reality — only then."""
    obs = Observation("azurerm_managed_disk.d", found=True,
                      attributes={"id": DISK_ID, "diskSizeGB": 512, "managedBy": ""})
    m = build_manifest(_plan(after={"id": DISK_ID, "disk_size_gb": 512}),
                       observations={"azurerm_managed_disk.d": obs})
    ch = m["changes"][0]
    assert ch["state_confidence"]["value"] == "state_matches_reality"
    assert ch["state_confidence"]["verified_against_live"] is True
    assert m["verdict"]["decision"] == "safe"
    assert m["producer"]["access"]["live_state"] == "queried"
    assert not sorted(VALIDATOR.iter_errors(m), key=str)


def test_the_same_plan_without_a_live_read_is_never_safe():
    """Identical plan, no observation. This is the control for the test above:
    `safe` came from the verification, not from the plan being boring."""
    m = build_manifest(_plan(after={"id": DISK_ID, "disk_size_gb": 512}))
    assert m["changes"][0]["state_confidence"]["value"] == "not_verified"
    assert m["verdict"]["decision"] != "safe"
    assert m["producer"]["access"]["live_state"] == "not_attempted"


def test_one_unverified_change_denies_safe_for_the_whole_plan():
    """Conformance rule 5 is per-change, and the roll-up must not average it
    away: a plan is only as trustworthy as its least verified change."""
    plan = load_plan(json.dumps({"format_version": "1.2", "resource_changes": [
        {"address": "azurerm_managed_disk.a", "type": "azurerm_managed_disk", "name": "a",
         "change": {"actions": ["update"], "before": {"id": DISK_ID, "disk_size_gb": 512},
                    "after": {"id": DISK_ID, "disk_size_gb": 512}}},
        {"address": "azurerm_network_security_group.b", "type": "azurerm_network_security_group",
         "name": "b", "change": {"actions": ["create"], "before": None, "after": {"security_rule": []}}},
    ]}))
    # managedBy: "" so the disk's availability also resolves. The ONLY thing
    # left undetermined is that the NSG was never probed, which is the variable
    # under test.
    obs = {"azurerm_managed_disk.a": Observation(
        "azurerm_managed_disk.a", found=True,
        attributes={"id": DISK_ID, "diskSizeGB": 512, "managedBy": ""})}
    m = build_manifest(plan, observations=obs)
    assert m["changes"][0]["state_confidence"]["value"] == "state_matches_reality"
    assert m["verdict"]["decision"] == "caution"
    assert "not verified" in m["verdict"]["rationale"]
    assert "1 of 2" in m["verdict"]["rationale"]


# ── Drift the live read finds itself ─────────────────────────────────────────

def test_live_read_detects_drift_terraform_refresh_never_reported():
    """No `resource_drift` in this plan at all. The live read finds it anyway,
    which is the case where refresh was skipped with -refresh=false."""
    obs = Observation("azurerm_managed_disk.d", found=True,
                      attributes={"id": DISK_ID, "diskSizeGB": 1024})
    m = build_manifest(_plan(), observations={"azurerm_managed_disk.d": obs})
    ch = m["changes"][0]
    assert ch["state_confidence"]["value"] == "drift_detected"
    assert "512" in ch["state_confidence"]["rationale"]
    assert "1024" in ch["state_confidence"]["rationale"]
    assert ch["severity"] == "blocking"


def test_camel_case_and_snake_case_are_the_same_attribute():
    """Terraform writes disk_size_gb, ARM returns diskSizeGB. Comparing them
    literally would report drift on every attribute of every resource, which is
    a false-drift firehose and destroys the feature's credibility."""
    same = Observation("azurerm_managed_disk.d", found=True,
                       attributes={"id": DISK_ID, "diskSizeGB": 512})
    m = build_manifest(_plan(), observations={"azurerm_managed_disk.d": same})
    assert m["changes"][0]["state_confidence"]["value"] == "state_matches_reality"


def test_a_resource_missing_from_the_cloud_is_drift_not_absence():
    obs = Observation("azurerm_managed_disk.d", found=False)
    m = build_manifest(_plan(), observations={"azurerm_managed_disk.d": obs})
    ch = m["changes"][0]
    assert ch["state_confidence"]["value"] == "drift_detected"
    assert "does not exist" in ch["state_confidence"]["rationale"]


def test_existence_alone_is_not_a_state_match():
    """A resource that exists but shares no comparable scalar with recorded
    state has not been verified. Calling that `state_matches_reality` would be
    the exact false-safe this format exists to prevent."""
    obs = Observation("azurerm_managed_disk.d", found=True, attributes={"tags": {"a": "b"}})
    m = build_manifest(_plan(before={"disk_size_gb": 512}),
                       observations={"azurerm_managed_disk.d": obs})
    assert m["changes"][0]["state_confidence"]["value"] == "not_verified"


# ── Failure never becomes a guess ────────────────────────────────────────────

@pytest.mark.parametrize("err", [
    "the `az` CLI is not logged in",
    "the signed-in identity is not authorised to read this resource",
    "timed out after 20s",
])
def test_a_failed_probe_stays_unverified_and_says_why(err):
    obs = Observation("azurerm_managed_disk.d", error=err)
    m = build_manifest(_plan(), observations={"azurerm_managed_disk.d": obs})
    ch = m["changes"][0]
    assert ch["state_confidence"]["value"] == "not_verified"
    assert err.split()[0] in ch["state_confidence"]["rationale"] or err in ch["state_confidence"]["rationale"]
    assert m["verdict"]["decision"] != "safe"
    assert m["producer"]["access"]["live_state"] == "unavailable"


def test_asking_and_being_refused_is_not_the_same_as_not_asking():
    """`unavailable` and `not_attempted` are different facts. An `unknown` is
    only interpretable if you know whether the producer had the access to
    determine otherwise."""
    refused = build_manifest(_plan(), observations={
        "azurerm_managed_disk.d": Observation("azurerm_managed_disk.d", error="forbidden")})
    never = build_manifest(_plan())
    assert refused["producer"]["access"]["live_state"] == "unavailable"
    assert never["producer"]["access"]["live_state"] == "not_attempted"


def test_terraform_drift_still_reported_when_the_live_read_fails():
    """Losing the live read must not lose the drift Terraform already found."""
    plan = load_plan((FIXTURES / "drift-on-planned-resource.json").read_text())
    obs = {"azurerm_managed_disk.sql_data":
           Observation("azurerm_managed_disk.sql_data", error="not logged in")}
    m = build_manifest(plan, observations=obs)
    ch = next(c for c in m["changes"] if c["address"] == "azurerm_managed_disk.sql_data")
    assert ch["state_confidence"]["value"] == "drift_detected"


def test_a_prober_that_raises_does_not_take_the_run_down():
    class Exploding(Prober):
        name = "boom"
        def available(self): return None
        def probe(self, rc): raise RuntimeError("kaboom")
    obs = probe_plan(_plan(), Exploding())
    assert "kaboom" in obs["azurerm_managed_disk.d"].error
    assert not obs["azurerm_managed_disk.d"].usable


# ── Availability, from a live read ───────────────────────────────────────────

def test_an_attached_resource_is_reported_as_interrupting():
    obs = Observation("azurerm_managed_disk.d", found=True, attributes={
        "id": DISK_ID, "diskSizeGB": 512,
        "managedBy": "/subscriptions/x/resourceGroups/rg/providers/"
                     "Microsoft.Compute/virtualMachines/sql-vm-01"})
    m = build_manifest(_plan(actions=["delete"], after=None),
                       observations={"azurerm_managed_disk.d": obs})
    av = m["changes"][0]["availability_impact"]
    assert av["value"] == "interrupts"
    assert "sql-vm-01" in av["rationale"]
    assert av["serves_production_traffic"] == "unknown"   # attached != serving
    assert m["changes"][0]["severity"] == "blocking"


# ── The Azure CLI prober's own plumbing ──────────────────────────────────────

def test_azure_prober_parses_a_real_shaped_response():
    body = json.dumps({"id": DISK_ID, "name": "sql-data-01",
                       "properties": {"diskSizeGB": 512, "diskState": "Attached"}})
    p = AzureCliProber(runner=_fake_az([("resource show", (0, body, ""))]))
    o = p.probe({"address": "a", "change": {"before": {"id": DISK_ID}}})
    assert o.usable and o.found is True
    # `properties` is flattened up one level so callers see one namespace.
    assert o.attributes["diskSizeGB"] == 512
    assert o.attributes["name"] == "sql-data-01"


@pytest.mark.parametrize("stderr,expect", [
    ("ResourceNotFound: was not found", "found_false"),
    ("The client does not have authorization to perform action", "authorised"),
])
def test_azure_prober_distinguishes_missing_from_forbidden(stderr, expect):
    p = AzureCliProber(runner=_fake_az([("resource show", (1, "", stderr))]))
    o = p.probe({"address": "a", "change": {"before": {"id": DISK_ID}}})
    if expect == "found_false":
        assert o.found is False and o.error is None   # it looked, and it is gone
    else:
        assert o.found is None and "authorised" in o.error   # it could not look


def test_azure_prober_skips_resources_with_no_id():
    """A create has no prior state, so there is nothing to look up. That is
    normal, not an error condition worth alarming about."""
    p = AzureCliProber(runner=_fake_az([]))
    o = p.probe({"address": "a", "change": {"before": None}})
    assert not o.usable and "nothing to look up" in o.error


def test_timeout_is_reported_not_swallowed():
    p = AzureCliProber(runner=_fake_az([("resource show", (124, "", "timed out after 20s"))]))
    o = p.probe({"address": "a", "change": {"before": {"id": DISK_ID}}})
    assert not o.usable and "timed out" in o.error


def test_unknown_provider_is_rejected():
    with pytest.raises(ValueError):
        prober_for("gcp")


def test_no_mutating_verb_can_reach_a_command():
    """A read-only guarantee is worth having as a test, not just a comment."""
    from blastcheck.live import _READ_ONLY_VERBS
    seen = []
    def spy(args, timeout):
        seen.append(args)
        return (0, "{}", "")
    AzureCliProber(runner=spy).probe({"address": "a", "change": {"before": {"id": DISK_ID}}})
    assert seen, "the prober issued no command at all"
    for args in seen:
        assert set(args) & _READ_ONLY_VERBS, f"no read-only verb in {args}"
        assert not (set(args) & {"delete", "create", "update", "set", "remove"})


# ── Recovery points: the question a plan can never answer ────────────────────

def test_no_recovery_point_makes_a_delete_unrecoverable():
    """The whole reason to ask a cloud anything. A destroy with no snapshot is
    not `unknown`, it is permanent — and that is a determination, not a guess."""
    rec = Observation("azurerm_managed_disk.d", found=False)
    m = build_manifest(_plan(actions=["delete"], after=None),
                       recovery={"azurerm_managed_disk.d": rec})
    ch = m["changes"][0]
    assert ch["reversibility"]["value"] == "irreversible"
    assert ch["data_durability"]["value"] == "unrecoverable_loss"
    assert ch["data_durability"]["confidence"] == "high"
    assert ch["severity"] == "blocking"
    assert m["verdict"]["decision"] == "blocked"


def test_a_recovery_point_makes_it_recoverable_but_not_free():
    """`reversible_with_data_loss`, not `reversible`. Restoring a 14-hour-old
    snapshot is technically reversible and operationally a disaster, and the
    format has a distinct value for exactly that."""
    rec = Observation("azurerm_managed_disk.d", found=True,
                      attributes={"count": 3, "snapshots": [{"name": "snap-nightly"}]})
    m = build_manifest(_plan(actions=["delete"], after=None),
                       recovery={"azurerm_managed_disk.d": rec})
    ch = m["changes"][0]
    assert ch["reversibility"]["value"] == "reversible_with_data_loss"
    assert "snap-nightly" in ch["reversibility"]["rationale"]
    assert ch["data_durability"]["value"] == "recoverable_loss"


def test_an_unchecked_recovery_lookup_never_reads_as_no_backup():
    """The dangerous confusion. 'I did not look' must not become 'there is no
    backup', which would turn an unimplemented lookup into a false alarm on
    every resource."""
    rec = Observation("azurerm_managed_disk.d",
                      error="no generic recovery-point lookup exists for `azurerm_managed_disk`")
    m = build_manifest(_plan(actions=["delete"], after=None),
                       recovery={"azurerm_managed_disk.d": rec})
    ch = m["changes"][0]
    assert ch["data_durability"]["value"] == "unknown"
    assert ch["reversibility"]["value"] == "unknown"


def test_recovery_is_only_probed_for_destructive_changes():
    """Asking whether a backup exists for a resource being created is wasted API
    calls and a slower pipeline for no information."""
    from blastcheck.live import probe_recovery_plan
    asked = []
    class Spy(Prober):
        name = "spy"
        def available(self): return None
        def probe_recovery(self, rc):
            asked.append(rc["address"])
            return Observation(rc["address"], found=False)
    plan = load_plan(json.dumps({"format_version": "1.2", "resource_changes": [
        {"address": "a.create", "type": "azurerm_managed_disk", "name": "c",
         "change": {"actions": ["create"], "before": None, "after": {}}},
        {"address": "a.destroy", "type": "azurerm_managed_disk", "name": "d",
         "change": {"actions": ["delete"], "before": {"id": DISK_ID}, "after": None}},
    ]}))
    probe_recovery_plan(plan, Spy())
    assert asked == ["a.destroy"]


def test_base_prober_reports_recovery_as_unimplemented_not_absent():
    o = Prober().probe_recovery({"address": "x"})
    assert not o.usable and "not implemented" in o.error


def test_azure_recovery_finds_snapshots_by_source_id():
    snaps = json.dumps([{"name": "snap-1", "time": "2026-08-01T00:00:00Z"}])
    p = AzureCliProber(runner=_fake_az([("snapshot list", (0, snaps, ""))]))
    o = p.probe_recovery({"address": "a", "type": "azurerm_managed_disk",
                          "change": {"before": {"id": DISK_ID}}})
    assert o.usable and o.found is True and o.attributes["count"] == 1


def test_azure_recovery_declines_types_it_cannot_query_generically():
    """Recovery Services vaults need the vault and resource group as inputs.
    Saying so is better than implying no backup exists."""
    p = AzureCliProber(runner=_fake_az([]))
    o = p.probe_recovery({"address": "a", "type": "azurerm_mssql_database",
                          "change": {"before": {"id": "x"}}})
    assert not o.usable and "no generic recovery-point lookup" in o.error


# ── The AWS prober ───────────────────────────────────────────────────────────

def test_aws_prober_parses_cloud_control_properties():
    """Cloud Control returns Properties as a JSON *string* inside the response,
    which is easy to miss and yields an empty attribute set if you do."""
    from blastcheck.live import AwsCliProber
    body = json.dumps({"ResourceDescription": {
        "Identifier": "my-bucket",
        "Properties": json.dumps({"BucketName": "my-bucket", "VersioningConfiguration": {}})}})
    p = AwsCliProber(runner=_fake_az([("cloudcontrol", (0, body, ""))]))
    o = p.probe({"address": "a", "type": "aws_s3_bucket",
                 "change": {"before": {"id": "my-bucket"}}})
    assert o.usable and o.attributes["BucketName"] == "my-bucket"


def test_aws_prober_refuses_to_guess_a_cloudformation_type():
    """`aws_db_instance` is AWS::RDS::DBInstance, not AWS::Db::Instance. String
    munging would produce a confusing API error instead of a clear message."""
    from blastcheck.live import AwsCliProber
    p = AwsCliProber(runner=_fake_az([]))
    o = p.probe({"address": "a", "type": "aws_wildly_obscure_thing",
                 "change": {"before": {"id": "x"}}})
    assert not o.usable and "no Cloud Control type mapping" in o.error


def test_aws_prober_distinguishes_missing_from_denied():
    from blastcheck.live import AwsCliProber
    gone = AwsCliProber(runner=_fake_az([("cloudcontrol", (1, "", "ResourceNotFoundException"))]))
    denied = AwsCliProber(runner=_fake_az([("cloudcontrol", (1, "", "AccessDeniedException"))]))
    rc = {"address": "a", "type": "aws_s3_bucket", "change": {"before": {"id": "b"}}}
    assert gone.probe(rc).found is False
    assert denied.probe(rc).found is None and "not authorised" in denied.probe(rc).error


def test_both_probers_are_selectable():
    assert prober_for("aws").name == "aws"
    assert prober_for("azure").name == "azure"
