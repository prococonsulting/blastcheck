"""
Provider packs: Layer 2 knowledge as data.

The point of a pack is that someone who knows a provider can add real precision
without reading the analyzers. So these tests care about two things: that a pack
actually raises confidence above the heuristic layer, and that a malformed or
hostile pack cannot break a run.
"""
import json
import pathlib

import pytest

from blastcheck.core import PACK, build_manifest, load_plan
from blastcheck.packs import load_packs, pack_dir


def test_shipped_packs_all_parse():
    p = load_packs()
    assert not p.errors, p.errors
    assert {"aws", "azurerm"} <= set(p.providers)
    assert len(p.precise) > 100


def test_a_malformed_pack_is_skipped_not_fatal(tmp_path):
    """One bad contributed file must not stop the tool from running. It is
    recorded so the failure is visible rather than silent."""
    (tmp_path / "good.json").write_text(json.dumps({"provider": "x", "stateless": ["x_thing"]}))
    (tmp_path / "broken.json").write_text("{not json")
    (tmp_path / "wrong-shape.json").write_text('["a list, not an object"]')
    p = load_packs(tmp_path)
    assert "x_thing" in p.stateless          # the good one still loaded
    assert len(p.errors) == 2
    assert any("broken.json" in e for e in p.errors)


def test_pack_classification_beats_the_name_heuristic():
    """`aws_ecr_repository` holds images. The heuristic would guess that from
    the name; the pack asserts it. The difference shows up as confidence."""
    assert PACK.classify("aws_ecr_repository") == "data_bearing"
    assert PACK.classify("aws_route_table") == "stateless"
    assert PACK.classify("azurerm_kubernetes_cluster") == "compute"
    assert PACK.classify("oci_something_unknown") is None


def test_exposure_rules_compare_against_the_before_state():
    """A bucket that was already public is not made public by this plan."""
    already = PACK.exposure_findings("aws_s3_bucket",
                                     {"acl": "public-read"}, {"acl": "public-read-write"})
    newly = PACK.exposure_findings("aws_s3_bucket", {"acl": "private"}, {"acl": "public-read"})
    assert not already      # value changed but it was public before and after
    assert newly


def test_one_way_growth_is_pack_driven_not_disk_specific():
    """An EBS volume grow is one-way for the same reason an Azure disk grow is.
    Neither fact belongs in code."""
    plan = load_plan(json.dumps({"format_version": "1.2", "resource_changes": [
        {"address": "aws_ebs_volume.data", "type": "aws_ebs_volume", "name": "data",
         "change": {"actions": ["update"], "before": {"size": 100}, "after": {"size": 500}}}
    ]}))
    ch = build_manifest(plan)["changes"][0]
    assert ch["reversibility"]["value"] == "irreversible"
    assert "never shrunk" in ch["reversibility"]["rationale"]


def test_a_pack_can_be_added_without_touching_code(tmp_path):
    """The actual contract with a contributor: drop in a JSON file, get
    precision. No Python, no analyzer changes."""
    (tmp_path / "oci.json").write_text(json.dumps({
        "provider": "oci",
        "data_bearing": ["oci_core_volume"],
        "one_way_growth": {"oci_core_volume": {"size_in_gbs": "an OCI block volume cannot be shrunk"}},
        "exposure": {"oci_objectstorage_bucket": [
            {"attribute": "access_type", "when_value": "ObjectRead", "kind": "exposure",
             "detail": "bucket contents are publicly readable"}]},
    }))
    p = load_packs(tmp_path)
    assert p.classify("oci_core_volume") == "data_bearing"
    assert "size_in_gbs" in p.one_way_attribute("oci_core_volume")
    hits = p.exposure_findings("oci_objectstorage_bucket",
                               {"access_type": "NoPublicAccess"}, {"access_type": "ObjectRead"})
    assert hits and hits[0]["kind"] == "exposure"


def test_packs_ship_inside_the_package():
    """Same failure mode as the schema in 0.1.0: a pack directory outside the
    package would not travel with a pip install."""
    d = pack_dir()
    assert d.is_dir() and list(d.glob("*.json"))
    assert d.parent.name == "blastcheck"
