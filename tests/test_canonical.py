"""
Tests for JCS canonicalization (RFC 8785) and the integrity slot.

The property under test is not "the bytes look right." It is that two producers
serializing the same logical manifest arrive at the same digest, and that a
manifest whose verdict has been edited fails to verify. Those two facts are the
entire commercial argument for signing a manifest at all.
"""
import json
import pathlib

import pytest
from jsonschema import Draft202012Validator

from blastcheck.canonical import (
    CanonicalizationError, attach_integrity, canonicalize, compute_digest,
    verify_integrity,
)
from blastcheck.core import build_manifest, load_plan

ROOT = pathlib.Path(__file__).resolve().parent.parent
SCHEMA = json.loads((ROOT / "schema" / "impact-manifest.schema.json").read_text())
VALIDATOR = Draft202012Validator(SCHEMA)
FIXTURES = ROOT / "tests" / "fixtures"


@pytest.mark.parametrize("value,expected", [
    ({"b": 1, "a": 2},      b'{"a":2,"b":1}'),          # keys sorted
    ({"a": [3, 1, 2]},      b'{"a":[3,1,2]}'),          # arrays keep order
    ({"x": 5.0},            b'{"x":5}'),                # integral float -> int
    ({"x": -0.0},           b'{"x":0}'),                # negative zero folded
    ({"t": True, "n": None}, b'{"n":null,"t":true}'),
    ({"s": "a\"b\\c\nd"},   b'{"s":"a\\"b\\\\c\\nd"}'), # short escapes
    ({"s": ""},       b'{"s":"\\u001f"}'),        # lowercase hex
    ({"s": "é"},      "{\"s\":\"é\"}".encode()),  # non-ASCII literal
    ({"s": "a/b"},          b'{"s":"a/b"}'),            # solidus not escaped
])
def test_rfc8785_serialization(value, expected):
    assert canonicalize(value) == expected


def test_keys_sort_by_utf16_not_codepoint():
    """RFC 8785 sorts by UTF-16 code units. An astral character becomes a
    surrogate pair, which sorts BELOW U+E000 — the opposite of code-point
    order. Getting this wrong produces digests that differ only for documents
    containing emoji, which is the worst possible bug to debug."""
    out = canonicalize({"\U0001F600": 1, "": 2}).decode()
    assert out.index("\U0001F600") < out.index("")


def test_refuses_values_it_cannot_guarantee():
    """Loud failure over a digest another implementation might not match."""
    for bad in (float("nan"), float("inf"), 1e-30, 1e30):
        with pytest.raises(CanonicalizationError):
            canonicalize({"x": bad})


def _manifest(fixture="nsg-rule-open.json"):
    return build_manifest(load_plan((FIXTURES / fixture).read_text()))


def test_digest_is_key_order_invariant():
    """The whole point: reordering keys must not change the digest."""
    m = _manifest()
    reordered = {k: m[k] for k in reversed(list(m))}
    assert compute_digest(m) == compute_digest(reordered)


def test_sign_and_verify_round_trip():
    signed = attach_integrity(_manifest())
    assert verify_integrity(signed)


def test_tampering_with_the_verdict_is_detected():
    """Editing a manifest to read `safe` is the attack this exists to stop."""
    signed = attach_integrity(_manifest())
    tampered = json.loads(json.dumps(signed))
    tampered["verdict"]["decision"] = "safe"
    assert not verify_integrity(tampered)


def test_unsigned_manifest_does_not_verify():
    """A missing digest must never read as 'verified' — same rule as `unknown`
    never reading as `safe`."""
    assert not verify_integrity(_manifest())


def test_signed_manifest_still_validates():
    signed = attach_integrity(_manifest())
    errors = sorted(VALIDATOR.iter_errors(signed), key=str)
    assert not errors, "\n".join(f"{list(e.path)}: {e.message}" for e in errors[:5])


@pytest.mark.parametrize("fixture", sorted(p.name for p in FIXTURES.glob("*.json")))
def test_every_fixture_signs_and_verifies(fixture):
    signed = attach_integrity(_manifest(fixture))
    assert verify_integrity(signed)
    assert not sorted(VALIDATOR.iter_errors(signed), key=str)
