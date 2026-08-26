"""
JCS canonicalization (RFC 8785) and the Impact Manifest `integrity` slot.

WHY THIS EXISTS AT ALL

JSON has no inherent byte ordering. Two conformant producers can serialize the
same logical document with different key order, whitespace, and number
formatting, and hash them to different digests. Signature verification then
fails for a reason nobody can diagnose from the failure itself, because both
documents are "the same" by every check a human would run.

The specification pins that down: the signature covers the manifest with the
`integrity` object removed, canonicalized with JCS. This module is the
implementation of that rule, and the reason it lives in blastcheck rather than
in a script somewhere is that a reference implementation which documents a
canonicalization rule it does not implement is not a reference for anything.

WHAT IS DELIBERATELY NOT HERE

No signing. The specification fixes the slot and the canonicalization rule at
v0.1 and defers a mandatory signing scheme to 1.0, with the intended layering
being standard attestation prior art (DSSE, in-toto, Sigstore). Emitting a
digest is useful on its own: it makes a manifest tamper-evident, which is most
of the practical value in a CI artifact, and it does so without inventing a key
distribution story this project has no business inventing.
"""

from __future__ import annotations

import hashlib
import json
import math
from typing import Any, Dict

__all__ = ["canonicalize", "compute_digest", "attach_integrity",
           "verify_integrity", "CanonicalizationError"]


class CanonicalizationError(ValueError):
    """A value cannot be canonicalized in a way guaranteed to match other
    conformant implementations."""


# ── Strings ──────────────────────────────────────────────────────────────────
# RFC 8785 section 3.2.2.2: the two-character escapes where they exist, \u00xx
# with LOWERCASE hex for the remaining control characters, and no escaping of
# anything else. Notably '/' and non-ASCII are emitted literally.

_SHORT_ESCAPES = {
    0x08: "\\b", 0x09: "\\t", 0x0A: "\\n", 0x0C: "\\f", 0x0D: "\\r",
    0x22: '\\"', 0x5C: "\\\\",
}


def _string(s: str) -> str:
    out = ['"']
    for ch in s:
        cp = ord(ch)
        esc = _SHORT_ESCAPES.get(cp)
        if esc is not None:
            out.append(esc)
        elif cp < 0x20:
            out.append("\\u%04x" % cp)
        else:
            out.append(ch)
    out.append('"')
    return "".join(out)


# ── Numbers ──────────────────────────────────────────────────────────────────
# RFC 8785 requires ECMAScript Number::toString. Python's repr() already gives
# the shortest round-tripping decimal, which is the hard part, but the two
# disagree on formatting at the extremes: exponent thresholds, exponent
# punctuation, and the trailing '.0' Python adds to integral floats.
#
# Rather than approximate at those extremes and emit a digest that might not
# match another implementation, values outside the range where the mapping is
# exact are refused. A loud failure is the correct behaviour for a project whose
# entire thesis is that silence about uncertainty is the dangerous failure mode.
#
# Manifests contain integers (sizes, counts) and no floats today, so this
# refusal is not expected to fire in practice. It is here so that if the format
# grows a float field, the gap surfaces as an error rather than as a digest two
# tools quietly disagree about.

_ES_FIXED_MIN = 1e-6      # below this ECMAScript switches to exponential
_ES_FIXED_MAX = 1e21      # at and above this it switches to exponential


def _number(n: Any) -> str:
    if isinstance(n, bool):                      # bool is a subclass of int
        raise CanonicalizationError("bool is not a number")
    if isinstance(n, int):
        return str(n)
    f = float(n)
    if math.isnan(f) or math.isinf(f):
        raise CanonicalizationError("NaN and Infinity are not valid JSON numbers")
    if f == 0:
        return "0"                               # canonicalizes -0.0 to "0"
    if f.is_integer() and abs(f) < _ES_FIXED_MAX:
        return str(int(f))                       # 5.0 -> "5", per ECMAScript
    if not (_ES_FIXED_MIN <= abs(f) < _ES_FIXED_MAX):
        raise CanonicalizationError(
            f"{f!r} falls outside the range where this implementation can "
            "guarantee an ECMAScript-identical serialization. Refusing rather "
            "than emitting a digest another conformant producer may not match."
        )
    text = repr(f)
    if "e" in text or "E" in text:               # repr disagrees with ES here
        raise CanonicalizationError(
            f"{f!r} serializes to exponential notation in Python but not in "
            "ECMAScript. Refusing rather than guessing."
        )
    return text


# ── Structure ────────────────────────────────────────────────────────────────

def _sort_key(key: str) -> bytes:
    """RFC 8785 sorts object keys by their UTF-16 code units, not by Unicode
    code point. The two orderings differ for characters above the BMP, because
    those become surrogate pairs in UTF-16 and surrogates sort below U+E000.
    Encoding to UTF-16BE and comparing bytes reproduces the required order."""
    return key.encode("utf-16-be")


def _serialize(value: Any) -> str:
    if value is None:
        return "null"
    if value is True:
        return "true"
    if value is False:
        return "false"
    if isinstance(value, str):
        return _string(value)
    if isinstance(value, (int, float)):
        return _number(value)
    if isinstance(value, dict):
        for k in value:
            if not isinstance(k, str):
                raise CanonicalizationError(f"object key must be a string, got {type(k).__name__}")
        items = sorted(value.items(), key=lambda kv: _sort_key(kv[0]))
        return "{" + ",".join(f"{_string(k)}:{_serialize(v)}" for k, v in items) + "}"
    if isinstance(value, (list, tuple)):
        # Array order is data, never sorted.
        return "[" + ",".join(_serialize(v) for v in value) + "]"
    raise CanonicalizationError(f"cannot canonicalize {type(value).__name__}")


def canonicalize(value: Any) -> bytes:
    """Return the RFC 8785 canonical UTF-8 serialization of `value`."""
    return _serialize(value).encode("utf-8")


# ── The integrity slot ───────────────────────────────────────────────────────

def _payload(manifest: Dict[str, Any]) -> Dict[str, Any]:
    """The signed payload: the manifest with `integrity` removed. A signature
    cannot cover itself, so the slot is excluded by construction rather than by
    asking the caller to remember."""
    return {k: v for k, v in manifest.items() if k != "integrity"}


def compute_digest(manifest: Dict[str, Any], algorithm: str = "sha256") -> Dict[str, str]:
    """Digest the canonicalized payload. Returns the schema's `digest` object."""
    try:
        h = hashlib.new(algorithm)
    except ValueError:
        raise CanonicalizationError(f"unsupported hash algorithm: {algorithm}")
    h.update(canonicalize(_payload(manifest)))
    return {"algorithm": algorithm, "value": h.hexdigest()}


def attach_integrity(manifest: Dict[str, Any], algorithm: str = "sha256") -> Dict[str, Any]:
    """Return the manifest with an `integrity.digest` attached. No signature:
    the specification defers a mandatory signing scheme, and a digest alone
    already makes the document tamper-evident."""
    out = dict(manifest)
    out["integrity"] = {"digest": compute_digest(manifest, algorithm)}
    return out


def verify_integrity(manifest: Dict[str, Any]) -> bool:
    """Recompute the digest the way a verifier must: delete `integrity`, apply
    JCS, hash, compare. False if there is no digest to check, so a caller can
    never read 'nothing to verify' as 'verified'."""
    recorded = (manifest.get("integrity") or {}).get("digest")
    if not recorded or "algorithm" not in recorded or "value" not in recorded:
        return False
    try:
        computed = compute_digest(manifest, recorded["algorithm"])
    except CanonicalizationError:
        return False
    # Constant-time compare: a manifest's digest is an integrity claim someone
    # may be probing.
    import hmac
    return hmac.compare_digest(computed["value"], str(recorded["value"]))
