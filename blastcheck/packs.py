"""
Provider packs: Layer 2 knowledge as data rather than code.

WHY DATA

Layer 2 is the precise, high-confidence layer. It was nine hardcoded Azure type
names in a Python set, which meant that adding AWS precision required reading
this codebase, understanding its analyzer structure, and being trusted with a
pull request against its logic. That is a wall between the project and the only
thing that would make it broadly useful.

Almost everything Layer 2 actually knows is declarative:

  * which resource types hold data (so a delete risks losing it)
  * which hold none (so a delete is recreatable from configuration)
  * which attributes, set to which values, widen exposure or remove a safeguard
  * which numeric attributes are one-way once increased

None of that needs code. A pack is a JSON file, so a contributor who knows a
provider well can add real precision without knowing Python and without touching
a single analyzer. What stays in code is the genuinely algorithmic: comparing
inline NSG rule lists, reading `after_unknown`, walking nested CIDR blocks.

WHY JSON AND NOT YAML

Zero runtime dependencies is a property this project keeps. YAML would cost a
parser for the convenience of nicer comments.

PACK RULES CARRY HIGH CONFIDENCE, HEURISTICS DO NOT

A pack is a claim by someone who knows the provider: `aws_db_instance` really is
data-bearing, `publicly_accessible: true` really does widen exposure. So pack
findings are `high` confidence and can be graded `blocking`, exactly like the
hand-written Azure rules they replace. Layer 1 pattern matching stays `low` and
`caution`. The distinction is the whole point of having both.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

__all__ = ["Pack", "load_packs", "pack_dir"]

_PACK_DIR = Path(__file__).resolve().parent / "packs"


def pack_dir() -> Path:
    return _PACK_DIR


class Pack:
    """The merged view of every loaded provider pack.

    Merged rather than per-provider because a plan can span providers, and the
    lookup is always by resource type — which already carries its provider as a
    prefix, so collisions are not a real concern."""

    def __init__(self) -> None:
        self.data_bearing: Set[str] = set()
        self.stateless: Set[str] = set()
        self.compute: Set[str] = set()
        # type -> [ {attribute, when, kind, detail} ]
        self.exposure: Dict[str, List[Dict[str, Any]]] = {}
        # type -> {attribute: reason} — increasing this value cannot be undone
        self.one_way_growth: Dict[str, Dict[str, str]] = {}
        self.providers: List[str] = []
        self.errors: List[str] = []

    @property
    def precise(self) -> Set[str]:
        """Types any pack says something definite about."""
        return self.data_bearing | self.stateless | self.compute | set(self.exposure)

    # ── lookups the analyzers use ────────────────────────────────────────────

    def classify(self, rtype: str) -> Optional[str]:
        if rtype in self.data_bearing:
            return "data_bearing"
        if rtype in self.stateless:
            return "stateless"
        if rtype in self.compute:
            return "compute"
        return None

    def one_way_attribute(self, rtype: str) -> Dict[str, str]:
        return self.one_way_growth.get(rtype, {})

    def exposure_findings(self, rtype: str, before: dict, after: dict) -> List[Dict[str, str]]:
        """Declarative exposure rules for this type. Each compares against the
        before-state so a pre-existing condition is never reported as something
        this change does."""
        rules = self.exposure.get(rtype)
        if not rules or not isinstance(after, dict):
            return []
        before = before if isinstance(before, dict) else {}
        out: List[Dict[str, str]] = []
        for r in rules:
            attr = r.get("attribute")
            if not attr:
                continue
            new, old = after.get(attr), before.get(attr)
            if new == old:
                continue
            hit = False
            if "when_true" in r:
                hit = new is True and old is not True
            elif "when_false" in r:
                hit = new is False and old is not False
            elif "when_value" in r:
                want = str(r["when_value"]).lower()
                hit = isinstance(new, str) and new.lower() == want and \
                    not (isinstance(old, str) and old.lower() == want)
            elif "when_contains" in r:
                want = str(r["when_contains"]).lower()
                hit = isinstance(new, str) and want in new.lower() and \
                    not (isinstance(old, str) and want in old.lower())
            elif "when_decreases" in r:
                hit = isinstance(new, str) and isinstance(old, str) and new < old
            if hit:
                out.append({"kind": r.get("kind", "exposure"),
                            "detail": r.get("detail") or f"`{attr}` changed to {new!r}"})
        return out


def _merge(pack: Pack, doc: Dict[str, Any], source: str) -> None:
    prov = str(doc.get("provider") or source)
    pack.providers.append(prov)
    for key, target in (("data_bearing", pack.data_bearing),
                        ("stateless", pack.stateless),
                        ("compute", pack.compute)):
        for t in doc.get(key) or []:
            if isinstance(t, str):
                target.add(t)
    for rtype, rules in (doc.get("exposure") or {}).items():
        if isinstance(rules, list):
            pack.exposure.setdefault(rtype, []).extend(r for r in rules if isinstance(r, dict))
    for rtype, attrs in (doc.get("one_way_growth") or {}).items():
        if isinstance(attrs, dict):
            pack.one_way_growth.setdefault(rtype, {}).update(
                {k: str(v) for k, v in attrs.items()})


def load_packs(directory: Optional[Path] = None) -> Pack:
    """Load every *.json pack. A malformed pack is recorded and skipped rather
    than raising: one bad contributed file must not stop the tool from running,
    and the manifest reports which pack failed."""
    pack = Pack()
    d = Path(directory) if directory else _PACK_DIR
    if not d.is_dir():
        return pack
    for f in sorted(d.glob("*.json")):
        try:
            doc = json.loads(f.read_text(encoding="utf-8"))
            if not isinstance(doc, dict):
                raise ValueError("pack must be a JSON object")
            _merge(pack, doc, f.stem)
        except Exception as e:
            pack.errors.append(f"{f.name}: {type(e).__name__}: {e}")
    return pack
