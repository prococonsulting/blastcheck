"""
blastcheck core — turn a `terraform show -json` plan into an Impact Manifest.

This is the REFERENCE producer for the Impact Manifest format. It is deliberately
OFFLINE and plan-only: it reasons from the plan artifact alone and, wherever a
verdict genuinely requires live cloud state, emits `unknown` / `not_verified`
with a stated reason rather than guessing. That honesty is the whole point —
a plan-only tool structurally cannot certify `safe` (it never verified live
state), and the manifest says so instead of pretending.

One exception to "plan-only", and it is the important one: `terraform plan`
refreshes by default, and records what that refresh found in a top-level
`resource_drift` array. That is a live-state observation sitting inside an
offline artifact. blastcheck did not perform the read, but it reads the result —
so drift IS determined, and a plan modifying an already-drifted resource is the
single highest-severity finding this tool produces.

Coverage is layered, and EVERY change is assessed:

  Layer 0  structural, works on any provider ever written. Action semantics
           (a delete is a delete), action_reason, replace_paths, drift,
           unreadable fields, plan-level errored/complete.
  Layer 1  provider-agnostic heuristics over resource-type names and attribute
           names and values. Tagged `source: heuristic`, LOW confidence, and
           graded `caution` rather than `blocking` — a guess reported as a guess.
  Layer 2  precise rules for types this tool understands exactly. Azure managed
           disks, VMs, NSGs (+ rules), storage accounts, SQL databases today.
           Where a precise rule exists it wins; a guess never overrides it.

Nothing is skipped for being unfamiliar. `extensions.assessment` records which
layer produced each verdict.

The reasoning is commented, not the syntax — every verdict rule is one a human
should be able to defend out loud.
"""

from __future__ import annotations

import json
import re
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Tuple

from .packs import load_packs

SCHEMA_VERSION = "0.1.0"
PRODUCER_VERSION = "0.5.0"

# Plan JSON format versions this tool has been exercised against. Terraform 0.12
# emitted "0.1"; 1.x emits "1.x". Reading an unrecognised major without saying so
# is the same class of mistake as reading an unreadable field as absent.
_KNOWN_FORMAT_MAJORS = {"0", "1"}

# ── Layer 2: precise rules, loaded from provider packs ───────────────────────
#
# These used to be nine hardcoded Azure type names. They are now data files, so
# a contributor who knows a provider can add real precision without reading this
# module. See packs.py for why, and blastcheck/packs/*.json for the content.
PACK = load_packs()
_DATA_BEARING = PACK.data_bearing
_STATELESS = PACK.stateless
_VM_TYPES = PACK.compute
PRECISE = PACK.precise
SUPPORTED = PRECISE  # retained name; every change is assessed regardless

# Sources that count as "the whole internet" for an inbound-allow rule.
_OPEN_SOURCES = {"*", "0.0.0.0/0", "internet", "any"}
# Ports whose exposure to the internet is a red flag on its own.
_SENSITIVE_PORTS = {"22", "3389", "*"}

# ── Layer 1: provider-agnostic heuristics ────────────────────────────────────
#
# The sets above are Layer 2: precise rules for types this tool understands
# exactly. They will never cover Terraform's provider ecosystem, and a tool that
# answers "no supported resource changes found" on a real plan is useless no
# matter how correct it is about the plans it does understand. A real 55-change
# AWS plan produced exactly that, with every unit test passing.
#
# So every change is assessed now. Where a precise rule exists it wins. Where
# none does, these patterns run against the resource TYPE NAME and the ATTRIBUTE
# names and values, which is all a plan carries and is provider-independent.
#
# Findings from this layer are tagged `source: heuristic` and carry LOW
# confidence, because that is what they are: an inference from a naming
# convention. The format has always had a `heuristic` evidence source and a
# confidence orthogonal to value, precisely so a guess can be reported as a
# guess rather than suppressed or dressed up as a determination.

# Type-name fragments suggesting a resource holds data. Word-boundary anchored:
# unanchored "table" matches `aws_route_table`, which holds nothing.
_DATA_HINTS = re.compile(
    r"(?:^|_)(disk|disks|volume|volumes|database|databases|db|rds|bucket|buckets|"
    r"blob|blobs|filesystem|efs|snapshot|snapshots|backup|backups|vault|"
    r"secret|secrets|registry|repository|repositories|dynamodb|documentdb|"
    r"elasticache|redis|cosmosdb|bigtable|datastore|warehouse|archive|"
    r"queue|topic|stream|statefile)(?:$|_)", re.I)
# Types matching a hint that demonstrably hold nothing. Routing, grouping and
# parameter objects are configuration, not storage.
_DATA_ANTIHINTS = re.compile(
    r"(?:^|_)(route_table|routing_table|subnet_group|option_group|parameter_group|"
    r"security_group|placement_group|log_group|resource_group|instance_profile|"
    r"instance_type|policy|acl|association|attachment|rule|role|binding|"
    r"membership|assignment|link|peering|endpoint|gateway)(?:$|_)", re.I)

_OPEN_CIDRS = ("0.0.0.0/0", "::/0")
# Attributes where reaching the whole internet is the normal, correct value and
# flagging it is noise. Outbound rules are open by default almost everywhere,
# and a default route is *defined* as 0.0.0.0/0. A heuristic that fires on every
# egress rule and every route table teaches people to skip the output, which
# costs more than the findings it buys.
_OPEN_CIDR_EXPECTED = re.compile(
    r"egress|outbound|destination_cidr|destination_prefix|nat_|^route$|_route$", re.I)
# Attribute names whose value flipping ON widens exposure.
_PUBLIC_ATTR = re.compile(r"public|anonymous|internet_facing|open_access", re.I)
# Attribute names whose value flipping OFF removes a protection.
_PROTECT_ATTR = re.compile(
    r"encrypt|kms|deletion_protection|purge_protection|prevent_destroy|"
    r"versioning|mfa_delete|backup_retention|require_ssl|force_ssl|https_only", re.I)
# Attribute names whose value flipping ON removes a protection (inverted sense).
_INVERTED_PROTECT_ATTR = re.compile(r"force_destroy|skip_final_snapshot|allow_forwarded", re.I)


class PlanError(ValueError):
    """The input is not a usable `terraform show -json` plan."""


# ── Plan parsing ─────────────────────────────────────────────────────────────

def load_plan(text: str) -> Dict[str, Any]:
    try:
        plan = json.loads(text)
    except (ValueError, UnicodeDecodeError) as e:
        raise PlanError(f"input is not valid JSON: {e}")
    if not isinstance(plan, dict):
        raise PlanError("plan must be a JSON object")
    if not isinstance(plan.get("resource_changes"), list):
        raise PlanError(
            "no `resource_changes` array — did you run `terraform show -json <planfile>`?"
        )
    return plan


def _action(actions: List[str]) -> str:
    """Reduce Terraform's action list to one verb for our rules. A replace is
    the pair delete+create; everything else is a single verb. (The manifest
    still carries the raw actions verbatim — this is only for our logic.)"""
    a = set(actions or [])
    if {"delete", "create"} <= a:
        return "replace"
    for verb in ("delete", "create", "update", "read", "no-op"):
        if verb in a:
            return verb
    return "no-op"


# ── Evidence helper ──────────────────────────────────────────────────────────

def _ev(evid: str, query: str, observation: str, source: str = "terraform_plan") -> Dict[str, Any]:
    return {"id": evid, "source": source, "query": query, "observation": observation}


# ── Plan-readability helpers ─────────────────────────────────────────────────
#
# A plan does not always carry the value of a field. Terraform puts anything it
# cannot resolve until apply into `after_unknown`, and redacts anything marked
# sensitive into `after_sensitive` — in both cases leaving `after` null.
#
# Reading `after` alone therefore cannot distinguish "this field is absent" from
# "this field exists and I am not allowed to see it yet". Treating the second as
# the first is how a rule silently returns a benign answer about a change it
# never actually examined. Under this format's central commitment — wrong
# loudly, not wrong quietly — an unreadable field MUST produce `unknown`, never
# a fall-through to the safe-looking value.

def _unresolved(field: str, unknown: Dict[str, Any], sensitive: Dict[str, Any]) -> Optional[str]:
    """Return a human reason if `field`'s after-value is not readable from the
    plan, else None. The reason is quoted into the rationale so a reader knows
    exactly which field defeated the check."""
    if (unknown or {}).get(field):
        return "not known until apply (Terraform reports it under `after_unknown`)"
    if (sensitive or {}).get(field):
        return "redacted in the plan (Terraform reports it under `after_sensitive`)"
    return None


def _unknown_fields(unknown: Dict[str, Any]) -> List[str]:
    """Field names the plan genuinely could not resolve. Empty containers are
    filtered out — Terraform emits `{}`/`[]` for structures it *can* resolve."""
    return sorted(k for k, v in (unknown or {}).items() if v not in (False, None, {}, [], ""))


def _looks_data_bearing(rtype: str) -> bool:
    """Layer 1 guess at whether a resource type holds data, from its name."""
    if rtype in _DATA_BEARING:
        return True
    if rtype in _STATELESS or _DATA_ANTIHINTS.search(rtype or ""):
        return False
    return bool(_DATA_HINTS.search(rtype or ""))


def _contains_open_cidr(value: Any) -> bool:
    """Does any string anywhere under this value name the whole internet?"""
    if isinstance(value, str):
        return value.strip() in _OPEN_CIDRS
    if isinstance(value, dict):
        return any(_contains_open_cidr(v) for v in value.values())
    if isinstance(value, (list, tuple)):
        return any(_contains_open_cidr(v) for v in value)
    return False


def _heuristic_exposure(action: str, before: dict, after: dict) -> List[dict]:
    """Layer 1 exposure findings, from attribute names and values alone.

    Every rule here compares against the BEFORE state where one exists, so that
    a pre-existing condition is not reported as something this change does. A
    plan that leaves a bucket exactly as public as it already was has not
    widened anything, and saying otherwise trains people to ignore the output."""
    if action not in ("create", "update", "replace") or not isinstance(after, dict):
        return []
    before = before if isinstance(before, dict) else {}
    out: List[dict] = []

    # Some resources carry their direction in an attribute rather than in the
    # attribute name (`aws_security_group_rule` has type = ingress | egress).
    # An outbound rule reaching the internet is the normal case everywhere.
    direction = ""
    for k in ("type", "direction", "traffic_direction"):
        v = after.get(k)
        if isinstance(v, str):
            direction = v.lower()
            break
    outbound = direction in ("egress", "outbound", "out")

    for key, val in after.items():
        was = before.get(key)
        if val == was:
            continue  # unchanged by this plan
        if _contains_open_cidr(val) and not _contains_open_cidr(was) \
                and not outbound and not _OPEN_CIDR_EXPECTED.search(key):
            out.append({"kind": "exposure",
                        "detail": f"`{key}` now reaches the whole internet (0.0.0.0/0 or ::/0)"})
        elif _PUBLIC_ATTR.search(key) and val is True and was is not True:
            out.append({"kind": "exposure", "detail": f"`{key}` set to true"})
        elif _PUBLIC_ATTR.search(key) and isinstance(val, str) and "public" in val.lower() \
                and not (isinstance(was, str) and "public" in was.lower()):
            out.append({"kind": "exposure", "detail": f"`{key}` set to {val!r}"})
        elif isinstance(val, str) and "public" in val.lower() and re.search(r"acl|access", key, re.I) \
                and not (isinstance(was, str) and "public" in was.lower()):
            out.append({"kind": "exposure", "detail": f"`{key}` set to {val!r}"})
        elif _PROTECT_ATTR.search(key) and val is False and was is not False:
            out.append({"kind": "identity", "detail": f"`{key}` disabled"})
        elif _INVERTED_PROTECT_ATTR.search(key) and val is True and was is not True:
            out.append({"kind": "identity", "detail": f"`{key}` enabled, removing a safeguard"})
    # A create has no before-state, so protections that are simply absent from a
    # new resource read as "off". Report them, but only the affirmative ones.
    return out[:8]


# ── Per-dimension analyzers (plan-only) ──────────────────────────────────────

def _availability(action: str, ev: List[str]) -> Dict[str, Any]:
    if action in ("create", "no-op", "read"):
        return {"value": "none", "confidence": "high",
                "rationale": "A create/no-op does not take an existing serving resource offline.",
                "evidence": ev}
    return {"value": "unknown", "confidence": "low",
            "rationale": "Whether this resource currently serves traffic requires live state, which "
                         "blastcheck did not query (plan-only). Not assumed to be safe.",
            "evidence": ev}


def _reversibility(action: str, rtype: str, before: dict, after: dict,
                   unknown: dict, sensitive: dict, ev: List[str]) -> Dict[str, Any]:
    if action == "create":
        return {"value": "reversible", "mechanism": "destroy the newly-created resource",
                "window": "until other changes depend on it", "cost": "none — nothing exists yet to lose",
                "confidence": "high", "rationale": "A create is undone by a delete.", "evidence": ev}
    # One-way growth: an attribute that can be increased but never decreased.
    # Which attribute, on which type, and why, all come from the provider pack.
    one_way = PACK.one_way_attribute(rtype)
    if one_way and action == "update":
        for attr, reason in one_way.items():
            why = _unresolved(attr, unknown, sensitive)
            if why:
                return {"value": "unknown", "cost": "unknown", "confidence": "low",
                        "rationale": f"Cannot determine whether `{attr}` increased: it is {why}. "
                                     f"{reason.capitalize()}, so this is not assumed reversible.",
                        "evidence": ev}
            b, a = before.get(attr), after.get(attr)
            if isinstance(b, (int, float)) and isinstance(a, (int, float)) and a > b:
                return {"value": "irreversible",
                        "cost": f"`{attr}` {int(b)} -> {int(a)} cannot be reduced; permanent",
                        "confidence": "high", "rationale": reason, "evidence": ev}

    if rtype == "azurerm_managed_disk" and action == "update":
        # The size is frequently a variable or a computed value, in which case
        # the plan carries no number at all. Answering "reversible" there would
        # be an affirmative wrong answer about the one irreversibility this tool
        # claims to catch, so the missing field becomes the verdict.
        why = _unresolved("disk_size_gb", unknown, sensitive)
        if why:
            return {"value": "unknown", "cost": "unknown", "confidence": "low",
                    "rationale": f"Cannot determine whether this is a disk grow: `disk_size_gb` is {why}. "
                                 "An Azure managed disk grow is irreversible, so this is not assumed reversible.",
                    "evidence": ev}
        b, a = before.get("disk_size_gb"), after.get("disk_size_gb")
        if isinstance(b, (int, float)) and isinstance(a, (int, float)) and a > b:
            return {"value": "irreversible",
                    "cost": f"an Azure managed disk grow ({int(b)}->{int(a)} GB) cannot be shrunk; permanent",
                    "confidence": "high",
                    "rationale": "Azure does not support shrinking a managed disk, so the size increase is one-way.",
                    "evidence": ev}
    if action in ("delete", "replace"):
        if rtype in _STATELESS:
            return {"value": "reversible", "mechanism": "re-apply the prior Terraform configuration",
                    "window": "any time", "cost": "none — configuration only, no data",
                    "confidence": "high", "rationale": "A stateless resource is recreated from configuration.",
                    "evidence": ev}
        return {"value": "unknown", "cost": "unknown", "confidence": "low",
                "rationale": "Reversal depends on a recovery point (snapshot/backup) that requires live "
                             "state to confirm; blastcheck did not query it.", "evidence": ev}
    # in-place update of something else
    pending = _unknown_fields(unknown)
    if pending:
        return {"value": "unknown", "cost": "unknown", "confidence": "low",
                "rationale": "This in-place update has field(s) whose values are not known until apply ("
                             + ", ".join(pending[:5]) + "), so what is actually changing — and therefore "
                             "whether it can be reversed — cannot be established from the plan.",
                "evidence": ev}
    return {"value": "reversible", "mechanism": "re-apply the prior Terraform configuration",
            "window": "until dependent changes apply", "cost": "unknown — depends on the field changed",
            "confidence": "low", "rationale": "An in-place update can generally be re-applied in reverse.",
            "evidence": ev}


def _data_durability(action: str, rtype: str, ev: List[str]) -> Dict[str, Any]:
    if action in ("create", "no-op", "read"):
        return {"value": "no_data_loss", "confidence": "high",
                "rationale": "Nothing is written or destroyed.", "evidence": ev}
    if action in ("delete", "replace") and rtype in _DATA_BEARING:
        return {"value": "unknown", "at_risk": [f"data held by {rtype} (recoverability not verified)"],
                "confidence": "low",
                "rationale": "The primary copy is removed; whether a recoverable backup or snapshot exists "
                             "requires live state, which was not queried. Not assumed recoverable.",
                "evidence": ev}
    if action in ("delete", "replace") and rtype in _VM_TYPES:
        return {"value": "unknown", "confidence": "low",
                "rationale": "Data durability depends on whether attached disks are retained or deleted, "
                             "which requires live/config detail not resolved here.", "evidence": ev}
    # Layer 1: no precise rule for this type, so guess from the name and say so.
    if action in ("delete", "replace") and _looks_data_bearing(rtype):
        return {"value": "unknown", "at_risk": [f"data possibly held by {rtype} (type not precisely known)"],
                "confidence": "low",
                "rationale": f"`{rtype}` has no precise rule in this version. Its name suggests it holds "
                             "data, and it is being destroyed, so durability is treated as undetermined "
                             "rather than assumed safe. This is an inference from the type name.",
                "evidence": ev}
    if action in ("delete", "replace"):
        return {"value": "unknown", "confidence": "low",
                "rationale": f"`{rtype}` is being destroyed and has no precise rule in this version. "
                             "Nothing in the plan establishes that it holds no data, so this is "
                             "undetermined rather than benign.",
                "evidence": ev}
    return {"value": "no_data_loss", "confidence": "medium",
            "rationale": "This change does not remove a data-bearing resource.", "evidence": ev}


def _rule_reaches_internet(rule: Optional[dict]) -> Optional[Tuple[List[str], List[str]]]:
    """If this NSG rule is an inbound Allow reaching the whole internet on a
    sensitive port, return (open_sources, sensitive_ports); otherwise None.

    Azure lets the same rule be written two ways: as a standalone
    `azurerm_network_security_rule` resource, or as an inline `security_rule`
    block on the NSG itself. Both spellings are common in real configuration.
    This predicate is shared by both code paths deliberately — checking only one
    spelling means an NSG opening RDP to the world reports as unchanged."""
    rule = rule or {}
    src = {str(s).lower() for s in (rule.get("source_address_prefixes") or [])}
    if rule.get("source_address_prefix"):
        src.add(str(rule["source_address_prefix"]).lower())
    ports = {str(p) for p in (rule.get("destination_port_ranges") or [])}
    if rule.get("destination_port_range") is not None:
        ports.add(str(rule["destination_port_range"]))
    inbound_allow = (str(rule.get("direction", "")).lower() == "inbound"
                     and str(rule.get("access", "")).lower() == "allow")
    if not inbound_allow:
        return None
    open_src, sensitive_ports = src & _OPEN_SOURCES, ports & _SENSITIVE_PORTS
    if open_src and sensitive_ports:
        return sorted(open_src), sorted(sensitive_ports)
    return None


def _default_network_action(block: Any) -> str:
    """Read `network_rules.default_action`, which the provider may present as a
    single object or as a one-element block list."""
    if isinstance(block, list):
        block = block[0] if block else None
    if isinstance(block, dict):
        return str(block.get("default_action", "")).lower()
    return ""


def _security(action: str, rtype: str, before: dict, after: dict,
              unknown: dict, sensitive: dict, base: str) -> Tuple[Dict[str, Any], List[dict]]:
    after = after or {}
    before = before or {}
    concerns: List[dict] = []
    extra_ev: List[dict] = []
    # Fields a check needed but the plan does not carry. If nothing is found AND
    # something was unreadable, the honest answer is `unknown`, not `unchanged`.
    unreadable: List[str] = []
    ev_id = f"{base}-sec"

    def note_unreadable(*fields: str) -> None:
        for f in fields:
            why = _unresolved(f, unknown, sensitive)
            if why:
                unreadable.append(f"`{f}` is {why}")

    if rtype == "azurerm_network_security_rule" and action in ("create", "update", "replace"):
        note_unreadable("direction", "access", "source_address_prefix", "source_address_prefixes",
                        "destination_port_range", "destination_port_ranges")
        hit = _rule_reaches_internet(after)
        if hit:
            concerns.append({"kind": "exposure",
                             "detail": f"inbound Allow from {hit[0]} to port(s) {hit[1]} "
                                       "— opens sensitive access to the internet"})
            extra_ev.append(_ev(ev_id, "change.after: direction/access/source_address_prefix(es)/destination_port_range(s)",
                                 "inbound Allow rule reaches the whole internet on a sensitive port"))

    if rtype == "azurerm_network_security_group" and action in ("create", "update", "replace"):
        # Rules declared INLINE on the NSG — a separate shape from the standalone
        # rule resource above, and just as common in real configuration.
        note_unreadable("security_rule")
        # Only flag rules that are NEWLY open: a rule that was already open before
        # this change is a pre-existing condition, not something this plan does.
        already_open = {str((r or {}).get("name", ""))
                        for r in (before.get("security_rule") or [])
                        if _rule_reaches_internet(r)}
        newly_open = []
        for r in (after.get("security_rule") or []):
            hit = _rule_reaches_internet(r)
            if hit and str((r or {}).get("name", "")) not in already_open:
                newly_open.append((str((r or {}).get("name", "")) or "<unnamed>", hit))
        for name, hit in newly_open:
            concerns.append({"kind": "exposure",
                             "detail": f"inline rule '{name}': inbound Allow from {hit[0]} to port(s) "
                                       f"{hit[1]} — opens sensitive access to the internet"})
        if newly_open:
            extra_ev.append(_ev(ev_id, "change.after.security_rule[] compared with change.before.security_rule[]",
                                 f"{len(newly_open)} inline rule(s) newly reach the whole internet on a sensitive port"))

    if rtype == "azurerm_storage_account" and action in ("create", "update", "replace"):
        note_unreadable("public_network_access_enabled", "allow_nested_items_to_be_public",
                        "min_tls_version", "network_rules")
        if after.get("public_network_access_enabled") is True and before.get("public_network_access_enabled") is not True:
            concerns.append({"kind": "exposure", "detail": "public network access enabled on the storage account"})
        if after.get("allow_nested_items_to_be_public") is True and before.get("allow_nested_items_to_be_public") is not True:
            concerns.append({"kind": "exposure", "detail": "blob/container public access allowed"})
        bt, at = before.get("min_tls_version"), after.get("min_tls_version")
        if isinstance(bt, str) and isinstance(at, str) and at < bt:
            concerns.append({"kind": "identity", "detail": f"minimum TLS version lowered {bt} -> {at}"})
        # A firewall flipping from default-Deny to default-Allow exposes the whole
        # account just as effectively as the public-access flag above.
        bd, ad = _default_network_action(before.get("network_rules")), _default_network_action(after.get("network_rules"))
        if bd == "deny" and ad == "allow":
            concerns.append({"kind": "exposure",
                             "detail": "storage firewall default_action changed Deny -> Allow, "
                                       "so the account is reachable from any network not explicitly blocked"})
        if concerns:
            extra_ev.append(_ev(ev_id, "change.after: public access / TLS / network_rules settings",
                                 "; ".join(c["detail"] for c in concerns)))

    # Declarative pack rules. Same standing as the hand-written rules above:
    # someone who knows the provider asserted these, so they are `high`
    # confidence and may be graded blocking. Layer 1 guesses may not.
    pack_hits = PACK.exposure_findings(rtype, before, after)
    if pack_hits:
        concerns.extend(pack_hits)
        extra_ev.append(_ev(ev_id, f"change.after vs change.before: {rtype} pack rules",
                             "; ".join(h["detail"] for h in pack_hits), source="policy"))

    if concerns:
        return ({"value": "widened", "concerns": concerns, "confidence": "high",
                 "rationale": "The plan's after-state widens exposure or weakens a control (see concerns).",
                 "evidence": [base + "-plan", ev_id]}, extra_ev)

    # Layer 1. Reached only when the precise and pack layers found NOTHING, so a
    # determination is never overridden by a guess — but reached for every type,
    # including precisely-known ones. Gating this on "unknown type" was a bug:
    # putting aws_security_group_rule into a pack silently disabled the open-CIDR
    # check for it, because that check is algorithmic and lives here rather than
    # in the pack. Knowing a type better must never mean checking it less.
    if True:
        guesses = _heuristic_exposure(action, before, after)
        if guesses:
            h_id = f"{base}-heur"
            extra_ev.append(_ev(h_id, "change.after vs change.before: attribute name and value patterns",
                                 "; ".join(g["detail"] for g in guesses), source="heuristic"))
            return ({"value": "widened", "concerns": guesses, "confidence": "low",
                     "rationale": f"`{rtype}` has no precise rule in this version. Pattern matching on "
                                  "attribute names and values suggests this change widens exposure or "
                                  "removes a protection. Treat as a lead, not a determination.",
                     "evidence": [base + "-plan", h_id]}, extra_ev)

    if unreadable:
        extra_ev.append(_ev(ev_id, "change.after_unknown / change.after_sensitive",
                             "; ".join(unreadable)))
        return ({"value": "unknown", "confidence": "low",
                 "rationale": "Exposure could not be assessed from the plan: " + "; ".join(unreadable)
                              + ". Not assumed unchanged.",
                 "evidence": [base + "-plan", ev_id]}, extra_ev)
    return ({"value": "unchanged", "confidence": "medium",
             "rationale": "No exposure-widening or control-weakening change was found in the plan diff for the "
                          "checked fields. (Plan-only; a live posture check may see more.)",
             "evidence": [base + "-plan"]}, extra_ev)


def _cost(action: str, rtype: str, before: dict, after: dict,
          unknown: dict, sensitive: dict, ev: List[str]) -> Dict[str, Any]:
    if action == "create":
        return {"direction": "increase", "recurrence": "recurring", "confidence": "low",
                "rationale": "A new billable resource is created; magnitude not derivable from the plan.", "evidence": ev}
    if action == "delete":
        return {"direction": "decrease", "recurrence": "recurring", "confidence": "low",
                "rationale": "A billable resource is removed.", "evidence": ev}
    if rtype == "azurerm_managed_disk" and action == "update":
        if _unresolved("disk_size_gb", unknown, sensitive):
            return {"direction": "unknown", "recurrence": "unknown", "confidence": "low",
                    "rationale": "The new disk size is not carried in the plan, so the direction of the "
                                 "cost change cannot be determined.", "evidence": ev}
        b, a = before.get("disk_size_gb"), after.get("disk_size_gb")
        if isinstance(b, (int, float)) and isinstance(a, (int, float)) and a != b:
            return {"direction": "increase" if a > b else "decrease", "recurrence": "recurring", "confidence": "low",
                    "rationale": f"managed disk size change {int(b)}->{int(a)} GB adjusts recurring spend.", "evidence": ev}
    if action in ("no-op", "read"):
        return {"direction": "none", "recurrence": "none", "confidence": "high",
                "rationale": "No billable change.", "evidence": ev}
    return {"direction": "unknown", "recurrence": "unknown", "confidence": "low",
            "rationale": "Cost effect of this change is not derivable from the plan alone.", "evidence": ev}


def _preconditions(action: str, rtype: str, any_unknown: bool) -> List[Dict[str, Any]]:
    pc: List[Dict[str, Any]] = []
    if action in ("delete", "replace") and rtype in _DATA_BEARING:
        pc.append({"id": "pc-recovery-point",
                   "description": "A verified recovery point (snapshot or backup) exists for this resource.",
                   "check": "exists(recovery_point for resource)", "status": "unknown",
                   "rationale": "Requires live state; blastcheck ran plan-only."})
    if any_unknown:
        pc.append({"id": "pc-live-access",
                   "description": "Live-state access is available so the target can be inspected before apply.",
                   "check": "provider_credentials_available == true", "status": "unsatisfied",
                   "rationale": "blastcheck ran plan-only (offline); the unknowns above require live state to resolve."})
    return pc


# ── State confidence, from Terraform's own refresh ───────────────────────────
#
# `terraform plan` refreshes by default: before computing a diff it reads live
# reality for every managed resource. Anything that moved since the last apply
# lands in a top-level `resource_drift` array, same shape as `resource_changes`.
#
# That array is a live-state observation sitting inside an offline artifact.
# blastcheck did not perform the read — Terraform did — but the fact is no less
# true for that, and it is the only dimension that invalidates all the others
# when it goes wrong. A plan TRUSTS recorded state; drift is the proof that
# trust was misplaced.
#
# What this cannot do, and must not pretend to: an empty `resource_drift` is
# ambiguous. It means either "refresh ran and found nothing" or "refresh was
# disabled with -refresh=false", and the plan JSON does not record which. So
# absence never earns `state_matches_reality`; it stays `not_verified`. Nor does
# refresh see resources that were created outside Terraform entirely — those are
# not in state, so nothing refreshes them.

def _drifted_fields(entry: Dict[str, Any], limit: int = 6) -> List[str]:
    """Fields whose live value differed from the recorded state at refresh time.
    In a drift entry `before` is the prior saved state and `after` is what
    Terraform actually found."""
    ch = (entry or {}).get("change") or {}
    before, after = ch.get("before") or {}, ch.get("after") or {}
    if not isinstance(before, dict) or not isinstance(after, dict):
        return []
    names = sorted(k for k in set(before) | set(after) if before.get(k) != after.get(k))
    return names[:limit]


def _norm_key(k: str) -> str:
    """`disk_size_gb` and `diskSizeGB` are the same field. Terraform uses snake
    case, ARM returns camel case, and comparing them literally would report drift
    on every single attribute of every single resource."""
    return re.sub(r"[^a-z0-9]", "", str(k).lower())


def _live_state_confidence(obs: Any, before: dict, base: str,
                           plan_ref: List[str]) -> Tuple[Dict[str, Any], List[dict]]:
    """State confidence from a live read blastcheck performed itself.

    This is the only path in the tool that can return `state_matches_reality`,
    and therefore the only path that makes a `safe` verdict reachable. It is
    deliberately conservative: only scalar attributes present on BOTH sides are
    compared, because a nested block or a computed field differing tells you
    nothing, and a false drift report is as corrosive to trust as a false safe."""
    ev_id = f"{base}-live"

    if obs is None or not getattr(obs, "usable", False):
        why = getattr(obs, "error", None) or "no live observation was attempted for this resource"
        return ({"value": "not_verified", "verified_against_live": False, "confidence": "high",
                 "rationale": f"A live read was attempted but did not produce a usable answer: {why}. "
                              "Recorded state therefore remains unverified.",
                 "evidence": plan_ref},
                [_ev(ev_id, "live read", why, source="live_state")])

    if obs.found is False:
        return ({"value": "drift_detected", "verified_against_live": True, "confidence": "high",
                 "rationale": "The resource recorded in state does not exist in the cloud. Anything this "
                              "plan intends to do to it was computed against a description of something "
                              "that is not there.",
                 "evidence": plan_ref + [ev_id]},
                [_ev(ev_id, f"live lookup of {obs.address}", "resource not found", source="live_state")])

    live = {_norm_key(k): v for k, v in (obs.attributes or {}).items()}
    diffs = []
    for k, v in (before or {}).items():
        if isinstance(v, (dict, list)) or v is None:
            continue  # only scalars are comparable across the two namespaces
        lk = _norm_key(k)
        if lk not in live:
            continue
        lv = live[lk]
        if isinstance(lv, (dict, list)) or lv is None:
            continue
        if isinstance(v, bool) != isinstance(lv, bool):
            continue
        if str(v) != str(lv):
            diffs.append(f"{k}: state {v!r} -> live {lv!r}")

    if diffs:
        return ({"value": "drift_detected", "verified_against_live": True, "confidence": "high",
                 "rationale": "A live read found this resource differs from the state the plan was "
                              "computed against (" + "; ".join(diffs[:4]) + ").",
                 "evidence": plan_ref + [ev_id]},
                [_ev(ev_id, f"live lookup of {obs.address}", "; ".join(diffs[:6]),
                     source="live_state")])

    compared = sum(1 for k, v in (before or {}).items()
                   if not isinstance(v, (dict, list)) and v is not None and _norm_key(k) in live)
    if compared == 0:
        return ({"value": "not_verified", "verified_against_live": False, "confidence": "medium",
                 "rationale": "The resource exists live, but no scalar attribute could be compared "
                              "against recorded state, so state was not actually verified. Existence "
                              "alone is not a match.",
                 "evidence": plan_ref + [ev_id]},
                [_ev(ev_id, f"live lookup of {obs.address}",
                     "resource exists; no comparable scalar attributes", source="live_state")])

    return ({"value": "state_matches_reality", "verified_against_live": True, "confidence": "high",
             "rationale": f"A live read confirmed this resource matches the state the plan was computed "
                          f"against, on {compared} comparable attribute(s).",
             "evidence": plan_ref + [ev_id]},
            [_ev(ev_id, f"live lookup of {obs.address}",
                 f"{compared} scalar attribute(s) match recorded state", source="live_state")])


def _state_confidence(drift: Optional[Dict[str, Any]], base: str,
                      plan_ref: List[str]) -> Tuple[Dict[str, Any], List[dict]]:
    if not drift:
        return ({
            "value": "not_verified", "verified_against_live": False, "confidence": "high",
            "rationale": "This resource is absent from the plan's `resource_drift`, which means either "
                         "that refresh found no drift or that refresh did not run (`-refresh=false`). "
                         "The plan does not record which, so recorded state is treated as unverified "
                         "rather than confirmed.",
            "evidence": plan_ref,
        }, [])

    ev_id = f"{base}-drift"
    fields = _drifted_fields(drift)
    ch = (drift.get("change") or {})
    detail = ", ".join(fields) if fields else "one or more attributes"
    observation = f"recorded state and live reality differ on: {detail}"
    # Where a scalar moved, name both values — it is the difference between
    # "something drifted" and a reader understanding what happened.
    b, a = ch.get("before") or {}, ch.get("after") or {}
    if isinstance(b, dict) and isinstance(a, dict):
        pairs = [f"{f}: recorded {b.get(f)!r} -> live {a.get(f)!r}" for f in fields
                 if not isinstance(b.get(f), (dict, list)) and not isinstance(a.get(f), (dict, list))]
        if pairs:
            observation = "; ".join(pairs[:4])

    evidence = [_ev(ev_id, f"resource_drift[] where address == {drift.get('address','')}",
                    observation, source="live_state")]
    return ({
        "value": "drift_detected", "verified_against_live": True, "confidence": "high",
        "rationale": f"Terraform's refresh found this resource had changed outside Terraform ({detail}). "
                     "The plan below was computed against a description of this resource that no longer "
                     "matched reality. blastcheck did not perform the live read; Terraform did, and "
                     "recorded it in `resource_drift`.",
        "evidence": plan_ref + [ev_id],
    }, evidence)


def _severity(dims: Dict[str, Any]) -> Tuple[str, str]:
    av = dims["availability_impact"]["value"]
    rv = dims["reversibility"]["value"]
    dd = dims["data_durability"]["value"]
    sec = dims["security_posture"]["value"]
    sc = dims["state_confidence"]["value"]
    # The plan is about to modify a resource that had already drifted out from
    # under it. This is the single most dangerous shape in the whole format: the
    # plan is internally consistent, reads as routine, and was computed against a
    # description of the resource that had stopped being true. It outranks the
    # other dimensions because it invalidates them — every verdict below was
    # derived from the same stale state.
    if sc == "drift_detected":
        return "blocking", ("This change targets a resource whose recorded state did not match live reality "
                            "at refresh time. The plan is internally consistent but was computed against a "
                            "description of the resource that had already stopped being true.")
    # Catastrophic: permanent data loss, taking a live thing down, or widening
    # exposure — but only where the finding was actually determined. A Layer 1
    # pattern match is a lead, and grading leads `blocking` is how a tool trains
    # people to ignore it. A low-confidence widening is `caution`: visible,
    # not alarming.
    sec_confident = dims["security_posture"].get("confidence") in ("high", "medium")
    if dd == "unrecoverable_loss" or av == "interrupts" or (sec == "widened" and sec_confident):
        return "blocking", "A dimension reports a catastrophic effect (data loss, interruption, or widened exposure)."
    if sec == "widened":
        return "caution", ("Pattern matching suggests this change widens exposure or removes a protection, "
                           "but no precise rule covers this resource type. Worth a look; not a determination.")
    # Safety-critical dimension could not be determined -> not certifiable.
    if "unknown" in (av, rv, dd, sec):
        return "unknown", "A safety-critical dimension could not be determined without live state."
    # Known but one-way / lossy on reversal -> proceed knowingly.
    if rv in ("irreversible", "reversible_with_data_loss"):
        return "caution", "The change is one-way or lossy on reversal; proceed knowingly."
    return "informational", "No dangerous or undetermined dimension found."


def _live_availability(obs: Any, action: str, ev: List[str]) -> Optional[Dict[str, Any]]:
    """Availability from a live read. Returns None when the observation cannot
    settle it, so the caller falls back to the honest plan-only `unknown`."""
    if obs is None or not getattr(obs, "usable", False) or obs.found is not True:
        return None
    attrs = {_norm_key(k): v for k, v in (obs.attributes or {}).items()}

    # `managedBy` is the ARM-wide way a resource says something else owns it —
    # a disk attached to a VM, for instance. Provider-agnostic within Azure
    # rather than a per-type special case.
    owner = attrs.get("managedby")
    if action in ("delete", "replace", "update") and isinstance(owner, str) and owner.strip():
        return {"value": "interrupts", "serves_production_traffic": "unknown", "confidence": "medium",
                "rationale": f"A live read shows this resource is attached to another resource "
                             f"({owner.rsplit('/', 1)[-1]}). Changing it is not isolated. Whether that "
                             "owner serves production traffic was not determined.",
                "evidence": ev}
    if action in ("delete", "replace", "update") and owner is not None and not str(owner).strip():
        return {"value": "none", "confidence": "medium",
                "rationale": "A live read shows nothing currently owns or is attached to this resource.",
                "evidence": ev}
    return None


def _live_recovery(rec: Any, action: str, rtype: str, base: str,
                   ev: List[str]) -> Tuple[Optional[Dict[str, Any]], Optional[Dict[str, Any]], List[dict]]:
    """Reversibility and data durability from a recovery-point lookup.

    Returns (reversibility, data_durability, evidence), each None where the
    lookup settles nothing. This is the pair of dimensions a plan can never
    answer: whether destroying something is survivable depends entirely on
    whether a restorable copy exists right now."""
    if rec is None or action not in ("delete", "replace"):
        return None, None, []
    ev_id = f"{base}-recovery"
    if not getattr(rec, "usable", False):
        # Not checked is not the same as no backup, and must never read as one.
        return None, None, [_ev(ev_id, "recovery-point lookup",
                                rec.error or "not attempted", source="live_state")]

    if rec.found:
        n = (rec.attributes or {}).get("count", 1)
        names = [s.get("name") for s in (rec.attributes or {}).get("snapshots", []) if isinstance(s, dict)]
        detail = f"{n} recovery point(s) exist" + (f" (e.g. {names[0]})" if names else "")
        return ({"value": "reversible_with_data_loss",
                 "mechanism": "restore from the most recent recovery point",
                 "window": "bounded by the age of that recovery point",
                 "cost": "everything written since the recovery point was taken is lost",
                 "confidence": "high",
                 "rationale": f"A live lookup found {detail}. The resource is restorable, but a restore "
                              "is not free: a technically reversible change can still be an operational "
                              "disaster if the recovery point is old.",
                 "evidence": ev},
                {"value": "recoverable_loss", "confidence": "high",
                 "rationale": f"A live lookup found {detail}, so the data is recoverable rather than "
                              "permanently lost.", "evidence": ev},
                [_ev(ev_id, "recovery-point lookup", detail, source="live_state")])

    return ({"value": "irreversible", "cost": "no recovery point exists to restore from",
             "confidence": "high",
             "rationale": "A live lookup found no recovery point for this resource. Destroying it "
                          "cannot be undone.", "evidence": ev},
            {"value": "unrecoverable_loss",
             "at_risk": [f"all data held by {rtype}"], "confidence": "high",
             "rationale": "A live lookup confirmed no snapshot or backup exists. This is permanent.",
             "evidence": ev},
            [_ev(ev_id, "recovery-point lookup", "no recovery point found", source="live_state")])


def analyze_change(index: int, rc: Dict[str, Any],
                   drift: Optional[Dict[str, Any]] = None,
                   obs: Any = None, rec: Any = None) -> Tuple[Dict[str, Any], List[dict]]:
    addr = str(rc.get("address", ""))
    rtype = str(rc.get("type", ""))
    change = rc.get("change") or {}
    actions_raw = [a for a in (change.get("actions") or []) if a in
                   ("no-op", "create", "read", "update", "delete", "replace")]
    action = _action(actions_raw)
    before = change.get("before") or {}
    after = change.get("after") or {}
    # Values Terraform could not resolve at plan time, and values it redacted.
    # `after` is null for both, so a rule that reads only `after` cannot tell
    # them apart from "absent" — see _unresolved().
    after_unknown = change.get("after_unknown")
    after_unknown = after_unknown if isinstance(after_unknown, dict) else {}
    after_sensitive = change.get("after_sensitive")
    after_sensitive = after_sensitive if isinstance(after_sensitive, dict) else {}

    base = f"e{index}"
    plan_ref = [f"{base}-plan"]
    unresolved_now = _unknown_fields(after_unknown)

    # Layer 0. Terraform states, in every provider, WHY it chose this action and
    # WHICH attribute forced a replacement. That is free, structural signal and
    # blastcheck was throwing it away.
    # NB: named plan_obs, not obs. `obs` is the live-observation parameter, and
    # shadowing it here made every change take the live-read path with a string
    # in place of an Observation — a silent, total degradation of live mode that
    # only surfaced because a drift test counted its evidence items.
    plan_obs = f"actions={actions_raw}; type={rtype}"
    reason = rc.get("action_reason")
    if reason:
        plan_obs += f"; action_reason={reason}"
    paths = change.get("replace_paths")
    if isinstance(paths, list) and paths:
        pretty = [".".join(str(p) for p in seg) if isinstance(seg, list) else str(seg) for seg in paths]
        plan_obs += f"; replacement forced by: {', '.join(pretty[:6])}"
    if unresolved_now:
        plan_obs += f"; not known until apply: {', '.join(unresolved_now[:8])}"
    evidence = [_ev(f"{base}-plan", f"resource_changes[] where address == {addr}", plan_obs)]

    sec_dim, sec_ev = _security(action, rtype, before, after, after_unknown, after_sensitive, base)
    evidence.extend(sec_ev)
    # A live read outranks Terraform's refresh: it is this tool's own observation,
    # taken now, rather than one inherited from an artifact of unknown age. Drift
    # already found by refresh is still reported if the live read is unusable.
    if obs is not None:
        state_dim, state_ev = _live_state_confidence(obs, before, base, plan_ref)
        if state_dim["value"] == "not_verified" and drift:
            state_dim, state_ev = _state_confidence(drift, base, plan_ref)
    else:
        state_dim, state_ev = _state_confidence(drift, base, plan_ref)
    evidence.extend(state_ev)

    live_av = _live_availability(obs, action, plan_ref)
    live_rev, live_dd, rec_ev = _live_recovery(rec, action, rtype, base, plan_ref)
    evidence.extend(rec_ev)
    dims = {
        "availability_impact": live_av or _availability(action, plan_ref),
        "reversibility": live_rev or _reversibility(action, rtype, before, after, after_unknown, after_sensitive, plan_ref),
        "data_durability": live_dd or _data_durability(action, rtype, plan_ref),
        "security_posture": sec_dim,
        "cost_delta": _cost(action, rtype, before, after, after_unknown, after_sensitive, plan_ref),
        "state_confidence": state_dim,
    }
    any_unknown = any(d.get("value") == "unknown" for d in
                      (dims["availability_impact"], dims["reversibility"],
                       dims["data_durability"], dims["security_posture"]))
    severity, rationale = _severity(dims)

    ch = {"address": addr, "resource_type": rtype, "name": str(rc.get("name", "")),
          "actions": actions_raw or ["no-op"], **dims,
          "preconditions": _preconditions(action, rtype, any_unknown),
          "severity": severity, "rationale": rationale}
    if rc.get("provider_name"):
        ch["provider"] = str(rc["provider_name"])
    return ch, evidence


# ── Verdict roll-up ──────────────────────────────────────────────────────────

def _verdict(changes: List[dict]) -> Dict[str, Any]:
    blocking = [c["address"] for c in changes if c["severity"] == "blocking"]
    unknown = [c["address"] for c in changes if c["severity"] == "unknown"]
    unknowns_present = any(
        d.get("value") == "unknown"
        for c in changes for d in (c[k] for k in
            ("availability_impact", "reversibility", "data_durability", "security_posture", "cost_delta"))
    ) or any(p.get("status") == "unknown" for c in changes for p in c.get("preconditions", []))

    drifted = [c["address"] for c in changes if c["state_confidence"]["value"] == "drift_detected"]

    if drifted:
        # Lead with drift when it is present. It is the finding a reader must not
        # scroll past, and it explains why the rest of the verdict is untrustworthy.
        decision = "blocked"
        why = (f"{len(drifted)} change(s) target resources that had already drifted from recorded state at "
               f"refresh time: {', '.join(drifted)}. The plan is internally consistent but was computed "
               "against a description of these resources that had stopped being true. Every other verdict "
               "for them was derived from that same stale state.")
    elif blocking:
        decision, why = "blocked", f"{len(blocking)} change(s) report a catastrophic effect: {', '.join(blocking)}."
    elif unknown:
        decision, why = "unknown", (f"{len(unknown)} change(s) could not be certified without live state: "
                                    f"{', '.join(unknown)}. Unproven is not safe.")
    else:
        # Nothing dangerous and nothing undetermined. Whether that earns `safe`
        # turns on one question: was recorded state actually verified against
        # reality? Conformance rule 5 forbids `safe` for any change whose
        # state_confidence is not a positive determination, and rule 3 says
        # `safe` is a positive claim rather than the absence of a known problem.
        # Both are satisfied only when every change was checked and matched.
        verified = [c for c in changes
                    if c["state_confidence"]["value"] == "state_matches_reality"]
        if len(verified) == len(changes) and changes:
            decision = "safe"
            why = (f"All {len(changes)} change(s) were assessed with no dangerous or undetermined "
                   "dimension, and recorded state was verified against live reality for every one of "
                   "them. This is a positive claim, not the absence of a finding.")
        else:
            unverified = len(changes) - len(verified)
            decision, why = "caution", (
                f"No dangerous or undetermined change was found, but recorded state was not verified "
                f"against reality for {unverified} of {len(changes)} change(s). A plan is only as "
                "trustworthy as the state it was computed against, so this cannot be certified `safe`. "
                "Re-run with `--live` to resolve it.")
    return {"decision": decision, "rationale": why,
            "blocking_changes": blocking + unknown, "unknowns_present": unknowns_present}


def _live_access(observations: Optional[Dict[str, Any]]) -> str:
    """`queried` only if a live read actually answered. Attempting and being
    refused is `unavailable`: a reader interpreting an `unknown` needs to know
    whether the producer even had the access to determine otherwise."""
    if not observations:
        return "not_attempted"
    if any(getattr(o, "usable", False) for o in observations.values()):
        return "queried"
    return "unavailable"


# ── Top-level: plan -> manifest ──────────────────────────────────────────────

def build_manifest(plan: Dict[str, Any], now: Optional[datetime] = None,
                   observations: Optional[Dict[str, Any]] = None,
                   recovery: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    now = now or datetime.now(timezone.utc)

    # Terraform's refresh findings, keyed by address. See _state_confidence().
    raw_drift = plan.get("resource_drift")
    drift_by_address: Dict[str, Any] = {}
    if isinstance(raw_drift, list):
        for d in raw_drift:
            if isinstance(d, dict) and d.get("address"):
                drift_by_address[str(d["address"])] = d

    # Every mutating change is assessed. Nothing is skipped for being an
    # unfamiliar type: Layer 0 rules (action semantics, drift, unreadable fields)
    # apply to any provider, and Layer 1 patterns apply to any attribute names.
    # A tool that answers "no supported resource changes found" on a real plan
    # is useless however correct it is about the plans it does understand.
    supported = []
    for rc in plan.get("resource_changes", []):
        acts = set((rc.get("change") or {}).get("actions") or [])
        if acts <= {"no-op", "read"}:
            continue  # nothing is mutated
        supported.append(rc)

    if not supported:
        raise PlanError(
            "no mutating resource changes found in this plan — every entry is a no-op or a data-source "
            "read, so there is nothing to assess."
        )

    changes, evidence = [], []
    for i, rc in enumerate(supported):
        addr_i = str(rc.get("address", ""))
        ch, ev = analyze_change(i, rc, drift_by_address.get(addr_i),
                                (observations or {}).get(addr_i),
                                (recovery or {}).get(addr_i))
        changes.append(ch)
        evidence.extend(ev)

    ts = now.strftime("%Y-%m-%dT%H:%M:%SZ")
    manifest = {
        "schema_version": SCHEMA_VERSION,
        "generated_at": ts,
        "valid_until": (now + timedelta(minutes=15)).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "producer": {
            "name": "blastcheck", "version": PRODUCER_VERSION, "homepage": "https://blastcheck.dev",
            # What blastcheck itself could see. `queried` only when at least one
            # live read actually returned an answer — asking and being refused
            # is `unavailable`, which is a different fact and a reader needs it
            # to interpret the unknowns below.
            "access": {"live_state": _live_access(observations)},
        },
        "source": {
            "type": "terraform_plan",
            "tool_version": str(plan.get("terraform_version") or ""),
            "format_version": str(plan.get("format_version") or ""),
        },
        "evidence": evidence,
        "changes": changes,
        "verdict": _verdict(changes),
    }
    ext: Dict[str, Any] = {}

    # How each verdict was reached. `change` is strict in the schema and rightly
    # so, but a reader must be able to tell a precise rule from a pattern match
    # without inferring it from the confidence field.
    depth = {}
    for r in supported:
        addr, rtype = str(r.get("address", "")), str(r.get("type", ""))
        depth[addr] = "precise" if rtype in PRECISE else (
            "heuristic" if _looks_data_bearing(rtype) or _DATA_HINTS.search(rtype) else "structural")
    ext["assessment"] = depth
    n_precise = sum(1 for v in depth.values() if v == "precise")
    if n_precise < len(depth):
        ext["assessment_note"] = (
            f"{n_precise} of {len(depth)} changes matched a precise rule for their resource type. The rest "
            "were assessed from action semantics, drift, unreadable fields, and attribute-name patterns, "
            "which are provider-independent but less certain. Their confidence values say so.")

    # Plan JSON format. An unrecognised major may be shaped differently than
    # anything this parser has seen, and reading it anyway without saying so is
    # the same mistake as reading an unreadable field as absent.
    fmt = str(plan.get("format_version") or "")
    if fmt and fmt.split(".")[0] not in _KNOWN_FORMAT_MAJORS:
        ext["unrecognised_plan_format"] = fmt

    # Drift on resources this plan does NOT touch is not a change, so it gets no
    # entry in changes[]. It is still a fact the reader should have: the estate
    # has moved, and the next plan that does touch these will inherit the problem.
    assessed = {str(r.get("address", "")) for r in supported}
    elsewhere = sorted(a for a in drift_by_address if a not in assessed)
    if elsewhere:
        ext["drift_outside_this_plan"] = elsewhere

    # Plan-level health. An errored plan is partial: actions recorded before the
    # failure are real, but absence of a change proves nothing about the rest.
    if plan.get("errored") is True:
        ext["plan_errored"] = True
    if plan.get("complete") is False:
        ext["plan_incomplete"] = True

    if ext:
        manifest["extensions"] = ext
    return manifest
