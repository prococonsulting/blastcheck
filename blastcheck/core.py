"""
blastcheck core — turn a `terraform show -json` plan into an Impact Manifest.

This is the REFERENCE producer for the Impact Manifest format. It is deliberately
OFFLINE and plan-only: it reasons from the plan artifact alone and, wherever a
verdict genuinely requires live cloud state, emits `unknown` / `not_verified`
with a stated reason rather than guessing. That honesty is the whole point —
a plan-only tool structurally cannot certify `safe` (it never verified live
state), and the manifest says so instead of pretending.

Scope (v0.1, narrow on purpose): Azure managed disks, virtual machines, network
security groups (+ rules), storage accounts, and SQL databases. Anything else in
the plan is recorded under `extensions.skipped`, never silently dropped.

The reasoning is commented, not the syntax — every verdict rule is one a human
should be able to defend out loud.
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Tuple

SCHEMA_VERSION = "0.1.0"
PRODUCER_VERSION = "0.1.1"

# ── Supported Azure resource surface ─────────────────────────────────────────
_DATA_BEARING = {
    "azurerm_managed_disk",
    "azurerm_storage_account",
    "azurerm_mssql_database",
    "azurerm_sql_database",
}
_STATELESS = {
    "azurerm_network_security_group",
    "azurerm_network_security_rule",
}
_VM_TYPES = {
    "azurerm_linux_virtual_machine",
    "azurerm_windows_virtual_machine",
    "azurerm_virtual_machine",
}
SUPPORTED = _DATA_BEARING | _STATELESS | _VM_TYPES

# Sources that count as "the whole internet" for an inbound-allow rule.
_OPEN_SOURCES = {"*", "0.0.0.0/0", "internet", "any"}
# Ports whose exposure to the internet is a red flag on its own.
_SENSITIVE_PORTS = {"22", "3389", "*"}


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
    # A managed-disk grow is a real plan-derivable irreversibility: Azure cannot shrink a disk.
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

    if concerns:
        return ({"value": "widened", "concerns": concerns, "confidence": "high",
                 "rationale": "The plan's after-state widens exposure or weakens a control (see concerns).",
                 "evidence": [base + "-plan", ev_id]}, extra_ev)
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


def _severity(dims: Dict[str, Any]) -> Tuple[str, str]:
    av = dims["availability_impact"]["value"]
    rv = dims["reversibility"]["value"]
    dd = dims["data_durability"]["value"]
    sec = dims["security_posture"]["value"]
    # Catastrophic: permanent data loss, taking a live thing down, or widening exposure.
    if dd == "unrecoverable_loss" or av == "interrupts" or sec == "widened":
        return "blocking", "A dimension reports a catastrophic effect (data loss, interruption, or widened exposure)."
    # Safety-critical dimension could not be determined -> not certifiable.
    if "unknown" in (av, rv, dd, sec):
        return "unknown", "A safety-critical dimension could not be determined without live state."
    # Known but one-way / lossy on reversal -> proceed knowingly.
    if rv in ("irreversible", "reversible_with_data_loss"):
        return "caution", "The change is one-way or lossy on reversal; proceed knowingly."
    return "informational", "No dangerous or undetermined dimension found."


def analyze_change(index: int, rc: Dict[str, Any]) -> Tuple[Dict[str, Any], List[dict]]:
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
    evidence = [_ev(f"{base}-plan", f"resource_changes[] where address == {addr}",
                    f"actions={actions_raw}; type={rtype}"
                    + (f"; not known until apply: {', '.join(unresolved_now[:8])}" if unresolved_now else ""))]

    sec_dim, sec_ev = _security(action, rtype, before, after, after_unknown, after_sensitive, base)
    evidence.extend(sec_ev)

    dims = {
        "availability_impact": _availability(action, plan_ref),
        "reversibility": _reversibility(action, rtype, before, after, after_unknown, after_sensitive, plan_ref),
        "data_durability": _data_durability(action, rtype, plan_ref),
        "security_posture": sec_dim,
        "cost_delta": _cost(action, rtype, before, after, after_unknown, after_sensitive, plan_ref),
        "state_confidence": {
            "value": "not_verified", "verified_against_live": False, "confidence": "high",
            "rationale": "blastcheck ran plan-only; live state was not queried, so recorded state could not "
                         "be checked against reality. Run with live-state enrichment to verify.",
            "evidence": plan_ref,
        },
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

    if blocking:
        decision, why = "blocked", f"{len(blocking)} change(s) report a catastrophic effect: {', '.join(blocking)}."
    elif unknown:
        decision, why = "unknown", (f"{len(unknown)} change(s) could not be certified without live state: "
                                    f"{', '.join(unknown)}. Unproven is not safe.")
    else:
        # No danger and no unknowns — but blastcheck ran plan-only, so state was
        # never verified. It CANNOT emit `safe`; that requires live-state enrichment.
        decision, why = "caution", ("No dangerous or undetermined change found, but this was a plan-only run: "
                                     "live state was never verified, so the plan cannot be certified `safe`. "
                                     "Re-run with live-state enrichment to reach a `safe` verdict.")
    return {"decision": decision, "rationale": why,
            "blocking_changes": blocking + unknown, "unknowns_present": unknowns_present}


# ── Top-level: plan -> manifest ──────────────────────────────────────────────

def build_manifest(plan: Dict[str, Any], now: Optional[datetime] = None) -> Dict[str, Any]:
    now = now or datetime.now(timezone.utc)
    supported, skipped = [], []
    for rc in plan.get("resource_changes", []):
        acts = set((rc.get("change") or {}).get("actions") or [])
        if acts <= {"no-op", "read"}:
            continue  # nothing is mutated
        (supported if rc.get("type") in SUPPORTED else skipped).append(rc)

    if not supported:
        raise PlanError(
            "no supported resource changes found. Supported (v0.1): Azure managed disks, virtual machines, "
            "network security groups (+ rules), storage accounts, SQL databases."
        )

    changes, evidence = [], []
    for i, rc in enumerate(supported):
        ch, ev = analyze_change(i, rc)
        changes.append(ch)
        evidence.extend(ev)

    ts = now.strftime("%Y-%m-%dT%H:%M:%SZ")
    manifest = {
        "schema_version": SCHEMA_VERSION,
        "generated_at": ts,
        "valid_until": (now + timedelta(minutes=15)).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "producer": {
            "name": "blastcheck", "version": PRODUCER_VERSION, "homepage": "https://blastcheck.dev",
            # Plan-only run: live state was not attempted. This is WHY unknowns exist.
            "access": {"live_state": "not_attempted"},
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
    if skipped:
        # Never silently drop unassessed changes — record them, per the format's spirit.
        manifest["extensions"] = {"skipped": [str(r.get("address", "")) for r in skipped]}
    return manifest
