"""
Human-readable rendering of an Impact Manifest.

WHY THIS EXISTS

Until now the only output was the manifest itself: 66 KB and seventeen hundred
lines of JSON for a middling plan. That is the correct wire format and a
terrible thing to put in front of a person. A first-time user piped a plan in,
got a wall of JSON, and could not tell whether their change was safe without
reaching for `jq`. Every finding in this codebase was invisible in practice.

WHAT IT MUST NOT DO

The rendering is a view, never a second opinion. It shows what the manifest
says, in the manifest's own words, and it never softens a verdict to fit on a
line. Two rules follow from that and are worth stating because both are easy to
break by accident:

  * `unknown` is displayed as prominently as `blocked`. A renderer that greys
    out the unknowns to make the output calmer has quietly reintroduced exactly
    the failure this format exists to prevent.
  * Confidence is always shown for a low-confidence finding. A heuristic guess
    and a determination must not look the same in a terminal, whatever they
    look like in JSON.

COLOUR

Honoured only on a terminal, and suppressed by NO_COLOR (the de facto standard)
so this behaves in a pipeline. Severity is never conveyed by colour alone; the
word is always there for anyone reading a log without ANSI support.
"""

from __future__ import annotations

import os
import sys
from typing import Any, Dict, List, Optional, TextIO

__all__ = ["render", "supports_colour", "gate_exit_code", "FAIL_ON_LEVELS"]

# Order matters: worst first, which is also the order a reader should meet them.
_SEVERITY_ORDER = ["blocking", "unknown", "caution", "informational"]
_SEVERITY_LABEL = {"blocking": "BLOCKED", "unknown": "UNKNOWN",
                   "caution": "CAUTION", "informational": "ok"}

# A finding is something true of THIS change. In a plan-only run every change
# also carries the same three baseline unknowns — "does it serve traffic",
# "is there a backup", "was state verified" — and printing those seventeen times
# buries the four findings that matter under identical paragraphs. They are a
# property of the run, so they are stated once, in the footer.
#
# The filter is deliberately about specificity, not severity: an `unknown` that
# names the field which defeated it IS a finding and is shown. Suppressing by
# severity would be the renderer quietly softening the output, which is the one
# thing it must never do.

def _findings(change):
    """(label, text) for everything specific to this change."""
    out = []

    sec = change.get("security_posture") or {}
    for c in (sec.get("concerns") or [])[:4]:
        out.append(("security", c.get("detail", "")))
    if sec.get("value") == "unknown":
        # Names the field that could not be read — specific, and actionable.
        out.append(("security", sec.get("rationale", "")))

    rev = change.get("reversibility") or {}
    if rev.get("value") in ("irreversible", "reversible_with_data_loss"):
        out.append(("reversibility", rev.get("cost") or rev.get("rationale", "")))

    dd = change.get("data_durability") or {}
    if dd.get("value") in ("unrecoverable_loss", "recoverable_loss"):
        out.append(("data", dd.get("rationale", "")))
    elif dd.get("at_risk"):
        out.append(("data", "; ".join(str(a) for a in dd["at_risk"][:2])))

    st = change.get("state_confidence") or {}
    if st.get("value") in ("drift_detected", "state_stale"):
        out.append(("state", st.get("rationale", "")))

    av = change.get("availability_impact") or {}
    if av.get("value") in ("interrupts", "at_risk"):
        out.append(("availability", av.get("rationale", "")))

    return out


_C = {
    "blocking": "\033[1;31m", "unknown": "\033[1;33m", "caution": "\033[33m",
    "informational": "\033[32m", "safe": "\033[1;32m", "blocked": "\033[1;31m",
    "dim": "\033[2m", "bold": "\033[1m", "reset": "\033[0m",
}


def supports_colour(stream: TextIO) -> bool:
    if os.environ.get("NO_COLOR") is not None:
        return False
    if os.environ.get("FORCE_COLOR"):
        return True
    return bool(getattr(stream, "isatty", lambda: False)())


class _Ink:
    def __init__(self, on: bool) -> None:
        self.on = on

    def __call__(self, text: str, style: str) -> str:
        if not self.on or style not in _C:
            return text
        return f"{_C[style]}{text}{_C['reset']}"


def _wrap(text, width):
    """Plain greedy wrap. Returns lines with no indentation; the caller owns
    alignment, which is the only way to keep hanging indents correct."""
    words = str(text).split()
    if not words:
        return [""]
    lines, cur = [], ""
    for w in words:
        if cur and len(cur) + 1 + len(w) > width:
            lines.append(cur)
            cur = w
        else:
            cur = f"{cur} {w}".strip()
    if cur:
        lines.append(cur)
    return lines


def render(manifest: Dict[str, Any], stream: Optional[TextIO] = None,
           colour: Optional[bool] = None, width: int = 92) -> str:
    stream = stream or sys.stdout
    ink = _Ink(supports_colour(stream) if colour is None else colour)
    changes = manifest.get("changes") or []
    verdict = manifest.get("verdict") or {}
    ext = manifest.get("extensions") or {}
    access = ((manifest.get("producer") or {}).get("access") or {}).get("live_state", "not_attempted")
    out: List[str] = []

    mode = {"queried": "live state verified",
            "unavailable": "live read attempted and unavailable",
            "not_attempted": "plan-only"}.get(access, access)
    producer = manifest.get("producer") or {}
    out.append(f"{producer.get('name','blastcheck')} {producer.get('version','')} — "
               f"{len(changes)} change(s) assessed, {mode}")
    out.append("")

    by_sev: Dict[str, List[dict]] = {s: [] for s in _SEVERITY_ORDER}
    for c in changes:
        by_sev.setdefault(c.get("severity", "informational"), []).append(c)

    baseline = 0
    for sev in _SEVERITY_ORDER:
        if sev == "informational":
            continue
        for c in by_sev.get(sev, []):
            found = _findings(c)
            if not found:
                # Unknown solely because of the run's baseline limits.
                baseline += 1
                continue
            out.append(f"  {ink(f'{_SEVERITY_LABEL[sev]:>7}', sev)}  {ink(c.get('address',''), 'bold')}")
            pad = " " * 11
            for label, text in found:
                head = f"{pad}{label:<14}"
                lines = _wrap(text, width - len(head))
                out.append(head + lines[0])
                for extra in lines[1:]:
                    out.append(" " * len(head) + extra)
            sp = c.get("security_posture") or {}
            if sp.get("confidence") == "low" and sp.get("value") == "widened":
                out.append(pad + ink("(pattern match, not a determination)", "dim"))
            out.append("")

    if baseline:
        out.append(ink(f"  {baseline} further change(s) are undetermined only because live state "
                       f"was not queried.", "dim"))
        out.append("")

    ok = len(by_sev.get("informational", []))
    if ok:
        out.append(ink(f"  {ok} change(s) had nothing to flag.", "dim"))
        out.append("")

    decision = verdict.get("decision", "unknown")
    style = {"safe": "safe", "blocked": "blocked", "caution": "caution"}.get(decision, "unknown")
    out.append(f"verdict: {ink(decision, style)}")
    for line in _wrap(verdict.get("rationale", ""), width - 2):
        out.append("  " + line)

    # Things a reader would be wrong not to know about.
    notes: List[str] = []
    if ext.get("drift_outside_this_plan"):
        n = len(ext["drift_outside_this_plan"])
        notes.append(f"{n} resource(s) outside this plan have also drifted from recorded state")
    if ext.get("plan_errored"):
        notes.append("this plan errored during planning, so it is incomplete and what is absent proves nothing")
    if ext.get("unrecognised_plan_format"):
        notes.append(f"plan format {ext['unrecognised_plan_format']} has never been exercised by this tool")
    if ext.get("assessment_note"):
        notes.append(ext["assessment_note"])
    if access == "not_attempted" and decision != "safe":
        notes.append("state was never verified against reality — re-run with --live to certify")
    if notes:
        out.append("")
        for n in notes:
            lines = _wrap(n, width - 6)
            out.append("  " + ink("·", "dim") + " " + lines[0])
            for extra in lines[1:]:
                out.append("    " + extra)
    out.append("")
    return "\n".join(out)


# ── Gating ───────────────────────────────────────────────────────────────────
#
# blastcheck stays a producer: the default is still exit 0 whatever the verdict.
# `--fail-on` does not change that — it lets the OPERATOR state their own policy
# on the command line, which is a different thing from the tool deciding for
# them. Without it, expressing a decision you have already made requires parsing
# JSON in shell, and that friction lands exactly when someone is deciding
# whether to adopt this at all.

FAIL_ON_LEVELS = {
    # flag value -> the verdicts that should fail the command
    "never": set(),
    "blocked": {"blocked"},
    "unknown": {"blocked", "unknown"},
    "caution": {"blocked", "unknown", "caution"},
    "unsafe": {"blocked", "unknown", "caution"},
}


def gate_exit_code(manifest: Dict[str, Any], fail_on: str) -> int:
    """2 when the verdict trips the operator's threshold, 0 otherwise.

    Two rather than one, deliberately: 1 already means blastcheck could not run.
    A pipeline must be able to tell "this plan is dangerous" apart from "the
    tool is broken", because those call for opposite responses."""
    triggers = FAIL_ON_LEVELS.get(fail_on or "never", set())
    decision = (manifest.get("verdict") or {}).get("decision", "unknown")
    return 2 if decision in triggers else 0
