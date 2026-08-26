"""
Live-state probes: the optional enrichment that lets a verdict be earned.

WHY THIS IS SHAPED THE WAY IT IS

Three constraints drove every decision here, and they are worth stating because
each one rules out an obvious alternative.

**blastcheck must keep zero runtime dependencies.** Pulling in azure-identity
and the mgmt SDKs would add a dependency tree larger than this project, for a
feature most runs will not use. So probes shell out to the cloud vendor's own
CLI, which anyone doing this work already has installed.

**blastcheck must never handle a credential.** Not read one, not store one, not
accept one as a flag. Shelling out to an authenticated CLI means the operator's
existing `az login` / SSO / managed identity does the work and blastcheck never
sees a secret. A tool that asks you to hand it cloud credentials in order to
tell you whether a change is safe has an obvious problem.

**blastcheck must never write.** Every command is built from a fixed template
with a read-only verb; nothing here is assembled from user input in a way that
could reach a mutating call. See _READ_ONLY_VERBS.

A probe that fails — no CLI, not logged in, no permission, timeout, resource
absent — does NOT degrade to a guess. It produces an Observation carrying the
reason, the dimension stays `unknown`, and the manifest says why. That is the
same rule as everywhere else in this codebase: the absence of an answer is not
an answer.
"""

from __future__ import annotations

import json
import shutil
import subprocess
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

__all__ = ["Observation", "Prober", "AzureCliProber", "prober_for", "probe_plan"]

# The only verbs any prober may invoke. A mutating verb cannot reach a
# subprocess call because it is not in this set and the command builders below
# take the verb from here, never from a caller.
_READ_ONLY_VERBS = frozenset({"show", "list", "get"})


class Observation:
    """What a probe saw, or why it saw nothing.

    `found is None` means the probe could not run at all — a distinct fact from
    `found is False`, which means the probe ran and the resource is not there.
    Collapsing those two would let "I could not look" read as "it is gone"."""

    __slots__ = ("address", "found", "attributes", "error", "observed_at")

    def __init__(self, address: str, found: Optional[bool] = None,
                 attributes: Optional[Dict[str, Any]] = None,
                 error: Optional[str] = None, observed_at: Optional[str] = None):
        self.address = address
        self.found = found
        self.attributes = attributes or {}
        self.error = error
        self.observed_at = observed_at or datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    @property
    def usable(self) -> bool:
        return self.found is not None and self.error is None

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return f"<Observation {self.address} found={self.found} error={self.error!r}>"


class Prober:
    """Interface a provider probe implements. Deliberately tiny: everything the
    rest of the codebase needs is one call that either returns facts or returns
    the reason there are none."""

    name = "none"

    def available(self) -> Optional[str]:
        """None if usable, else a human reason it is not."""
        return "no prober configured"

    def probe(self, rc: Dict[str, Any]) -> Observation:  # pragma: no cover - interface
        raise NotImplementedError


def _run(args: List[str], timeout: float) -> "tuple[int, str, str]":
    """Run a read-only command. Never invoked with a shell, so nothing here is
    interpretable as shell syntax."""
    if not args or args[0] in ("", None):
        raise ValueError("empty command")
    try:
        p = subprocess.run(args, capture_output=True, text=True, timeout=timeout, shell=False)
        return p.returncode, p.stdout, p.stderr
    except subprocess.TimeoutExpired:
        return 124, "", f"timed out after {timeout:.0f}s"
    except OSError as e:
        return 127, "", str(e)


class AzureCliProber(Prober):
    """Reads live Azure state through the operator's own `az` session.

    Uses `az resource show --ids <arm id>`, which works for ANY Azure resource
    type rather than needing a per-service command. That generality is the whole
    reason this is worth doing: a per-type implementation would recreate the
    narrow-scope problem the layered assessment just fixed."""

    name = "azure"

    def __init__(self, timeout: float = 20.0, runner=None):
        self.timeout = timeout
        self._run = runner or _run

    def available(self) -> Optional[str]:
        if shutil.which("az") is None:
            return "the `az` CLI is not installed or not on PATH"
        rc, out, err = self._run(["az", "account", "show", "--output", "json"], self.timeout)
        if rc != 0:
            return "the `az` CLI is not logged in (`az login`), or the session has expired"
        return None

    def probe(self, rc_entry: Dict[str, Any]) -> Observation:
        addr = str(rc_entry.get("address", ""))
        before = (rc_entry.get("change") or {}).get("before") or {}
        resource_id = before.get("id") if isinstance(before, dict) else None
        if not resource_id or not str(resource_id).startswith("/subscriptions/"):
            return Observation(addr, error="no Azure resource id in the plan's prior state, so there "
                                           "is nothing to look up (this is normal for a create)")

        verb = "show"
        assert verb in _READ_ONLY_VERBS
        code, out, err = self._run(
            ["az", "resource", verb, "--ids", str(resource_id), "--output", "json"], self.timeout)
        if code == 124:
            return Observation(addr, error=err)
        if code != 0:
            low = (err or "").lower()
            if "not found" in low or "resourcenotfound" in low:
                return Observation(addr, found=False)
            if "authorization" in low or "forbidden" in low or "does not have authorization" in low:
                return Observation(addr, error="the signed-in identity is not authorised to read this resource")
            return Observation(addr, error=(err or "az resource show failed").strip()[:200])
        try:
            body = json.loads(out)
        except ValueError:
            return Observation(addr, error="az returned output that was not JSON")

        # Flatten one level of `properties`, which is where ARM puts most of what
        # matters, so callers see a single namespace.
        attrs: Dict[str, Any] = {k: v for k, v in body.items() if k != "properties"}
        props = body.get("properties")
        if isinstance(props, dict):
            for k, v in props.items():
                attrs.setdefault(k, v)
        return Observation(addr, found=True, attributes=attrs)


_PROBERS = {"azure": AzureCliProber}


def prober_for(provider: str, timeout: float = 20.0) -> Prober:
    cls = _PROBERS.get((provider or "").lower())
    if cls is None:
        raise ValueError(f"no live prober for {provider!r}; available: {', '.join(sorted(_PROBERS))}")
    return cls(timeout=timeout)


def probe_plan(plan: Dict[str, Any], prober: Prober,
               limit: int = 200) -> Dict[str, Observation]:
    """Probe every mutating change in the plan. Returns address -> Observation.

    A cap exists because a large plan against a slow API is a way to hang a
    pipeline; anything beyond it is reported as unprobed rather than silently
    omitted, by the caller."""
    out: Dict[str, Observation] = {}
    n = 0
    for rc in plan.get("resource_changes", []) or []:
        acts = set((rc.get("change") or {}).get("actions") or [])
        if acts <= {"no-op", "read"}:
            continue
        if n >= limit:
            break
        addr = str(rc.get("address", ""))
        try:
            out[addr] = prober.probe(rc)
        except Exception as e:  # a prober bug must not take the whole run down
            out[addr] = Observation(addr, error=f"probe raised {type(e).__name__}: {e}"[:200])
        n += 1
    return out
