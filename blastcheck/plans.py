"""
Getting a JSON plan from whatever the user actually has.

`terraform show -json tfplan > plan.json` is a step people forget, get wrong, or
pipe incorrectly, and being told "no `resource_changes` array" because you handed
the tool a binary plan file is a poor first experience. If the input is a saved
plan rather than JSON, run the conversion — with the same binary that produced
it — instead of making the user do it.
"""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path
from typing import Optional, Tuple

__all__ = ["read_plan_text", "PlanReadError"]

# `tofu` first: someone who has both almost certainly wants OpenTofu, and either
# produces an identical JSON plan format.
_ENGINES = ("tofu", "terraform")


class PlanReadError(RuntimeError):
    pass


def _looks_like_json(raw: bytes) -> bool:
    head = raw.lstrip()[:1]
    return head in (b"{", b"[")


def read_plan_text(path: Optional[str], stdin_text: Optional[str] = None) -> Tuple[str, Optional[str]]:
    """Return (json_text, note). `note` describes any conversion performed, so
    the caller can tell the user what happened rather than doing it silently."""
    if path is None:
        if stdin_text is None:
            raise PlanReadError("no plan given")
        return stdin_text, None

    p = Path(path)
    try:
        raw = p.read_bytes()
    except OSError as e:
        raise PlanReadError(f"cannot read plan: {e}")

    if _looks_like_json(raw):
        try:
            return raw.decode("utf-8"), None
        except UnicodeDecodeError as e:
            raise PlanReadError(f"plan is not valid UTF-8: {e}")

    # A binary saved plan. Convert it with the engine that wrote it.
    engine = next((e for e in _ENGINES if shutil.which(e)), None)
    if engine is None:
        raise PlanReadError(
            f"`{path}` is not JSON — it looks like a saved Terraform plan, and neither "
            "`tofu` nor `terraform` is on PATH to convert it. Run "
            f"`terraform show -json {path} > plan.json` and pass that instead.")
    try:
        r = subprocess.run([engine, "show", "-json", str(p)],
                           capture_output=True, text=True, timeout=120, shell=False,
                           cwd=str(p.parent if p.parent.as_posix() else "."))
    except (OSError, subprocess.TimeoutExpired) as e:
        raise PlanReadError(f"`{engine} show -json` failed: {e}")
    if r.returncode != 0:
        raise PlanReadError(
            f"`{engine} show -json {p.name}` failed: {(r.stderr or '').strip()[:300]}\n"
            "A saved plan can only be read from the working directory it was created in, "
            "with the same provider versions.")
    try:
        json.loads(r.stdout)
    except ValueError as e:
        raise PlanReadError(f"`{engine} show -json` did not produce valid JSON: {e}")
    return r.stdout, f"converted with `{engine} show -json`"
