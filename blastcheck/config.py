"""
Per-repository configuration.

WHY JSON AND NOT TOML

`tomllib` is Python 3.11+, and this package supports 3.9. TOML would therefore
cost a runtime dependency for a convenience, and zero runtime dependencies is a
property this project keeps. The packs are JSON for the same reason, so a repo
with a `.blastcheck.json` is at least consistent with what it already contains.

WHY IGNORES ARE RECORDED, NOT REMOVED

An ignore does not delete a finding. It lowers the change's severity so it stops
gating a pipeline, and the finding stays in the manifest with a note saying it
was ignored and by which pattern. A configuration file that could make a finding
vanish would be the most effective way yet invented to produce a false `safe`,
and it would be invisible to whoever reads the manifest later.
"""

from __future__ import annotations

import fnmatch
import json
from pathlib import Path
from typing import Any, Dict, List, Optional

__all__ = ["Config", "load_config", "CONFIG_NAMES"]

CONFIG_NAMES = (".blastcheck.json", "blastcheck.json")


class Config:
    def __init__(self, data: Optional[Dict[str, Any]] = None, source: Optional[str] = None):
        data = data or {}
        self.source = source
        self.fail_on: Optional[str] = data.get("fail_on")
        self.live: Optional[str] = data.get("live")
        self.live_timeout: Optional[float] = data.get("live_timeout")
        # Glob patterns matched against a change's address.
        self.ignore: List[str] = [str(p) for p in (data.get("ignore") or [])]
        self.errors: List[str] = []

    def ignored_by(self, address: str) -> Optional[str]:
        """The pattern that ignores this address, or None. Returning the pattern
        rather than a boolean is deliberate: the manifest records WHICH rule
        suppressed a finding, so nobody has to guess later."""
        for pat in self.ignore:
            if fnmatch.fnmatchcase(address, pat):
                return pat
        return None

    def __bool__(self) -> bool:
        return bool(self.source)


def load_config(start: Optional[Path] = None, explicit: Optional[str] = None) -> Config:
    """Find and load configuration.

    An explicit --config path that does not exist is an error the caller should
    surface; a missing discovered file is not. Searching upward from the working
    directory means the config sits with the repository rather than with
    whichever subdirectory the pipeline happened to run from."""
    if explicit:
        p = Path(explicit)
        try:
            return Config(json.loads(p.read_text(encoding="utf-8")), str(p))
        except Exception as e:
            c = Config()
            c.errors.append(f"{p}: {type(e).__name__}: {e}")
            return c

    here = (start or Path.cwd()).resolve()
    for directory in [here, *here.parents]:
        for name in CONFIG_NAMES:
            p = directory / name
            if p.is_file():
                try:
                    return Config(json.loads(p.read_text(encoding="utf-8")), str(p))
                except Exception as e:
                    c = Config()
                    c.errors.append(f"{p}: {type(e).__name__}: {e}")
                    return c
    return Config()


def apply_ignores(manifest: Dict[str, Any], config: Config) -> Dict[str, Any]:
    """Downgrade ignored changes and record that it happened.

    Severity drops to `informational` so an ignore stops a gate, but every
    dimension, rationale and piece of evidence is left exactly as it was. A
    reader of the manifest can still see precisely what was found and that
    somebody chose to accept it."""
    if not config.ignore:
        return manifest
    ignored = {}
    for change in manifest.get("changes") or []:
        pattern = config.ignored_by(str(change.get("address", "")))
        if not pattern:
            continue
        was = change.get("severity")
        if was == "informational":
            continue
        change["severity"] = "informational"
        change["rationale"] = (f"Ignored by configuration pattern `{pattern}`. The findings below "
                               f"stand and were originally graded `{was}`; only the severity was "
                               "lowered so this does not gate a pipeline.")
        ignored[str(change.get("address", ""))] = {"pattern": pattern, "original_severity": was}

    if ignored:
        ext = manifest.setdefault("extensions", {})
        ext["ignored"] = ignored
        if config.source:
            ext["config_source"] = config.source
        # The verdict was computed before the downgrade, so recompute it or the
        # summary would contradict the changes it summarises.
        from .core import _verdict
        manifest["verdict"] = _verdict(manifest.get("changes") or [])
    return manifest
