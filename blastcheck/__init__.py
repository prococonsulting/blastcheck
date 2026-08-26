"""blastcheck — reference producer of Impact Manifest documents from a Terraform plan."""
from pathlib import Path

from .core import build_manifest, load_plan, PlanError, SCHEMA_VERSION, PRODUCER_VERSION
from .canonical import canonicalize, compute_digest, attach_integrity, verify_integrity
from .live import Observation, Prober, prober_for, probe_plan

__version__ = PRODUCER_VERSION

_SCHEMA = Path(__file__).resolve().parent / "schema" / "impact-manifest.schema.json"


def schema_path() -> Path:
    """Filesystem path to the pinned Impact Manifest schema shipped with this
    package.

    The schema lives inside the package rather than at the repository root so
    that it travels with an install. A consumer that wants to validate a
    manifest should not have to go find the specification repository, and a
    reference implementation that ships without the contract it implements is
    only half a reference. (0.1.0 shipped exactly that way: the package-data
    glob pointed at a directory outside the package and silently matched
    nothing.)"""
    return _SCHEMA


__all__ = [
    "build_manifest", "load_plan", "PlanError", "SCHEMA_VERSION", "PRODUCER_VERSION",
    "canonicalize", "compute_digest", "attach_integrity", "verify_integrity",
    "schema_path",
    "Observation", "Prober", "prober_for", "probe_plan",
]
