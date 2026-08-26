"""blastcheck — reference producer of Impact Manifest documents from a Terraform plan."""
from .core import build_manifest, load_plan, PlanError, SCHEMA_VERSION, PRODUCER_VERSION

__version__ = PRODUCER_VERSION
__all__ = ["build_manifest", "load_plan", "PlanError", "SCHEMA_VERSION", "PRODUCER_VERSION"]
