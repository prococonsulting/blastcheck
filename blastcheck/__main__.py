"""
blastcheck CLI — read a `terraform show -json` plan, emit an Impact Manifest.

    terraform show -json plan.tfplan | blastcheck
    blastcheck --plan plan.json > manifest.json

blastcheck is a PRODUCER, not a gate: it emits the manifest and exits 0 on
success. Turning the manifest into a pass/fail decision is a separate policy
layer (the CI gate). Exit codes reflect execution, not the verdict:
  0  a manifest was produced
  1  bad input / no supported resources
"""

from __future__ import annotations

import argparse
import json
import sys

from .core import build_manifest, load_plan, PlanError, PRODUCER_VERSION


def main(argv=None) -> int:
    p = argparse.ArgumentParser(
        prog="blastcheck",
        description="Emit an Impact Manifest (change-safety assertion) from a `terraform show -json` plan.",
    )
    p.add_argument("--plan", metavar="FILE",
                   help="path to `terraform show -json` output; reads stdin if omitted")
    p.add_argument("--compact", action="store_true", help="emit compact JSON (default is indented)")
    p.add_argument("--version", action="version", version=f"blastcheck {PRODUCER_VERSION}")
    args = p.parse_args(argv)

    try:
        text = open(args.plan, encoding="utf-8").read() if args.plan else sys.stdin.read()
    except OSError as e:
        print(f"blastcheck: cannot read plan: {e}", file=sys.stderr)
        return 1

    try:
        manifest = build_manifest(load_plan(text))
    except PlanError as e:
        print(f"blastcheck: {e}", file=sys.stderr)
        return 1

    json.dump(manifest, sys.stdout, indent=None if args.compact else 2)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
