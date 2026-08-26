"""
blastcheck CLI — read a `terraform show -json` plan, emit an Impact Manifest.

    terraform show -json plan.tfplan | blastcheck
    blastcheck --plan plan.json > manifest.json

blastcheck is a PRODUCER, not a gate: it emits the manifest and exits 0 on
success. Turning the manifest into a pass/fail decision is a separate policy
layer (the CI gate). Exit codes reflect execution, not the verdict:
  0  a manifest was produced, or --verify confirmed a digest
  1  bad input / no supported resources / --verify failed
"""

from __future__ import annotations

import argparse
import json
import sys

from .canonical import CanonicalizationError, attach_integrity, verify_integrity
from .live import probe_plan, prober_for
from .core import build_manifest, load_plan, PlanError, PRODUCER_VERSION


def main(argv=None) -> int:
    p = argparse.ArgumentParser(
        prog="blastcheck",
        description="Emit an Impact Manifest (change-safety assertion) from a `terraform show -json` plan.",
    )
    p.add_argument("--plan", metavar="FILE",
                   help="path to `terraform show -json` output; reads stdin if omitted")
    p.add_argument("--compact", action="store_true", help="emit compact JSON (default is indented)")
    p.add_argument("--sign", action="store_true",
                   help="attach integrity.digest over the JCS-canonicalized manifest (RFC 8785), "
                        "making the document tamper-evident")
    p.add_argument("--verify", metavar="MANIFEST",
                   help="verify an existing manifest's integrity.digest and exit; "
                        "exits 1 if the digest is absent or does not match")
    p.add_argument("--live", metavar="PROVIDER", nargs="?", const="azure",
                   help="verify recorded state against live cloud reality using the provider's own "
                        "CLI and your existing login (default: azure). blastcheck never reads, stores "
                        "or accepts a credential, and only ever issues read-only commands. This is the "
                        "only mode in which a `safe` verdict is reachable.")
    p.add_argument("--live-timeout", type=float, default=20.0, metavar="SECONDS",
                   help="per-resource timeout for live reads (default: 20)")
    p.add_argument("--version", action="version", version=f"blastcheck {PRODUCER_VERSION}")
    args = p.parse_args(argv)

    # --verify is a distinct mode: it consumes a manifest, not a plan.
    if args.verify:
        try:
            existing = json.load(open(args.verify, encoding="utf-8"))
        except (OSError, ValueError) as e:
            print(f"blastcheck: cannot read manifest: {e}", file=sys.stderr)
            return 1
        if verify_integrity(existing):
            print(f"blastcheck: {args.verify}: digest OK", file=sys.stderr)
            return 0
        # Absent and mismatched are reported separately: "nobody signed this"
        # and "someone changed this" are different facts, and collapsing them
        # is the same mistake as reading `unknown` as `safe`.
        if not (existing.get("integrity") or {}).get("digest"):
            print(f"blastcheck: {args.verify}: no integrity.digest present — "
                  "unsigned, not verified", file=sys.stderr)
        else:
            print(f"blastcheck: {args.verify}: DIGEST MISMATCH — this manifest "
                  "has been modified since it was signed", file=sys.stderr)
        return 1

    try:
        text = open(args.plan, encoding="utf-8").read() if args.plan else sys.stdin.read()
    except OSError as e:
        print(f"blastcheck: cannot read plan: {e}", file=sys.stderr)
        return 1

    try:
        plan = load_plan(text)
    except PlanError as e:
        print(f"blastcheck: {e}", file=sys.stderr)
        return 1

    observations = None
    if args.live:
        try:
            prober = prober_for(args.live, timeout=args.live_timeout)
        except ValueError as e:
            print(f"blastcheck: {e}", file=sys.stderr)
            return 1
        # An unavailable prober is NOT a fatal error. The manifest is still
        # worth producing; it just records `access.live_state: unavailable` and
        # every state verdict stays unverified, with the reason stated. Exiting
        # here would trade a useful honest answer for no answer at all.
        why = prober.available()
        if why:
            print(f"blastcheck: live checks unavailable ({why}); continuing plan-only",
                  file=sys.stderr)
            observations = {}
        else:
            observations = probe_plan(plan, prober)
            usable = sum(1 for o in observations.values() if o.usable)
            print(f"blastcheck: live read {usable}/{len(observations)} resource(s) via {prober.name}",
                  file=sys.stderr)

    try:
        manifest = build_manifest(plan, observations=observations)
    except PlanError as e:
        print(f"blastcheck: {e}", file=sys.stderr)
        return 1

    if args.sign:
        try:
            manifest = attach_integrity(manifest)
        except CanonicalizationError as e:
            print(f"blastcheck: cannot canonicalize for signing: {e}", file=sys.stderr)
            return 1

    json.dump(manifest, sys.stdout, indent=None if args.compact else 2)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
