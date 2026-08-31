"""
blastcheck CLI — read a `terraform show -json` plan, emit an Impact Manifest.

    terraform show -json plan.tfplan | blastcheck
    blastcheck --plan plan.json > manifest.json

blastcheck is a PRODUCER, not a gate: it emits the manifest and exits 0 on
success. Turning the manifest into a pass/fail decision is a separate policy
layer (the CI gate). Exit codes reflect execution, not the verdict:
  0  a manifest was produced, or --verify confirmed a digest
  1  blastcheck could not run: bad input, unreadable file, --verify failed
  2  the verdict tripped the threshold the operator set with --fail-on

1 and 2 are deliberately distinct. A pipeline must be able to tell "this plan is
dangerous" apart from "the tool is broken", because those call for opposite
responses.

OUTPUT FORMAT

Human-readable on a terminal, the manifest JSON when stdout is redirected or
piped. So `blastcheck --plan p.json` is readable and
`blastcheck --plan p.json > manifest.json` still writes a manifest, without
anyone having to know a flag. `--json` and `--text` force it either way.
"""

from __future__ import annotations

import argparse
import json
import os
import sys

from .canonical import CanonicalizationError, attach_integrity, verify_integrity
from .config import apply_ignores, load_config
from .plans import PlanReadError, read_plan_text
from .live import probe_plan, probe_recovery_plan, prober_for
from .core import build_manifest, load_plan, PlanError, PRODUCER_VERSION
from .render import FAIL_ON_LEVELS, gate_exit_code, render, render_rules


def main(argv=None) -> int:
    p = argparse.ArgumentParser(
        prog="blastcheck",
        description="Emit an Impact Manifest (change-safety assertion) from a `terraform show -json` plan.",
    )
    p.add_argument("target", nargs="?", metavar="PLAN|rules",
                   help="a `terraform show -json` file, a saved .tfplan (converted automatically), "
                        "or the word `rules` to list what blastcheck knows. Reads stdin if omitted.")
    p.add_argument("--plan", metavar="FILE",
                   help="same as the positional argument; kept for scripts that already use it")
    p.add_argument("--config", metavar="FILE",
                   help="path to a blastcheck config file (default: .blastcheck.json, searched "
                        "upward from the working directory)")
    p.add_argument("--json", dest="as_json", action="store_true",
                   help="emit the Impact Manifest as JSON (the default when stdout is not a terminal)")
    p.add_argument("--text", dest="as_text", action="store_true",
                   help="emit the human-readable summary even when redirected")
    p.add_argument("--fail-on", choices=sorted(FAIL_ON_LEVELS), default="never", metavar="LEVEL",
                   help="exit 2 when the verdict is this bad or worse: "
                        + ", ".join(sorted(FAIL_ON_LEVELS))
                        + ". Default `never` — blastcheck is a producer, and what a verdict should do "
                          "to your pipeline is your policy, not its decision.")
    p.add_argument("--no-color", dest="no_color", action="store_true",
                   help="disable colour (NO_COLOR in the environment does the same)")
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
    p.add_argument("--include-provider-ids", action="store_true",
                   help="embed each cloud's own resource identifier (from the plan's "
                        "recorded state) in the manifest, so downstream tools can join "
                        "to live state without guessing. OFF by default because these "
                        "identifiers expose account layout (subscription GUIDs, account "
                        "ids, project ids) - an id-bearing manifest is not safe to paste "
                        "into a public PR comment or CI log. Deliberately not a config-"
                        "file option: inclusion is an explicit per-invocation choice.")
    p.add_argument("--version", action="version", version=f"blastcheck {PRODUCER_VERSION}")
    args = p.parse_args(argv)

    # `blastcheck rules` — show what this build actually knows. Without it the
    # 110 precisely-classified types and 41 pack rules are invisible, and a tool
    # whose knowledge you cannot inspect reads as a toy.
    if args.target == "rules":
        sys.stdout.write(render_rules(colour=False if args.no_color else None,
                                      stream=sys.stdout))
        return 0

    config = load_config(explicit=args.config)
    for err in config.errors:
        print(f"blastcheck: ignoring unreadable config ({err})", file=sys.stderr)
    # Explicit flags beat the file; the file beats the built-in default.
    if args.fail_on == "never" and config.fail_on in FAIL_ON_LEVELS:
        args.fail_on = config.fail_on
    if not args.live and config.live:
        args.live = config.live
    if config.live_timeout and args.live_timeout == 20.0:
        args.live_timeout = float(config.live_timeout)

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

    plan_path = args.plan or args.target
    try:
        text, note = read_plan_text(plan_path, None if plan_path else sys.stdin.read())
    except PlanReadError as e:
        print(f"blastcheck: {e}", file=sys.stderr)
        return 1
    if note:
        print(f"blastcheck: {plan_path} {note}", file=sys.stderr)

    try:
        plan = load_plan(text)
    except PlanError as e:
        print(f"blastcheck: {e}", file=sys.stderr)
        return 1

    observations = None
    recovery = None
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
            total = sum(1 for rc in (plan.get("resource_changes") or [])
                        if not (set((rc.get("change") or {}).get("actions") or []) <= {"no-op", "read"}))
            # A silent minute while 200 resources are probed reads as a hang.
            print(f"blastcheck: reading live state for {total} resource(s) via {prober.name} "
                  f"(up to {args.live_timeout:.0f}s each)...", file=sys.stderr)
            observations = probe_plan(plan, prober)
            usable = sum(1 for o in observations.values() if o.usable)
            recovery = probe_recovery_plan(plan, prober)
            checked = sum(1 for o in recovery.values() if o.usable)
            print(f"blastcheck: live read {usable}/{len(observations)} resource(s) via {prober.name}",
                  file=sys.stderr)
            if recovery:
                print(f"blastcheck: recovery points checked for {checked}/{len(recovery)} "
                      "resource(s) being destroyed", file=sys.stderr)

    try:
        manifest = build_manifest(plan, observations=observations, recovery=recovery,
                                  include_provider_ids=args.include_provider_ids)
    except PlanError as e:
        print(f"blastcheck: {e}", file=sys.stderr)
        return 1

    manifest = apply_ignores(manifest, config)
    if config.source and (manifest.get("extensions") or {}).get("ignored"):
        n = len((manifest["extensions"] or {}).get("ignored") or {})
        print(f"blastcheck: {n} change(s) downgraded by ignore rules in {config.source} "
              "(findings are kept in the manifest)", file=sys.stderr)

    if args.sign:
        try:
            manifest = attach_integrity(manifest)
        except CanonicalizationError as e:
            print(f"blastcheck: cannot canonicalize for signing: {e}", file=sys.stderr)
            return 1

    # Format: explicit flags win; otherwise a terminal gets prose and a pipe
    # gets the manifest, so redirection keeps working without a flag.
    as_json = args.as_json or (not args.as_text and not sys.stdout.isatty())
    try:
        if as_json:
            json.dump(manifest, sys.stdout, indent=None if args.compact else 2)
            sys.stdout.write("\n")
        else:
            sys.stdout.write(render(manifest, sys.stdout,
                                    colour=False if args.no_color else None))
        sys.stdout.flush()
    except BrokenPipeError:
        # `blastcheck ... | head` closes the pipe early. That is a normal way to
        # use a CLI, not an error, and a Python traceback in response makes the
        # tool look broken. Redirect the remaining stdout to devnull so the
        # interpreter's own shutdown flush cannot raise a second time.
        try:
            os.dup2(os.open(os.devnull, os.O_WRONLY), sys.stdout.fileno())
        except OSError:
            pass
        return 0

    return gate_exit_code(manifest, args.fail_on)


def _entry() -> int:
    try:
        return main()
    except KeyboardInterrupt:
        # 130 is the conventional shell code for SIGINT. Silent, because a user
        # who pressed Ctrl-C does not need a stack trace explaining it.
        print("", file=sys.stderr)
        return 130


if __name__ == "__main__":
    raise SystemExit(_entry())
