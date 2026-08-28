#!/usr/bin/env bash
#
# Prove --live actually works against a real cloud.
#
#     scripts/live-check.sh ~/infra/some-terraform-dir
#     scripts/live-check.sh --plan /tmp/plan.json --provider azure
#
# Every --live code path in this project is currently tested against injected
# fakes. Fakes agree with whatever the code expects, which is exactly the
# property you do not want when the question is "does the real CLI return the
# shape we assumed?". This script answers that question and nothing else.
#
# What it is actually checking, in order of how badly each would matter:
#
#   1. that live probing RAN. The dangerous failure is not a crash, it is
#      --live silently degrading to plan-only: no CLI, not logged in, no
#      permission. Every dimension stays `unknown`, the run looks normal, and
#      the operator concludes the tool is useless rather than unauthenticated.
#      producer.access.live_state distinguishes `queried` from `unavailable`,
#      and this script fails loudly on anything but `queried`.
#
#   2. that probing CHANGED something. If live_state is `queried` but not one
#      dimension moved off `unknown`, the prober is reaching the cloud and
#      failing to match anything to recorded state -- a real bug that no unit
#      test with a fake could ever surface.
#
#   3. that nothing got *worse*. A dimension going from a determination back
#      to `unknown` under --live would mean live data is being read as less
#      trustworthy than no data, which is backwards.
#
# It never writes to your cloud, and it never asks you for a credential --
# blastcheck shells out to the CLI you are already logged into.

set -euo pipefail

PROVIDER=""
PLAN=""
TFDIR=""

while [ $# -gt 0 ]; do
  case "$1" in
    --plan)     PLAN="${2:?--plan needs a path}"; shift 2 ;;
    --provider) PROVIDER="${2:?--provider needs azure or aws}"; shift 2 ;;
    -h|--help)  sed -n '2,34p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *)          TFDIR="$1"; shift ;;
  esac
done

die() { printf '\n\033[31mFAIL\033[0m  %s\n\n' "$*" >&2; exit 1; }
say() { printf '\033[36m==>\033[0m %s\n' "$*"; }
ok()  { printf '\033[32m ok \033[0m %s\n' "$*"; }
warn(){ printf '\033[33mnote\033[0m  %s\n' "$*"; }

command -v blastcheck >/dev/null || die "blastcheck is not on PATH (pip install blastcheck)"
say "using $(blastcheck --version)"

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

# ------------------------------------------------------------------ the plan

if [ -z "$PLAN" ]; then
  [ -n "$TFDIR" ] || die "give me a terraform directory, or --plan <file>

    scripts/live-check.sh ~/infra/prod
    scripts/live-check.sh --plan /tmp/plan.json --provider azure"
  [ -d "$TFDIR" ] || die "$TFDIR is not a directory"
  command -v terraform >/dev/null || die "terraform is not on PATH"

  say "planning in $TFDIR"
  # -refresh is left at its default ON. Refresh is what populates
  # resource_drift, and drift is the one live fact an offline plan carries.
  ( cd "$TFDIR" && terraform plan -out "$work/tfplan" >/dev/null ) \
    || die "terraform plan failed -- fix that first, it is not a blastcheck problem"
  ( cd "$TFDIR" && terraform show -json "$work/tfplan" ) > "$work/plan.json"
  PLAN="$work/plan.json"
  ok "plan captured"
fi

[ -f "$PLAN" ] || die "no such plan file: $PLAN"

changes=$(python3 -c "
import json,sys
d=json.load(open('$PLAN'))
print(len(d.get('resource_changes') or []))")
[ "$changes" -gt 0 ] || die "that plan has zero resource changes -- there is nothing for --live to verify.
       Point this at a plan that actually changes something."
ok "$changes change(s) in the plan"

# Guess the provider from the plan rather than making you remember it.
if [ -z "$PROVIDER" ]; then
  PROVIDER=$(python3 -c "
import json
d = json.load(open('$PLAN'))
types = ' '.join((c.get('type') or '') for c in (d.get('resource_changes') or []))
print('azure' if 'azurerm_' in types else 'aws' if 'aws_' in types else '')")
  [ -n "$PROVIDER" ] || die "could not tell which cloud this plan targets -- pass --provider azure|aws"
  ok "provider looks like $PROVIDER"
fi

# ------------------------------------------------- is the CLI even usable?

case "$PROVIDER" in
  azure)
    command -v az >/dev/null || die "the 'az' CLI is not installed"
    az account show >/dev/null 2>&1 || die "not logged in to Azure -- run: az login"
    acct=$(az account show --query name -o tsv 2>/dev/null || echo "?")
    ok "azure session active: $acct" ;;
  aws)
    command -v aws >/dev/null || die "the 'aws' CLI is not installed"
    aws sts get-caller-identity >/dev/null 2>&1 || die "no usable AWS credentials -- configure a profile or SSO session"
    who=$(aws sts get-caller-identity --query Arn --output text 2>/dev/null || echo "?")
    ok "aws session active: $who" ;;
  *) die "unknown provider '$PROVIDER' (expected azure or aws)" ;;
esac

# ------------------------------------------------------- the two runs

say "run 1 of 2: plan-only (baseline)"
blastcheck --plan "$PLAN" --json > "$work/offline.json" || die "the plan-only run failed"
ok "baseline captured"

say "run 2 of 2: --live $PROVIDER  (read-only; no credential is handled)"
if ! blastcheck --plan "$PLAN" --live "$PROVIDER" --json > "$work/live.json" 2>"$work/live.err"; then
  echo; sed 's/^/    /' "$work/live.err" >&2
  die "the --live run exited non-zero"
fi
ok "live run captured"

# ------------------------------------------------------------- the verdict

python3 - "$work/offline.json" "$work/live.json" <<'ENDCHECK'
import json, sys

off = json.load(open(sys.argv[1]))
liv = json.load(open(sys.argv[2]))

DIMS = ["availability_impact", "reversibility", "data_durability",
        "security_posture", "cost_delta", "state_confidence"]

def val(dim):
    return dim.get("value") or dim.get("direction") or "?"

access = (liv.get("producer", {}).get("access", {}) or {}).get("live_state")
print()
print("  producer.access.live_state: %s" % access)

# 1 -- did probing actually happen?
if access != "queried":
    print()
    print("\033[31mFAIL\033[0m  --live did not reach the cloud (live_state=%r)." % access)
    print("      This is the failure mode that looks like success: every dimension")
    print("      stays `unknown` and the run appears normal. Usually it means the")
    print("      CLI is missing, the session expired, or the identity lacks read")
    print("      permission on these resources. Nothing is wrong with the plan.")
    sys.exit(1)
print("  \033[32mok\033[0m  live probing ran")

o_changes = {c["address"]: c for c in off.get("changes", [])}
l_changes = {c["address"]: c for c in liv.get("changes", [])}

improved, regressed, unchanged = [], [], 0
for addr, lc in l_changes.items():
    oc = o_changes.get(addr)
    if not oc:
        continue
    for d in DIMS:
        if d not in lc or d not in oc:
            continue
        o, l = val(oc[d]), val(lc[d])
        if o == l:
            unchanged += 1
        elif o == "unknown" and l != "unknown":
            improved.append((addr, d, o, l))
        elif l == "unknown" and o != "unknown":
            regressed.append((addr, d, o, l))
        else:
            improved.append((addr, d, o, l))

print()
print("  verdict  plan-only: %-10s   --live: %s"
      % (off.get("verdict", {}).get("decision"), liv.get("verdict", {}).get("decision")))
print()

# 3 -- nothing may get worse
if regressed:
    print("\033[31mFAIL\033[0m  %d dimension(s) got WORSE under --live:" % len(regressed))
    for a, d, o, l in regressed[:10]:
        print("      %-46s %-20s %s -> %s" % (a, d, o, l))
    print()
    print("      Live data must never be read as less trustworthy than no data.")
    sys.exit(1)

# 2 -- probing must change something
if not improved:
    print("\033[31mFAIL\033[0m  live probing ran but resolved nothing.")
    print("      %d dimension(s) were compared and every one is unchanged." % unchanged)
    print("      The prober is reaching the cloud and matching nothing to recorded")
    print("      state -- which is a real bug, and one no test with a fake prober")
    print("      could surface. Worth investigating before trusting --live.")
    sys.exit(1)

print("  \033[32mok\033[0m  %d dimension(s) resolved by live state:" % len(improved))
for a, d, o, l in improved[:20]:
    print("      %-46s %-20s %s -> %s" % (a[:44], d, o, l))
if len(improved) > 20:
    print("      ... and %d more" % (len(improved) - 20))

certified = sum(1 for c in l_changes.values()
                if (c.get("state_confidence") or {}).get("value") == "state_matches_reality")
print()
print("  %d of %d change(s) reached state_matches_reality" % (certified, len(l_changes)))
if liv.get("verdict", {}).get("decision") == "safe":
    print("  \033[32mand the plan earned a `safe` verdict -- the first one from real data.\033[0m")
elif certified == len(l_changes):
    print("  every change was verified; `safe` was withheld on the findings themselves,")
    print("  which is the correct behaviour.")
else:
    print("  `safe` is correctly withheld: one unverified change denies it to the plan.")
ENDCHECK

echo
ok "live mode verified against a real $PROVIDER account"
printf '\n  This is the evidence the spec freeze was waiting on. If it passed on a\n'
printf '  real estate, the 1.0 gate is met.\n\n'
