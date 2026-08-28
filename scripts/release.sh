#!/usr/bin/env bash
#
# One command to cut a blastcheck release.
#
#     scripts/release.sh 0.8.0
#
# It bumps the version, proves the artifact actually works, commits, pushes,
# tags once, watches the workflow, and confirms PyPI is serving the result.
#
# The checks in here are not defensive padding. Every one corresponds to a way
# this project has already shipped, or nearly shipped, something broken: a
# wheel missing its schema, two racing release runs from a double tag push,
# and a job queued forever on a runner label that no longer exists.
#
# Nothing is force-pushed. The tag is only created after the tests pass and a
# real wheel has been installed and exercised.

set -euo pipefail

VERSION="${1:-}"
REPO="prococonsulting/blastcheck"
API="https://api.github.com/repos/${REPO}"

die() { printf '\n\033[31merror\033[0m  %s\n\n' "$*" >&2; exit 1; }
say() { printf '\033[36m==>\033[0m %s\n' "$*"; }
ok()  { printf '\033[32m ok \033[0m %s\n' "$*"; }

[ -n "$VERSION" ] || die "usage: scripts/release.sh <version>    e.g. scripts/release.sh 0.8.0"
[[ "$VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || die "version must look like 1.2.3, got '$VERSION'"

cd "$(git rev-parse --show-toplevel)"

# ---------------------------------------------------------------- pre-flight

# Some sandboxes leave git lock files behind that git itself then cannot
# remove. Move rather than delete, so nothing is destroyed if one is real.
for lock in .git/index.lock .git/HEAD.lock .git/objects/maintenance.lock; do
  if [ -e "$lock" ]; then
    mkdir -p .git/_stale
    mv "$lock" ".git/_stale/$(basename "$lock").$$" 2>/dev/null || true
  fi
done

[ "$(git rev-parse --abbrev-ref HEAD)" = "main" ] || die "not on main"
[ -z "$(git status --porcelain)" ] || die "working tree is dirty - commit or stash first"

git fetch --quiet origin --tags
[ "$(git rev-parse HEAD)" = "$(git rev-parse origin/main)" ] ||
  die "local main and origin/main disagree - pull or push first"

if git ls-remote --tags origin "v$VERSION" | grep -q .; then
  next=$(awk -F. '{printf "%d.%d.%d", $1, $2, $3+1}' <<<"$VERSION")
  die "tag v$VERSION already exists on origin.
       A version can never be replaced once PyPI has it, so use the next one:
           scripts/release.sh $next"
fi

command -v python3 >/dev/null || die "python3 not found"
python3 -c "import build"  2>/dev/null || die "the build module is missing:  pip install build"
python3 -c "import pytest" 2>/dev/null || die "pytest is missing:  pip install -e '.[test]'"
python3 -c "import jsonschema, sys; sys.exit(0 if hasattr(jsonschema, 'Draft202012Validator') else 1)" 2>/dev/null ||
  die "jsonschema is missing or too old (need >=4):  pip install -U 'jsonschema>=4'"

# ---------------------------------------------------------------------- bump

say "setting version to $VERSION"
python3 - "$VERSION" <<'ENDBUMP'
import re, sys, pathlib

# The version literal lives in exactly one place in the package. __init__.py
# re-exports it as __version__; editing that re-export is how a package ends
# up disagreeing with itself.
v = sys.argv[1]
edits = [
    ("blastcheck/core.py", r'(^PRODUCER_VERSION\s*=\s*")[^"]+(")'),
    ("pyproject.toml",     r'(^version\s*=\s*")[^"]+(")'),
]
for path, pat in edits:
    p = pathlib.Path(path)
    s = p.read_text()
    s2, n = re.subn(pat, lambda m: m.group(1) + v + m.group(2), s, count=1, flags=re.M)
    if n != 1:
        sys.exit("could not rewrite the version in %s - pattern matched %d times" % (path, n))
    p.write_text(s2)
    print("    " + path)
ENDBUMP

reported=$(python3 -c "import blastcheck; print(blastcheck.__version__)")
[ "$reported" = "$VERSION" ] || die "package reports $reported after the bump, expected $VERSION"
ok "core.py and pyproject.toml both say $VERSION"

# --------------------------------------------------- prove it before tagging

say "running the suite"
python3 -m pytest -q || die "tests failed - nothing was committed"

say "building a wheel and exercising it in a scratch venv"
# The failure this catches: a wheel that installs cleanly and then cannot
# work, because the schema or the packs were never inside it. That shipped as
# 0.1.0 and had to be yanked. `--version` alone would not have caught it, so
# this runs the two commands that actually read those files.
rm -rf dist build ./*.egg-info
python3 -m build --wheel >/dev/null 2>&1 || die "wheel build failed"

scratch=$(mktemp -d)
trap 'rm -rf "$scratch"' EXIT
python3 -m venv "$scratch/v" >/dev/null
"$scratch/v/bin/pip" install --quiet dist/*.whl || die "the wheel would not install"
"$scratch/v/bin/blastcheck" --version | grep -q "$VERSION" || die "installed wheel reports the wrong version"
"$scratch/v/bin/blastcheck" rules | grep -q "Provider packs" || die "the wheel is missing the provider packs"
"$scratch/v/bin/python" -c "from blastcheck import schema_path; open(schema_path())" \
  >/dev/null 2>&1 || die "the wheel is missing the schema"
ok "wheel installs clean and finds its schema and packs"

# ---------------------------------------------------------------------- ship

say "committing and pushing"
git add blastcheck/core.py pyproject.toml
git commit -qm "blastcheck $VERSION"
git push --quiet origin main
ok "main pushed"

# Pushed exactly once, deliberately. Pushing the tag twice starts two release
# runs that race to publish the same version; the loser fails on an
# already-existing file and leaves a red X on a release that actually worked.
git tag -a "v$VERSION" -m "blastcheck $VERSION"
git push --quiet origin "v$VERSION"
ok "tagged v$VERSION"

# --------------------------------------------------------------------- watch

say "waiting for the release workflow to appear"
run=""
for _ in $(seq 1 30); do
  run=$(curl -sSf "${API}/actions/runs?per_page=15" 2>/dev/null | python3 -c "
import json, sys
try:
    d = json.load(sys.stdin)
except Exception:
    sys.exit(0)
for r in d.get('workflow_runs', []):
    if r['name'] == 'release' and r['head_branch'] == 'v${VERSION}':
        print(r['id'])
        break
" || true)
  [ -n "$run" ] && break
  sleep 5
done
[ -n "$run" ] || die "no release run appeared for v$VERSION - check https://github.com/${REPO}/actions"

url="https://github.com/${REPO}/actions/runs/${run}"
echo "    $url"

# A retired runner label does not fail the job - it queues forever, which is
# indistinguishable from a slow allocation until you know to look for it. So
# report per-job state, and time out rather than watch a job that will never
# be scheduled.
previous=""
finished=""
for _ in $(seq 1 120); do
  snapshot=$(curl -sSf "${API}/actions/runs/${run}/jobs?per_page=20" 2>/dev/null | python3 -c "
import json, sys
try:
    d = json.load(sys.stdin)
except Exception:
    print('PENDING'); print('OK'); sys.exit(0)
jobs = d.get('jobs', [])
if not jobs:
    print('PENDING'); print('OK'); sys.exit(0)
print('DONE' if all(j['status'] == 'completed' for j in jobs) else 'RUNNING')
print('BAD' if [j for j in jobs if j['conclusion'] not in (None, 'success', 'skipped')] else 'OK')
for j in jobs:
    print('    %-46s %-11s %s' % (j['name'][:44], j['status'], j['conclusion'] or ''))
" || true)

  state=$(sed -n 1p <<<"$snapshot")
  health=$(sed -n 2p <<<"$snapshot")
  table=$(tail -n +3 <<<"$snapshot")

  if [ -n "$table" ] && [ "$table" != "$previous" ]; then
    printf '%s\n' "$table"
    previous="$table"
  fi

  if [ "$state" = "DONE" ]; then
    [ "$health" = "OK" ] || die "the release run failed - $url"
    finished=yes
    break
  fi
  sleep 10
done

[ -n "$finished" ] || die "still unfinished after 20 minutes.
       A job stuck in 'queued' almost always means a retired runner label.
       Check the matrix in .github/workflows/release.yml against GitHub's
       current runner images.
       $url"
ok "workflow green"

# ------------------------------------------------ verify what the world sees

say "confirming PyPI is serving $VERSION"
# Green does not mean published. Ask the index, not the workflow.
for _ in $(seq 1 20); do
  if curl -sSf "https://pypi.org/simple/blastcheck/" 2>/dev/null | grep -q "blastcheck-${VERSION}-"; then
    ok "PyPI has $VERSION"
    printf '\n\033[32mreleased\033[0m  blastcheck %s\n' "$VERSION"
    printf '  https://github.com/%s/releases/tag/v%s\n' "$REPO" "$VERSION"
    printf '  https://pypi.org/project/blastcheck/%s/\n' "$VERSION"
    printf '\n  brew formula still needs:  contrib/update-formula.sh %s\n\n' "$VERSION"
    exit 0
  fi
  sleep 15
done
die "the workflow was green but PyPI is not serving $VERSION yet.
       Check the publish job: $url"
