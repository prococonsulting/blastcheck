#!/usr/bin/env bash
#
# Create the Homebrew tap, once.
#
#     scripts/setup-tap.sh
#
# `brew install prococonsulting/tap/blastcheck` is printed in the README and on
# blastcheck.dev. It does not work: prococonsulting/homebrew-tap does not
# exist. This creates it and seeds it with the current formula, after which
# scripts/release.sh keeps it current on every release with no further thought.
#
# Homebrew resolves `prococonsulting/tap` to the repo `homebrew-tap` -- the
# prefix is stripped by convention, so the repo name is not a typo.
#
# Run this once. It is safe to re-run: it will not clobber an existing tap.

set -euo pipefail

OWNER="prococonsulting"
TAP="homebrew-tap"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"

die() { printf '\n\033[31merror\033[0m  %s\n\n' "$*" >&2; exit 1; }
say() { printf '\033[36m==>\033[0m %s\n' "$*"; }
ok()  { printf '\033[32m ok \033[0m %s\n' "$*"; }

if curl -sS -o /dev/null -w '%{http_code}' "https://github.com/${OWNER}/${TAP}" | grep -q 200; then
  ok "https://github.com/${OWNER}/${TAP} already exists -- nothing to create"
  echo "    scripts/release.sh keeps the formula current from here on."
  exit 0
fi

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
tap="$work/$TAP"

say "building the tap contents"
mkdir -p "$tap/Formula"
cp "$ROOT/contrib/blastcheck.rb" "$tap/Formula/blastcheck.rb"

cat > "$tap/README.md" <<'ENDREADME'
# prococonsulting/homebrew-tap

Homebrew formulae published by [ProCo Consulting](https://prococonsulting.com).

```
brew install prococonsulting/tap/blastcheck
```

## blastcheck

[blastcheck](https://blastcheck.dev) reads a `terraform show -json` plan and
emits an [Impact Manifest](https://github.com/prococonsulting/impact-manifest):
a machine-readable change-safety assertion. It has no runtime dependencies, so
the formula is a plain virtualenv install with nothing vendored.

`Formula/blastcheck.rb` is generated, not hand-edited. It is updated on every
release from the sdist that PyPI is actually serving, so the formula can only
ever describe a published, byte-identical artifact. The source of truth is
`contrib/blastcheck.rb` in
[prococonsulting/blastcheck](https://github.com/prococonsulting/blastcheck).
ENDREADME

# Point the formula at whatever is currently published, so the tap is usable
# the moment it exists rather than after the next release.
latest=$(curl -sSf "https://pypi.org/pypi/blastcheck/json" \
  | python3 -c "import json,sys; print(json.load(sys.stdin)['info']['version'])")
say "pointing the formula at the published $latest"
"$ROOT/contrib/update-formula.sh" "$latest"
cp "$ROOT/contrib/blastcheck.rb" "$tap/Formula/blastcheck.rb"
grep -qE '^  url "https://' "$tap/Formula/blastcheck.rb" || die "the formula still has a placeholder url"
ok "formula points at $latest"

say "creating github.com/${OWNER}/${TAP}"
cd "$tap"
git init -q -b main
git add -A
git commit -qm "The ProCo Homebrew tap

Seeded with blastcheck ${latest}, pointing at the sdist PyPI is serving rather
than one built locally -- a formula should only ever describe an artifact that
is actually published.

Formula/blastcheck.rb is generated. Edit contrib/blastcheck.rb in the
blastcheck repo instead; scripts/release.sh republishes it here on release."

if command -v gh >/dev/null 2>&1 && gh auth status >/dev/null 2>&1; then
  gh repo create "${OWNER}/${TAP}" --public --source=. --remote=origin --push \
    --description "Homebrew formulae from ProCo Consulting" \
    || die "gh repo create failed"
  ok "tap created and pushed"
else
  cat <<ENDMANUAL

  \033[33mgh is not installed or not authenticated\033[0m, so the repo has to be
  created by hand -- one click, then this finishes itself:

    1. https://github.com/new
       Owner: ${OWNER}    Name: ${TAP}    Public    (no README, no .gitignore)

    2. then run:

       cd $tap
       git remote add origin https://github.com/${OWNER}/${TAP}.git
       git push -u origin main

  The prepared repo is at: $tap
  (it is in a temp dir -- copy it somewhere first if you want to keep it)

ENDMANUAL
  # Do not delete the work we just prepared.
  trap - EXIT
  exit 3
fi

echo
ok "brew install ${OWNER}/tap/blastcheck should now work"
echo "    verify with:  brew install ${OWNER}/tap/blastcheck && blastcheck rules"
