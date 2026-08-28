#!/usr/bin/env bash
# Point the Homebrew formula at a published PyPI release.
#
#   contrib/update-formula.sh 0.7.0
#
# Reads the sdist URL and hash from PyPI itself rather than computing them
# locally, so the formula can only ever describe an artifact that is actually
# published and byte-identical to what users will download.
set -euo pipefail
version="${1:?usage: update-formula.sh <version>}"

read -r url sha < <(python3 - "$version" <<'PY'
import json, sys, urllib.request
v = sys.argv[1]
d = json.load(urllib.request.urlopen("https://pypi.org/pypi/blastcheck/json"))
files = d["releases"].get(v)
if not files:
    sys.exit(f"blastcheck {v} is not on PyPI yet")
sdist = next((f for f in files if f["packagetype"] == "sdist"), None)
if not sdist:
    sys.exit(f"blastcheck {v} has no sdist on PyPI")
print(sdist["url"], sdist["digests"]["sha256"])
PY
)

formula="$(dirname "$0")/blastcheck.rb"
python3 - "$formula" "$url" "$sha" <<'PY'
import pathlib, re, sys
p = pathlib.Path(sys.argv[1]); s = p.read_text()
s = re.sub(r'^  url ".*"$',    f'  url "{sys.argv[2]}"',    s, flags=re.M)
s = re.sub(r'^  sha256 ".*"$', f'  sha256 "{sys.argv[3]}"', s, flags=re.M)
p.write_text(s)
PY
echo "formula updated:"
grep -E '^  (url|sha256) ' "$formula"
