#!/bin/bash
# Makes an approved release candidate the official release: the same signed
# files become the newest release, which consoles on the official channel
# install. Then main gets the tested commit.
#
#   bash tools/release/promote.sh 0.12.1
set -euo pipefail
V=${1:?version}
REPO=Max-Zit/rmmzit
cd "$(dirname "$0")/../.."
gh release view "v$V" --repo "$REPO" --json isPrerelease --jq .isPrerelease | grep -q true ||
    { echo "v$V is not a release candidate" >&2; exit 1; }
gh release edit "v$V" --repo "$REPO" --prerelease=false --latest --title "RMMZit $V"
git fetch -q origin
git switch -q main
git merge -q --ff-only "v$V"
git push -q origin main
git switch -q develop
echo "v$V is the official release; main is at v$V"
