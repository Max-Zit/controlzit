#!/bin/bash
# Publishes a built release (dist/release-V, see build.sh) on GitHub.
#
#   bash tools/release/publish.sh 0.12.1 notes.md
#   CANDIDATE=1 bash tools/release/publish.sh 0.12.1 notes.md
#
# CANDIDATE=1 publishes a release candidate: a pre-release that consoles on
# the official channel do not see, also copied to the release "testing"
# (the testing channel, update source
# https://github.com/Max-Zit/controlzit/releases/download/testing).
# After the candidate is approved, promote.sh makes it the official release.
set -euo pipefail
V=${1:?version}
NOTES=${2:?release notes file}
REPO=Max-Zit/controlzit
cd "$(dirname "$0")/../.."
R="dist/release-$V"
[ -f "$R/manifest.json.sig" ] || { echo "$R is not a signed release; run build.sh first" >&2; exit 1; }
FLAGS=()
TITLE="ControlZit $V"
if [ -n "${CANDIDATE:-}" ]; then
    FLAGS=(--prerelease --latest=false)
    TITLE="ControlZit $V (release candidate)"
fi
git tag "v$V"
git push -q origin "v$V"
gh release create "v$V" --repo "$REPO" --title "$TITLE" --notes-file "$NOTES" "${FLAGS[@]}" "$R"/*
if [ -n "${CANDIDATE:-}" ]; then
    # The testing channel holds exactly the candidate's signed files.
    if ! gh release view testing --repo "$REPO" >/dev/null 2>&1; then
        gh release create testing --repo "$REPO" --prerelease --latest=false --title "Testing channel" \
            --notes "Release candidates for test consoles. Update channel: Testing (Settings → ControlZit updates)."
    fi
    for a in $(gh release view testing --repo "$REPO" --json assets --jq '.assets[].name'); do
        gh release delete-asset testing "$a" --repo "$REPO" --yes
    done
    gh release upload testing --repo "$REPO" --clobber "$R"/*
    gh release edit testing --repo "$REPO" --notes "Current candidate: ControlZit $V (https://github.com/$REPO/releases/tag/v$V). For test consoles only: Settings → ControlZit updates → Update channel: Testing."
    echo "published candidate v$V (also on the testing channel)"
else
    echo "published v$V"
fi
