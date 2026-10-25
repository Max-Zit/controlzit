#!/bin/bash
# Builds a release into dist/: agent MSI + exe + Linux agents, the server
# for Linux (deb, rpm, plain program) and Windows, the installer's version
# files for the console, third-party licenses and, with the release key,
# the signed manifest of dist/release-V (the files that go on GitHub).
#   bash tools/release/build.sh 0.3.0 [release-notes.md]
set -euo pipefail
V=${1:?version}
NOTES=${2:-}
KEY=${CONTROLZIT_RELEASE_KEY:-/c/Users/Mili/Ai/release-keys/controlzit-release.key}
cd "$(dirname "$0")/../.."
export GOTMPDIR=$PWD/.gotmp
mkdir -p dist
powershell -NoProfile -ExecutionPolicy Bypass -File packaging/windows/build-msi.ps1 -Version "$V" | tail -1
cp bin/msi/controlzit-agent.exe "dist/controlzit-agent-$V-windows-amd64.exe"
for arch in amd64 arm64; do
  GOOS=linux GOARCH=$arch CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -X main.version=$V" -o "dist/controlzit-agent-$V-linux-$arch" ./cmd/controlzit-agent
done
for os in linux windows; do
  ext=; [ $os = windows ] && ext=.exe
  GOOS=$os GOARCH=amd64 CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -X main.version=$V" -o "dist/controlzit-server-$V-$os-amd64$ext" ./cmd/controlzit-server
done
printf '{"version":"%s"}\n' "$V" > "dist/controlzit-agent-$V-x64.json"
for arch in amd64 arm64; do printf '{"version":"%s"}\n' "$V" > "dist/controlzit-agent-$V-linux-$arch.json"; done
# Licenses of everything linked into the programs (fails on an unknown license).
go run ./tools/licenses -out THIRD_PARTY_LICENSES.md "dist/controlzit-server-$V-linux-amd64" "dist/controlzit-server-$V-windows-amd64.exe" "dist/controlzit-agent-$V-windows-amd64.exe" "dist/controlzit-agent-$V-linux-amd64" "dist/controlzit-agent-$V-linux-arm64" bin/msi/controlzit-tray.exe
cp THIRD_PARTY_LICENSES.md "dist/THIRD_PARTY_LICENSES-$V.md"

# Linux packages of the server; they carry the agent installers of this
# version under the names the console offers them by.
rm -rf bin/pkg && mkdir -p bin/pkg/downloads
cp "dist/controlzit-server-$V-linux-amd64" bin/pkg/controlzit-server
cp "dist/controlzit-agent-$V-x64.msi" bin/pkg/downloads/controlzit-agent-x64.msi
cp "dist/controlzit-agent-$V-x64.json" bin/pkg/downloads/controlzit-agent-x64.json
for arch in amd64 arm64; do
  cp "dist/controlzit-agent-$V-linux-$arch" "bin/pkg/downloads/controlzit-agent-linux-$arch"
  cp "dist/controlzit-agent-$V-linux-$arch.json" "bin/pkg/downloads/controlzit-agent-linux-$arch.json"
done
export VERSION=$V ARCH=amd64
NFPM="go run github.com/goreleaser/nfpm/v2/cmd/nfpm@v2.43.0"
rm -f "dist/controlzit-server_${V}_amd64.deb" "dist/controlzit-server-${V}-1.x86_64.rpm"
$NFPM package --config packaging/linux/nfpm-server.yaml --packager deb --target dist/ >/dev/null
$NFPM package --config packaging/linux/nfpm-server.yaml --packager rpm --target dist/ >/dev/null

# What goes on GitHub, with the signed manifest.
R="dist/release-$V"
rm -rf "$R" && mkdir -p "$R"
cp "dist/controlzit-agent-$V-x64.msi" "dist/controlzit-agent-$V-x64.json" "dist/controlzit-agent-$V-windows-amd64.exe" \
   "dist/controlzit-agent-$V-linux-amd64" "dist/controlzit-agent-$V-linux-amd64.json" "dist/controlzit-agent-$V-linux-arm64" "dist/controlzit-agent-$V-linux-arm64.json" \
   "dist/controlzit-server-$V-linux-amd64" "dist/controlzit-server-$V-windows-amd64.exe" \
   "dist/controlzit-server_${V}_amd64.deb" "dist/controlzit-server-${V}-1.x86_64.rpm" \
   "dist/THIRD_PARTY_LICENSES-$V.md" packaging/install.sh "$R/"
(cd "$R" && sha256sum $(ls | grep -v '^SHA256SUMS') > SHA256SUMS)
if [ -f "$KEY" ]; then
  go run ./tools/relsign sign -key "$KEY" -version "$V" -dir "$R" ${NOTES:+-notes "$NOTES"}
else
  echo "note: no release key at $KEY; the release is not signed"
fi
echo "built $V"
