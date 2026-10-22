#!/bin/bash
# Builds a release into dist/: agent MSI + exe, servers for Linux and
# Windows, the installer's version file for the console, SHA256SUMS.
#   bash tools/release/build.sh 0.2.8
set -euo pipefail
V=${1:?version}
cd "$(dirname "$0")/../.."
export GOTMPDIR=$PWD/.gotmp
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
(cd dist && sha256sum "controlzit-agent-$V-x64.msi" "controlzit-agent-$V-windows-amd64.exe" "controlzit-agent-$V-linux-amd64" "controlzit-agent-$V-linux-arm64" "controlzit-server-$V-linux-amd64" "controlzit-server-$V-windows-amd64.exe" > "SHA256SUMS-$V.txt")
echo "built $V"
