#!/bin/bash
# Puts a built release on the lab server (CT 9600): server binary plus the
# agent installer the console offers and the agents update to.
#   bash tools/release/deploy-lab.sh 0.2.8
set -euo pipefail
V=${1:?version}
cd "$(dirname "$0")/../.."
K="-o BatchMode=yes -i /c/Users/Mili/Ai/vm/keys/lab_ed25519"
H=root@192.168.101.179
scp $K "dist/rmmzit-server-$V-linux-amd64" $H:/usr/local/bin/rmmzit-server.new
scp $K "dist/rmmzit-agent-$V-x64.msi" $H:/var/lib/rmmzit/downloads/rmmzit-agent-x64.msi
scp $K "dist/rmmzit-agent-$V-x64.json" $H:/var/lib/rmmzit/downloads/rmmzit-agent-x64.json
for arch in amd64 arm64; do
  scp $K "dist/rmmzit-agent-$V-linux-$arch" $H:/var/lib/rmmzit/downloads/rmmzit-agent-linux-$arch
  scp $K "dist/rmmzit-agent-$V-linux-$arch.json" $H:/var/lib/rmmzit/downloads/rmmzit-agent-linux-$arch.json
done
ssh $K $H "chmod 755 /usr/local/bin/rmmzit-server.new && mv /usr/local/bin/rmmzit-server.new /usr/local/bin/rmmzit-server && systemctl restart rmmzit && sleep 3 && /usr/local/bin/rmmzit-server -version"
