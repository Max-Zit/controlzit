#!/bin/bash
# Puts a built release on the lab server (CT 9600): server binary plus the
# agent installer the console offers and the agents update to.
#   bash tools/release/deploy-lab.sh 0.2.8
set -euo pipefail
V=${1:?version}
cd "$(dirname "$0")/../.."
K="-o BatchMode=yes -i /c/Users/Mili/Ai/vm/keys/lab_ed25519"
H=root@192.168.101.179
scp $K "dist/controlzit-server-$V-linux-amd64" $H:/usr/local/bin/controlzit-server.new
scp $K "dist/controlzit-agent-$V-x64.msi" $H:/var/lib/controlzit/downloads/controlzit-agent-x64.msi
scp $K "dist/controlzit-agent-$V-x64.json" $H:/var/lib/controlzit/downloads/controlzit-agent-x64.json
scp $K "dist/controlzit-agent-$V-linux-amd64" $H:/var/lib/controlzit/downloads/controlzit-agent-linux-amd64
ssh $K $H "chmod 755 /usr/local/bin/controlzit-server.new && mv /usr/local/bin/controlzit-server.new /usr/local/bin/controlzit-server && systemctl restart controlzit && sleep 3 && /usr/local/bin/controlzit-server -version"
