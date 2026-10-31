#!/bin/sh
# Stop the services when the package is removed (not on an upgrade).
case "$1" in
    remove|purge|0)
        if command -v systemctl >/dev/null 2>&1; then
            systemctl disable --now rmmzit-helper.path >/dev/null 2>&1 || true
            systemctl disable --now rmmzit-server.service >/dev/null 2>&1 || true
        fi
        rm -f /usr/bin/controlzit-server /etc/systemd/system/controlzit-server.service
        ;;
esac
