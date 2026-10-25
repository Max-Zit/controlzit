#!/bin/sh
# Stop the services when the package is removed (not on an upgrade).
case "$1" in
    remove|purge|0)
        if command -v systemctl >/dev/null 2>&1; then
            systemctl disable --now controlzit-helper.path >/dev/null 2>&1 || true
            systemctl disable --now controlzit-server.service >/dev/null 2>&1 || true
        fi
        ;;
esac
