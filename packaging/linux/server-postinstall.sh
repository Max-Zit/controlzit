#!/bin/sh
set -e
if ! getent passwd controlzit >/dev/null; then
    useradd --system --home-dir /var/lib/controlzit --shell /usr/sbin/nologin controlzit 2>/dev/null \
      || useradd --system --home-dir /var/lib/controlzit --shell /sbin/nologin controlzit
fi
install -d -m 0700 -o controlzit -g controlzit /var/lib/controlzit
install -d -m 0750 -o controlzit -g controlzit /var/lib/controlzit/downloads /var/lib/controlzit/helper
install -d -m 0700 -o root -g root /var/cache/controlzit
# The agent installers of this version, offered in the console right away.
if [ -d /usr/share/controlzit/downloads ]; then
    cp -f /usr/share/controlzit/downloads/* /var/lib/controlzit/downloads/ 2>/dev/null || true
    chown -R controlzit:controlzit /var/lib/controlzit/downloads
fi
chown root:controlzit /etc/controlzit/server.env
chmod 640 /etc/controlzit/server.env
if command -v systemctl >/dev/null 2>&1; then
    systemctl daemon-reload || true
    systemctl enable controlzit-server.service >/dev/null 2>&1 || true
    systemctl enable --now controlzit-helper.path >/dev/null 2>&1 || true
    # An upgrade by hand (dpkg -i, rpm -U) runs the new version right away.
    systemctl try-restart controlzit-server.service >/dev/null 2>&1 || true
fi
if grep -q 'CHANGE_ME' /etc/controlzit/server.env; then
    echo "ControlZit server installed. Set CONTROLZIT_DB in /etc/controlzit/server.env,"
    echo "then: systemctl start controlzit-server (or use install.sh, which does all of it)."
fi
