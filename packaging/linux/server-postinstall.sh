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
# The ControlZit appliance (not other servers): the setup menu on its
# screen, the start-up script and hardened SSH.
if [ -f /var/lib/controlzit/.appliance ]; then
    a=/usr/share/controlzit/appliance
    install -m 0755 $a/controlzit-setup /usr/local/sbin/controlzit-setup
    install -m 0755 $a/controlzit-appliance-boot /usr/local/sbin/controlzit-appliance-boot
    install -m 0644 $a/controlzit-appliance-boot.service /etc/systemd/system/controlzit-appliance-boot.service
    install -m 0644 $a/controlzit-menu.sh /etc/profile.d/controlzit-menu.sh
    install -m 0440 $a/sudoers-controlzit-setup /etc/sudoers.d/controlzit-setup
    systemctl daemon-reload 2>/dev/null || true
    systemctl enable controlzit-appliance-boot.service >/dev/null 2>&1 || true
    if [ -d /etc/ssh/sshd_config.d ]; then
        install -m 0644 $a/sshd-controlzit.conf /etc/ssh/sshd_config.d/50-controlzit.conf
        sshd -t 2>/dev/null && { systemctl reload ssh 2>/dev/null || true; } || rm -f /etc/ssh/sshd_config.d/50-controlzit.conf
    fi
    [ -f /var/lib/controlzit/.appliance-ready ] && /usr/local/sbin/controlzit-appliance-boot issue >/dev/null 2>&1 || true
fi
