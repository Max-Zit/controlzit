#!/bin/sh
set -e
# Installations from before the rename to RMMZit: the package
# controlzit-server is removed by dpkg or dnf before this script runs (this
# package replaces it). Move its data and settings over, and keep the old
# names working for the update that is running: the previous version's
# helper restarts and checks the server under them.
MIGRATED=
if [ -d /var/lib/controlzit ] && [ ! -L /var/lib/controlzit ] && [ ! -e /var/lib/rmmzit ]; then
    # dpkg only deconfigures the replaced package: its server still runs.
    # (Not its helper: that one may be running this installation.)
    if command -v systemctl >/dev/null 2>&1; then
        systemctl stop controlzit-server.service controlzit-helper.path >/dev/null 2>&1 || true
    fi
    mv /var/lib/controlzit /var/lib/rmmzit
    ln -s rmmzit /var/lib/controlzit
    MIGRATED=1
fi
if getent passwd controlzit >/dev/null && ! getent passwd rmmzit >/dev/null; then
    # The same user under the new name (its files keep their owner).
    if usermod -l rmmzit -d /var/lib/rmmzit controlzit 2>/dev/null; then
        if getent group controlzit >/dev/null && ! getent group rmmzit >/dev/null; then
            groupmod -n rmmzit controlzit || true
        fi
    fi
fi
if [ -f /etc/controlzit/server.env ] && grep -q 'CHANGE_ME' /etc/rmmzit/server.env; then
    # The settings as they are: RMMZit also reads the CONTROLZIT_ names.
    cp -p /etc/controlzit/server.env /etc/rmmzit/server.env
fi
if [ -f /etc/systemd/network/50-controlzit.network ] && [ ! -e /etc/systemd/network/50-rmmzit.network ]; then
    mv /etc/systemd/network/50-controlzit.network /etc/systemd/network/50-rmmzit.network
fi
if [ -n "$MIGRATED" ]; then
    [ -e /usr/bin/controlzit-server ] || ln -s rmmzit-server /usr/bin/controlzit-server
    [ -e /etc/systemd/system/controlzit-server.service ] || ln -s /usr/lib/systemd/system/rmmzit-server.service /etc/systemd/system/controlzit-server.service
fi
if ! getent passwd rmmzit >/dev/null; then
    group=
    if getent group rmmzit >/dev/null; then group="-g rmmzit"; fi
    # shellcheck disable=SC2086
    useradd --system $group --home-dir /var/lib/rmmzit --shell /usr/sbin/nologin rmmzit 2>/dev/null \
      || useradd --system $group --home-dir /var/lib/rmmzit --shell /sbin/nologin rmmzit
fi
install -d -m 0700 -o rmmzit -g rmmzit /var/lib/rmmzit
if [ -n "$MIGRATED" ]; then chown -R rmmzit:rmmzit /var/lib/rmmzit; fi
install -d -m 0750 -o rmmzit -g rmmzit /var/lib/rmmzit/downloads /var/lib/rmmzit/helper
install -d -m 0700 -o root -g root /var/cache/rmmzit
# The agent installers of this version, offered in the console right away.
if [ -d /usr/share/rmmzit/downloads ]; then
    cp -f /usr/share/rmmzit/downloads/* /var/lib/rmmzit/downloads/ 2>/dev/null || true
    chown -R rmmzit:rmmzit /var/lib/rmmzit/downloads
fi
chown root:rmmzit /etc/rmmzit/server.env
chmod 640 /etc/rmmzit/server.env
if command -v systemctl >/dev/null 2>&1; then
    systemctl daemon-reload || true
    systemctl enable rmmzit-server.service >/dev/null 2>&1 || true
    systemctl enable --now rmmzit-helper.path >/dev/null 2>&1 || true
    # An upgrade by hand (dpkg -i, rpm -U) runs the new version right away.
    systemctl try-restart rmmzit-server.service >/dev/null 2>&1 || true
    # From ControlZit: the old server was stopped above; start the new one.
    if [ -n "$MIGRATED" ]; then systemctl start rmmzit-server.service >/dev/null 2>&1 || true; fi
fi
if grep -q 'CHANGE_ME' /etc/rmmzit/server.env; then
    echo "RMMZit server installed. Set RMMZIT_DB in /etc/rmmzit/server.env,"
    echo "then: systemctl start rmmzit-server (or use install.sh, which does all of it)."
fi
# The RMMZit appliance (not other servers): the setup menu on its
# screen, the start-up script and hardened SSH.
if [ -f /var/lib/rmmzit/.appliance ]; then
    a=/usr/share/rmmzit/appliance
    install -m 0755 $a/rmmzit-setup /usr/local/sbin/rmmzit-setup
    install -m 0755 $a/rmmzit-appliance-boot /usr/local/sbin/rmmzit-appliance-boot
    install -m 0644 $a/rmmzit-appliance-boot.service /etc/systemd/system/rmmzit-appliance-boot.service
    install -m 0644 $a/rmmzit-menu.sh /etc/profile.d/rmmzit-menu.sh
    install -m 0440 $a/sudoers-rmmzit-setup /etc/sudoers.d/rmmzit-setup
    systemctl daemon-reload 2>/dev/null || true
    systemctl enable rmmzit-appliance-boot.service >/dev/null 2>&1 || true
    if [ -d /etc/ssh/sshd_config.d ]; then
        install -m 0644 $a/sshd-rmmzit.conf /etc/ssh/sshd_config.d/50-rmmzit.conf
        # Inside the installer (no host keys yet) sshd -t fails anyway: take
        # the file out only when it is what makes the check fail.
        if sshd -t 2>/dev/null; then
            systemctl reload ssh 2>/dev/null || true
        else
            mv /etc/ssh/sshd_config.d/50-rmmzit.conf /etc/ssh/50-rmmzit.conf.off
            if sshd -t 2>/dev/null; then
                rm -f /etc/ssh/50-rmmzit.conf.off
            else
                mv /etc/ssh/50-rmmzit.conf.off /etc/ssh/sshd_config.d/50-rmmzit.conf
            fi
        fi
    fi
    [ -f /var/lib/rmmzit/.appliance-ready ] && /usr/local/sbin/rmmzit-appliance-boot issue >/dev/null 2>&1 || true
fi
# The old system user, once nothing runs under it any more.
if [ -n "$MIGRATED" ] && getent passwd controlzit >/dev/null; then
    userdel controlzit >/dev/null 2>&1 || true
fi
# Appliances from before the rename to RMMZit: their own copies of the
# setup menu, start-up script and settings under the old name.
if [ -f /var/lib/rmmzit/.appliance ] && [ -e /usr/local/sbin/controlzit-setup ]; then
    systemctl disable controlzit-appliance-boot.service >/dev/null 2>&1 || true
    rm -f /usr/local/sbin/controlzit-setup /usr/local/sbin/controlzit-appliance-boot /usr/local/sbin/controlzit-firstboot \
        /etc/systemd/system/controlzit-appliance-boot.service /etc/systemd/system/controlzit-firstboot.service \
        /etc/profile.d/controlzit-menu.sh /etc/sudoers.d/controlzit-setup /etc/ssh/sshd_config.d/50-controlzit.conf
    if [ -f /etc/systemd/resolved.conf.d/50-controlzit.conf ]; then
        mv /etc/systemd/resolved.conf.d/50-controlzit.conf /etc/systemd/resolved.conf.d/50-rmmzit.conf
    fi
    systemctl daemon-reload 2>/dev/null || true
    systemctl reload ssh 2>/dev/null || true
fi
