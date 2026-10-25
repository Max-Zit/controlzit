#!/bin/sh
# Runs inside the newly installed system (preseed late_command).
set -e
cd /root/controlzit-install
# The appliance marker first: the package then installs the setup menu and
# the start-up script of the appliance.
mkdir -p /var/lib/controlzit
touch /var/lib/controlzit/.appliance
dpkg -i controlzit-server_*.deb
install -m 0755 controlzit-firstboot /usr/local/sbin/controlzit-firstboot
install -m 0644 controlzit-firstboot.service /etc/systemd/system/controlzit-firstboot.service
systemctl enable controlzit-firstboot.service
# Automatic security updates of Debian.
printf 'APT::Periodic::Update-Package-Lists "1";\nAPT::Periodic::Unattended-Upgrade "1";\n' > /etc/apt/apt.conf.d/20auto-upgrades
# Where to get the source code of the GPL software, and the exact Debian
# packages of this installation.
mkdir -p /usr/share/doc/controlzit
install -m 0644 SOURCE-CODE.txt /usr/share/doc/controlzit/SOURCE-CODE.txt
dpkg-query -W -f '${Package} ${Version}\n' > /usr/share/doc/controlzit/debian-packages.txt
# The administrator chooses its own password at the first sign-in.
chage -d 0 czadmin
usermod -aG sudo czadmin
# systemd-networkd with DHCP on whatever adapter the machine has, and DNS
# from the lease (systemd-resolved): the same on a server and in every copy
# of a VM image. Settings → Network changes it later.
mkdir -p /etc/systemd/network
printf '# Written by ControlZit (Settings -> Network).\n[Match]\nName=en* eth*\n\n[Network]\nDHCP=ipv4\n' > /etc/systemd/network/50-controlzit.network
printf 'auto lo\niface lo inet loopback\n' > /etc/network/interfaces
systemctl enable systemd-networkd systemd-networkd-wait-online systemd-resolved
ln -sf /run/systemd/resolve/stub-resolv.conf /etc/resolv.conf
if [ -f IMAGE ]; then
    # A VM image is copied many times: no host identity baked in (SSH keys
    # and the machine ID are created at the first start).
    rm -f /etc/ssh/ssh_host_*
    truncate -s 0 /etc/machine-id
    rm -f /var/lib/dbus/machine-id
    apt-get clean
fi
