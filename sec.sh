#!/bin/bash
 
#-----------------------------------------------------------------------------------------------------------#
#---------------------------------DEBIAN-HARDENING-SCRIPT-(AMD-RYZEN-AI-370HX)------------------------------#
#-----------------------------------------------------------------------------------------------------------#
 
set -euo pipefail
 
WARN_COUNT=0
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color
 
log_info() {
    echo -e "${GREEN}[+]${NC} $1"
}
 
log_warn() {
    echo -e "${YELLOW}[!]${NC} $1"
}
 
log_error() {
    echo -e "${RED}[x]${NC} $1"
}
 
# PRE-CONFIG
log_info "Setting up prerequisites..."
apt purge -y anacron apt-listchanges bind9* blue* cron* debian-faq dhcpcd-base dictionaries-common doc-debian fdisk inetutils-telnet man-db manpages netcat-traditional openssh-client os-prober pci* powertop reportbug systemd-userdbd task-english traceroute usbutils util-linux-locales vim* wamerican whiptail wireless-* wpasupplicant wtmpdb
apt install -y extrepo iptables iptables-persistent netfilter-persistent wget pamu2fcfg libpam-u2f --no-install-recommends --no-install-suggests 2>/dev/null || true
extrepo enable librewolf
apt update 2>/dev/null || true
 
# PAM
log_info "Configuring U2F authentication..."
pamu2fcfg -u user -o pam://local -i pam://local > /etc/security/u2f_keys
chown root:root /etc/security/u2f_keys 2>/dev/null || true
chmod 0400 /etc/security/u2f_keys 2>/dev/null || true
chattr +i /etc/security/u2f_keys 2>/dev/null || true
 
log_info "Configuring faillock..."
mkdir -p /var/log/faillock 2>/dev/null || true
chmod 0700 /var/log/faillock 2>/dev/null || true
rm -f /etc/pam.d/remote 2>/dev/null || true
rm -f /etc/pam.d/cron 2>/dev/null || true
 
cat > /etc/security/faillock.conf << 'EOF'
deny=3
unlock_time=900
fail_interval=900
silent
EOF
 
cat > /etc/pam.d/common-auth << 'EOF'
#%PAM-1.0
auth     required     pam_faildelay.so delay=2000000
auth     required     pam_faillock.so preauth
auth     sufficient   pam_u2f.so authfile=/etc/security/u2f_keys origin=pam://local appid=pam://local
auth    [default=die] pam_faillock.so authfail
auth     requisite    pam_deny.so
EOF
 
cat > /etc/pam.d/common-account << 'EOF'
#%PAM-1.0
account   required    pam_access.so accessfile=/etc/security/access.conf
account   required    pam_unix.so
EOF
 
cat > /etc/pam.d/common-password << 'EOF'
#%PAM-1.0
password  requisite   pam_deny.so
EOF
 
cat > /etc/pam.d/common-session << 'EOF'
#%PAM-1.0
session   required    pam_limits.so
session   optional    pam_umask.so umask=077
session   required    pam_env.so readenv=1 user_readenv=0
session   optional    pam_tmpdir.so
session   optional    pam_systemd.so
EOF
 
cat > /etc/pam.d/common-session-noninteractive << 'EOF'
#%PAM-1.0
session   required    pam_limits.so
session   optional    pam_umask.so umask=077
session   required    pam_env.so readenv=1 user_readenv=0
session   optional    pam_tmpdir.so
session   optional    pam_systemd.so
EOF
 
cat > /etc/pam.d/sudo << 'EOF'
#%PAM-1.0
auth     required     pam_faildelay.so delay=2000000
auth     required     pam_faillock.so preauth
auth     sufficient   pam_u2f.so authfile=/etc/security/u2f_keys origin=pam://local appid=pam://local
auth    [default=die] pam_faillock.so authfail
auth     requisite    pam_deny.so
account   include     common-account
session   required    pam_limits.so
session   include     common-session
EOF
 
cat > /etc/pam.d/sudo-i << 'EOF'
#%PAM-1.0
auth     required     pam_faildelay.so delay=2000000
auth     required     pam_faillock.so preauth
auth     sufficient   pam_u2f.so authfile=/etc/security/u2f_keys origin=pam://local appid=pam://local
auth    [default=die] pam_faillock.so authfail
auth     requisite    pam_deny.so
account   include     common-account
session   required    pam_limits.so
session   include     common-session
EOF
 
cat > /etc/pam.d/su << 'EOF'
#%PAM-1.0
auth     required     pam_faildelay.so delay=2000000
auth     required     pam_faillock.so preauth
auth     sufficient   pam_u2f.so authfile=/etc/security/u2f_keys origin=pam://local appid=pam://local
auth    [default=die] pam_faillock.so authfail
auth     requisite    pam_deny.so
account   include     common-account
session   required    pam_limits.so
session   include     common-session
EOF
 
cat > /etc/pam.d/su-l << 'EOF'
#%PAM-1.0
auth     required     pam_faildelay.so delay=2000000
auth     required     pam_faillock.so preauth
auth     sufficient   pam_u2f.so authfile=/etc/security/u2f_keys origin=pam://local appid=pam://local
auth    [default=die] pam_faillock.so authfail
auth     requisite    pam_deny.so
account   include     common-account
session   required    pam_limits.so
session   include     common-session
EOF
 
cat > /etc/pam.d/login << 'EOF'
#%PAM-1.0
auth      required    pam_securetty.so
auth      required    pam_nologin.so
auth     required     pam_faildelay.so delay=2000000
auth     required     pam_faillock.so preauth
auth     sufficient   pam_u2f.so authfile=/etc/security/u2f_keys origin=pam://local appid=pam://local
auth    [default=die] pam_faillock.so authfail
auth     requisite    pam_deny.so
account   required    pam_access.so accessfile=/etc/security/access.conf
session   required    pam_limits.so
session   include     common-session
EOF
 
cat > /etc/pam.d/chfn << 'EOF'
#%PAM-1.0
auth     required     pam_faildelay.so delay=2000000
auth     required     pam_faillock.so preauth
auth     sufficient   pam_u2f.so authfile=/etc/security/u2f_keys origin=pam://local appid=pam://local
auth    [default=die] pam_faillock.so authfail
auth     requisite    pam_deny.so
account   include     common-account
session   include     common-session
EOF
 
cat > /etc/pam.d/chsh << 'EOF'
#%PAM-1.0
auth     required     pam_faildelay.so delay=2000000
auth     required     pam_faillock.so preauth
auth     sufficient   pam_u2f.so authfile=/etc/security/u2f_keys origin=pam://local appid=pam://local
auth    [default=die] pam_faillock.so authfail
auth     requisite    pam_deny.so
account   include     common-account
session   include     common-session
EOF
 
cat > /etc/pam.d/chpasswd << 'EOF'
#%PAM-1.0
password  requisite   pam_deny.so
EOF
 
cat > /etc/pam.d/newusers << 'EOF'
#%PAM-1.0
password  requisite   pam_deny.so
EOF
 
cat > /etc/pam.d/passwd << 'EOF'
#%PAM-1.0
password  requisite   pam_deny.so
EOF
 
cat > /etc/pam.d/runuser << 'EOF'
#%PAM-1.0
auth      sufficient  pam_rootok.so
auth      requisite   pam_deny.so
account   include     common-account
session   required    pam_limits.so
session   include     common-session
EOF
 
cat > /etc/pam.d/runuser-l << 'EOF'
#%PAM-1.0
auth      include     runuser
session   include     runuser
EOF
 
cat > /etc/pam.d/sshd << 'EOF'
#%PAM-1.0
auth      required    pam_deny.so
account   required    pam_deny.so
password  required    pam_deny.so
session   required    pam_deny.so
EOF
 
cat > /etc/pam.d/other << 'EOF'
#%PAM-1.0
auth      required    pam_deny.so
account   required    pam_deny.so
password  required    pam_deny.so
session   required    pam_deny.so
EOF
 
cat > /usr/lib/pam.d/systemd-user << 'EOF'
#%PAM-1.0
session   required    pam_limits.so
account   include     common-account
session   required    pam_env.so readenv=1 user_readenv=0
session   optional    pam_systemd.so
session   include     common-session
EOF
 
cat > /usr/lib/pam.d/polkit << 'EOF'
#%PAM-1.0
auth      required    pam_deny.so
account   required    pam_deny.so
password  required    pam_deny.so
session   required    pam_deny.so
EOF
 
chown -R root:root /etc/pam.d/* 2>/dev/null || true
chmod -R 0644 /etc/pam.d/* 2>/dev/null || true
sed -i 's|^user:[^:]*:|user:!*:|' /etc/shadow
sed -i 's|^root:[^:]*:|root:!*:|' /etc/shadow
sed -i 's|^user:[^:]*:|user:!*:|' /etc/shadow-
sed -i 's|^root:[^:]*:|root:!*:|' /etc/shadow-
 
# MULLVAD VPN
log_info "Installing Mullvad VPN..."
MULLVAD_DEB="/tmp/mullvad-vpn.deb"
MULLVAD_URL="https://repository.mullvad.net/deb/stable/pool/main/m/mullvad-vpn/mullvad-vpn_2026.1_amd64.deb"
log_info "Downloading Mullvad VPN..."
apt install -y wget 2>/dev/null || true
if wget -q -O "$MULLVAD_DEB" "$MULLVAD_URL"; then
    log_info "Download complete - installing..."
    if dpkg -i "$MULLVAD_DEB"; then
        log_info "Mullvad installed successfully"
        rm -f "$MULLVAD_DEB"
        systemctl enable mullvad-daemon.service
        log_info "mullvad-daemon.service enabled for boot"
    else
        log_error "Mullvad dpkg install failed"
        (( WARN_COUNT++ )) || true
    fi
else
    log_error "Mullvad download failed - check connectivity and URL"
    (( WARN_COUNT++ )) || true
fi
 
# MULLVAD CONFIGURATION
log_info "Setting up Mullvad VPN..."
read -rsp "[*] Enter Mullvad account number: " MULLVAD_ACCOUNT
echo
mullvad account login "$MULLVAD_ACCOUNT"
unset MULLVAD_ACCOUNT
mullvad dns set default --block-ads --block-malware --block-trackers
mullvad relay set location us-chi-wg-316
mullvad relay set ip-version ipv4
mullvad anti-censorship set wireguard-port --port 51820
mullvad anti-censorship set mode wireguard-port
mullvad tunnel set daita on
mullvad tunnel set ipv6 off
mullvad tunnel set rotation-interval 24
mullvad auto-connect set on
mullvad connect
 
# IPTABLES
log_info "Setting up firewall..."
iptables -t filter -F
iptables -t filter -X
iptables -t filter -Z
iptables -t mangle -F
iptables -t mangle -X
iptables -t mangle -Z
iptables -t raw -F
iptables -t raw -X
iptables -t raw -Z
iptables -t nat -F
iptables -t nat -X
iptables -t nat -Z
iptables -P INPUT ACCEPT
iptables -P FORWARD ACCEPT
iptables -P OUTPUT ACCEPT
iptables -t filter -P INPUT ACCEPT
iptables -t filter -P OUTPUT ACCEPT
iptables -t filter -P FORWARD ACCEPT
iptables -t nat -P PREROUTING ACCEPT
iptables -t nat -P INPUT ACCEPT
iptables -t nat -P OUTPUT ACCEPT
iptables -t nat -P POSTROUTING ACCEPT
iptables -t mangle -P PREROUTING ACCEPT
iptables -t mangle -P INPUT ACCEPT
iptables -t mangle -P FORWARD ACCEPT
iptables -t mangle -P OUTPUT ACCEPT
iptables -t mangle -P POSTROUTING ACCEPT
iptables -t raw -P PREROUTING ACCEPT
iptables -t raw -P OUTPUT ACCEPT
 
cat > /etc/iptables/rules.v4 << 'EOF'
*raw
:PREROUTING ACCEPT [0:0]
:OUTPUT ACCEPT [0:0]
-A PREROUTING -p tcp --tcp-flags FIN,SYN,RST,PSH,ACK,URG NONE -j DROP
-A PREROUTING -p tcp --tcp-flags FIN,SYN FIN,SYN -j DROP
-A PREROUTING -p tcp --tcp-flags SYN,RST SYN,RST -j DROP
-A PREROUTING -p tcp --tcp-flags FIN,RST FIN,RST -j DROP
-A PREROUTING -p tcp --tcp-flags FIN,ACK FIN -j DROP
-A PREROUTING -p tcp --tcp-flags ACK,URG URG -j DROP
-A PREROUTING -p tcp --tcp-flags ACK,FIN FIN -j DROP
-A PREROUTING -p tcp --tcp-flags ACK,PSH PSH -j DROP
-A PREROUTING -p tcp --tcp-flags ALL ALL -j DROP
-A PREROUTING -p tcp --tcp-flags ALL NONE -j DROP
-A PREROUTING -p tcp --tcp-flags ALL FIN,PSH,URG -j DROP
-A PREROUTING -p tcp --tcp-flags ALL SYN,FIN,PSH,URG -j DROP
-A PREROUTING -p tcp --tcp-flags ALL SYN,RST,ACK,FIN,URG -j DROP
-A PREROUTING -p tcp --tcp-flags SYN,ACK,FIN,RST RST -m limit --limit 1/s --limit-burst 2  -j DROP
-A PREROUTING -s 10.0.0.0/8 ! -i wg0-mullvad -j DROP
-A PREROUTING -s 172.16.0.0/12 -j DROP
-A PREROUTING -s 192.168.0.0/16 -j DROP
-A PREROUTING -s 224.0.0.0/3 -j DROP
-A PREROUTING -s 169.254.0.0/16 -j DROP
-A PREROUTING -s 0.0.0.0/8 -j DROP
-A PREROUTING -s 240.0.0.0/5 -j DROP
-A PREROUTING -s 127.0.0.0/8 ! -i lo -j DROP
COMMIT

*mangle
:PREROUTING ACCEPT [0:0]
:INPUT ACCEPT [0:0]
:FORWARD ACCEPT [0:0]
:OUTPUT ACCEPT [0:0]
:POSTROUTING ACCEPT [0:0]
-A PREROUTING -m conntrack --ctstate INVALID -j DROP
-A PREROUTING -p tcp ! --syn -m conntrack --ctstate NEW -j DROP
-A PREROUTING -p tcp -m conntrack --ctstate NEW -m tcpmss ! --mss 536:65535 -j DROP
-A PREROUTING -p tcp --tcp-flags FIN,SYN,RST,PSH,ACK,URG NONE -j DROP
-A PREROUTING -p tcp --tcp-flags FIN,SYN FIN,SYN -j DROP
-A PREROUTING -p tcp --tcp-flags SYN,RST SYN,RST -j DROP
-A PREROUTING -p tcp --tcp-flags FIN,RST FIN,RST -j DROP
-A PREROUTING -p tcp --tcp-flags FIN,ACK FIN -j DROP
-A PREROUTING -p tcp --tcp-flags ACK,URG URG -j DROP
-A PREROUTING -p tcp --tcp-flags ACK,FIN FIN -j DROP
-A PREROUTING -p tcp --tcp-flags ACK,PSH PSH -j DROP
-A PREROUTING -p tcp --tcp-flags ALL ALL -j DROP
-A PREROUTING -p tcp --tcp-flags ALL NONE -j DROP
-A PREROUTING -p tcp --tcp-flags ALL FIN,PSH,URG -j DROP
-A PREROUTING -p tcp --tcp-flags ALL SYN,FIN,PSH,URG -j DROP
-A PREROUTING -p tcp --tcp-flags ALL SYN,RST,ACK,FIN,URG -j DROP
-A PREROUTING -p tcp --tcp-flags SYN,ACK,FIN,RST RST -m limit --limit 1/s --limit-burst 2 -j DROP
-A PREROUTING -s 10.0.0.0/8 ! -i wg0-mullvad -j DROP
-A PREROUTING -s 172.16.0.0/12 -j DROP
-A PREROUTING -s 192.168.0.0/16 -j DROP
-A PREROUTING -s 224.0.0.0/3 -j DROP
-A PREROUTING -s 169.254.0.0/16 -j DROP
-A PREROUTING -s 0.0.0.0/8 -j DROP
-A PREROUTING -s 240.0.0.0/5 -j DROP
-A PREROUTING -s 127.0.0.0/8 ! -i lo -j DROP
COMMIT
EOF
 
*filter
:INPUT DROP [0:0]
:FORWARD DROP [0:0]
:OUTPUT DROP [0:0]
-A INPUT -i lo -s 127.0.0.0/8 -d 127.0.0.0/8 -j ACCEPT
-A INPUT -m conntrack --ctstate INVALID -j DROP
-A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
-A INPUT -p tcp ! --syn -m conntrack --ctstate NEW -j DROP
-A INPUT -i wg0-mullvad -p udp -m limit --limit 10/sec --limit-burst 20 -j ACCEPT
-A INPUT -p udp -j DROP
-A INPUT -f -j DROP
-A INPUT -j DROP
-A OUTPUT -o lo -s 127.0.0.0/8 -d 127.0.0.0/8 -j ACCEPT
-A OUTPUT -m conntrack --ctstate INVALID -j DROP
-A OUTPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
-A OUTPUT -d 173.249.255.127/32 -p udp -m udp --dport 51820 -m conntrack --ctstate NEW -j ACCEPT
-A OUTPUT -o wg0-mullvad -j ACCEPT
-A OUTPUT ! -o wg0-mullvad -j DROP
COMMIT
EOF
 
cat > /etc/iptables/rules.v6 << 'EOF'
*filter
:INPUT DROP [0:0]
:FORWARD DROP [0:0]
:OUTPUT DROP [0:0]
COMMIT
EOF
 
update-alternatives --set iptables /usr/sbin/iptables-nft
update-alternatives --set ip6tables /usr/sbin/ip6tables-nft
iptables-restore /etc/iptables/rules.v4
ip6tables-restore /etc/iptables/rules.v6
iptables-save
ip6tables-save
netfilter-persistent save
chown -R root:root /etc/iptables/* 2>/dev/null || true
chmod -R 0400 /etc/iptables/* 2>/dev/null || true
chattr +i /etc/iptables/rules.v4 2>/dev/null || true
chattr +i /etc/iptables/rules.v6 2>/dev/null || true
chattr -R +i /etc/iptables/* 2>/dev/null || true
touch /etc/systemd/network/20-wired.network
chown root:root /etc/systemd/network/20-wired.network
chmod 644 /etc/systemd/network/20-wired.network

cat > /etc/systemd/network/20-wired.network << 'EOF'
[Match]
Name=enp194s0f0
 
[Network]
Address=192.168.88.190/24
Gateway=192.168.88.1
DNS=100.64.0.7
EOF
 
systemctl enable --now systemd-networkd 2>/dev/null || true
systemctl start systemd-networkd 2>/dev/null || true
systemctl disable networking 2>/dev/null || true
systemctl mask networking 2>/dev/null || true
mullvad reconnect
 
# SYSTEMD HARDENING
log_info "Disabling unnecessary systemd services..."
DISABLE=(
"accounts-daemon.service" "anacron.service" "anacron.timer" "apport.service" "apt-daily-upgrade.service" "apt-daily-upgrade.timer" "apt-daily.service" "apt-daily.timer" "aptsig.service" "avahi-daemon.service" "avahi-daemon.socket" "baloo_file.service" "bluetooth.service" "bluetooth.target" "bolt.service" "breakpoint-pre-basic.service" "breakpoint-pre-mount.service" "breakpoint-pre-switch-root.service" "breakpoint-pre-udev.service" "brltty.service" "capsule.service" "capsule.slice" "chef-client.service" "cloud-config.service" "cloud-final.service" "cloud-init-local.service" "cloud-init.service" "cloud-init.target" "cockpit.service" "cockpit.socket" "colord.service" "console-getty.service" "container-getty.service" "containerd.service" "cron.service" "ctrl-alt-del.target" "cups-browsed.service" "cups.path" "cups.service" "cups.socket" "debug-shell.service" "dm-event.service" "dm-event.socket" "docker.service" "docker.socket" "e2scrub_all.service" "e2scrub_all.timer" "e2scrub_fail0.service" "e2scrub_reap.service" "e2scrub.service" "e2scrub@.service" "emergency.service" "emergency.target" "exim4.service" "factory-reset-now.target" "factory-reset.target" "fprintd.service" "fwupd-refresh.timer" "fwupd.service" "gdm3.service" "geoclue.service" "getty@ttyS0.service" "gnome-remote-desktop.service" "gnome-software-service.service" "grub2-common.service" "hibernate.target" "hv-fcopy-daemon.service" "hv-kvp-daemon.service" "hv-vss-daemon.service" "hybrid-sleep.target" "hyperv-daemons.service" "ifup@.service" "ifupdown-online.service" "ifupdown-pre.service" "iio-sensor-proxy.service" "imports.target" "inetd.service" "iscsi.service" "iscsid.service" "iscsid.socket" "kerneloops.service" "kexec.target" "krb5-admin-server.service" "krb5-kdc.service" "libvirt-guests.service" "libvirtd-admin.socket" "libvirtd-ro.socket" "libvirtd.service" "libvirtd.socket" "lightdm.service" "lvm2-lvmpolld.service" "lvm2-lvmpolld.service" "lvm2-lvmpolld.socket" "lvm2-lvmpolld.socket" "lvm2-monitor.service" "lxc-net.service" "lxc.service" "lxd.service" "lxd.socket" "machine.slice" "machines.target" "man-db.timer" "ModemManager.service" "motd-news.timer" "multipassd.service" "multipathd.service" "networking.service" "nfs-blkmap.service" "nfs-client.target" "nfs-common.service" "nfs-idmapd.service" "nfs-mountd.service" "nfs-server.service" "nmbd.service" "nscd.service" "nslcd.service" "nvmefc-boot-connections.service" "nvmf-autoconnect.service" "open-iscsi.service" "open-vm-tools.service" "packagekit.service" "podman.service" "podman.socket" "postfix.service" "power-profiles-daemon.service" "powertop.service" "printer.target" "proc-sys-fs-binfmt_misc.automount" "proc-sys-fs-binfmt_misc.mount" "proceps.service" "proftpd.service" "puppet.service" "pure-ftpd.service" "qemu-guest-agent.service" "quotaon-root.service" "quotaon.service" "quotaon@.service" "rbdmap.service" "rc-local.service" "remote-cryptsetup.target" "remote-fs-pre.target" "remote-fs.target" "remote-integritysetup.target" "remote-veritysetup.target" "rescue.service" "rescue.target" "rpcbind.service" "rpcbind.socket" "rpcbind.target" "rsync.service" "rtkit-daemon.service" "salt-minion.service" "samba-ad-dc.service" "samba.service" "sendmail.service" "serial-getty@.service" "smbd.service" "snapd.seeded.service" "snapd.service" "snapd.socket" "snmpd.service" "snmptrapd.service" "soft-reboot.target" "speech-dispatcher.service" "spice-vdagentd.service" "spice-vdagentd.socket" "ssh.service" "ssh.socket" "sshd.service" "sshd.socket" "sssd-autofs.socket" "sssd-kcm.socket" "sssd-nss.socket" "sssd-pac.socket" "sssd-pam.socket" "sssd-ssh.socket" "sssd-sudo.socket" "sssd.service" "sssd.socket" "storage-target-node.target" "sudo.service" "suspend-then-hibernate.target" "switcheroo-control.service" "sys-fs-fuse-connections.mount" "sys-kernel-config.mount" "sys-kernel-debug.mount" "sys-kernel-tracing.mount" "system-binfmt.service" "system-update-cleanup.service" "system-update-pre.target" "system-update.target" "systemd-backlight@.service" "systemd-binfmt.service" "systemd-bsod.service" "systemd-coredump.socket" "systemd-factory-reset-complete.service" "systemd-factory-reset-reboot.service" "systemd-factory-reset-request.service" "systemd-factory-reset.socket" "systemd-factory-reset@.service" "systemd-firstboot.service" "systemd-growfs.service" "systemd-growfs@.service" "systemd-hibernate-clear.service" "systemd-hibernate-resume.service" "systemd-hibernate.service" "systemd-homed-activate.service" "systemd-homed.service" "systemd-hostnamed.service" "systemd-hybrid-sleep.service" "systemd-journal-gatewayd.socket" "systemd-journal-remote.socket" "systemd-journal-upload.service" "systemd-kexec.service" "systemd-localed.service" "systemd-loop@.service" "systemd-network-generator.service" "systemd-networkd-auto-update.service" "systemd-nspawn@.service" "systemd-pstore.service" "systemd-quotacheck-root.service" "systemd-quotacheck@.service" "systemd-rfkill.service" "systemd-rfkill.socket" "systemd-soft-reboot.service" "systemd-storagetm.service" "systemd-suspend-then-hibernate.service" "systemd-sysext-initrd.service" "systemd-sysext.service" "systemd-sysext.socket" "systemd-sysext@.service" "systemd-timedated.service" "systemd-userdbd.service" "systemd-userdbd.socket" "systemd-volatile-root.service" "telnet.socket" "tigervnc.service" "tracker-extract-3.service" "tracker-miner-fs-3.service" "tracker-miner-rss-3.service" "tracker-writeback-3.service" "udisks2.service" "unattended-upgrades.service" "usb-gadget.target" "usbip.service" "usbipd.service" "usbmuxd.service" "usbmuxd.socket" "vboxadd-service.service" "vboxadd.service" "vboxautostart-service.service" "vboxballoonctrl-service.service" "vboxdrv.service" "vboxweb-service.service" "vino-server.service" "virtlockd.service" "virtlockd.socket" "virtlogd.service" "virtlogd.socket" "vmtoolsd.service" "vmware-tools.service" "vmware-vmblock-fuse.service" "vsftpd.service" "webmin.service" "whoopsie.service" "winbind.service" "wpa_supplicant.service" "x11-common.service" "x11vnc.service" "xinetd.service" "xrdp-sesman.service" "xrdp.service" "xrdp.socket"
)
 
for svc in "${DISABLE[@]}"; do
     echo "    [-] Disabling ${svc}"
    systemctl stop "$svc" 2>/dev/null || true
    systemctl disable --now "$svc" 2>/dev/null || true
    systemctl mask --now "$svc" 2>/dev/null || true
done
 
# AMD: Removed thermald.service (Intel-only)
SERVICES_TO_ENABLE=(
    "systemd-journald.service"
    "systemd-udevd.service"
    "systemd-logind.service"
    "dbus.service"
    "pipewire.socket"
    "pipewire-pulse.socket"
    "wireplumber.service"
    "opensnitchd.service"
    "iptables-restore.service"
    "pcscd.service"
    "pcscd.socket"
    "systemd-timesyncd.service"
    "systemd-logind.service"
)
 
for svc in "${SERVICES_TO_ENABLE[@]}"; do
    echo "    [+] Enabling ${svc}"
    systemctl unmask "$svc" 2>/dev/null || true
    systemctl enable "$svc" 2>/dev/null || true
done
 
mkdir -p /etc/systemd/system.conf.d
cat > /etc/systemd/system.conf.d/hardening.conf << 'EOF'
[Manager]
DumpCore=no
CrashShell=no
DefaultLimitCORE=0
DefaultLimitNOFILE=1024
DefaultLimitNPROC=512
DefaultTimeoutStopSec=30s
EOF
 
mkdir -p /etc/systemd/user.conf.d
cat > /etc/systemd/user.conf.d/hardening.conf << 'EOF'
[Manager]
DefaultLimitCORE=0
DefaultLimitNOFILE=1024
DefaultLimitNPROC=256
EOF
 
mkdir -p /etc/systemd/journald.conf.d
cat > /etc/systemd/journald.conf.d/hardening.conf << 'EOF'
[Journal]
Storage=persistent
SystemMaxUse=500M
SystemMaxFileSize=50M
RuntimeMaxUse=100M
Compress=yes
ForwardToSyslog=no
RateLimitInterval=30s
RateLimitBurst=1000
EOF
 
mkdir -p /var/log/journal
systemd-tmpfiles --create --prefix /var/log/journal
systemctl restart systemd-journald
 
# APT HARDENING
log_info "Configuring APT hardening..."
cat > /etc/apt/apt.conf.d/99-hardening << 'EOF'
APT::Get::AllowUnauthenticated "false";
Acquire::AllowInsecureRepositories "false";
Acquire::AllowDowngradeToInsecureRepositories "false";
APT::Install-Recommends "false";
APT::Install-Suggests "false";
APT::AutoRemove::RecommendsImportant "false";
APT::AutoRemove::SuggestsImportant "false";
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Download-Upgradeable-Packages "0";
APT::Periodic::AutocleanInterval "7";
APT::Periodic::Unattended-Upgrade "0";
APT::Sandbox::Seccomp "true";
EOF
 
chown root:root /etc/apt/apt.conf.d/99-hardening 2>/dev/null || true
chmod 0640 /etc/apt/apt.conf.d/99-hardening 2>/dev/null || true
chattr +i /etc/apt/apt.conf.d/99-hardening 2>/dev/null || true
 
# PACKAGE DENY
log_info "Creating package deny list..."
install -d /etc/apt/preferences.d
cat >/etc/apt/preferences.d/deny.pref <<'EOF'
Package: aircrack* aircrack-ng* alpine* anacron* ansible* aoss* apache* ar aria2c* arj* arp* as ascii* ash aspell* at atobm* autoconf* automake* autopsy* avahi* avahi-daemon avahi-utils awk* aws* base32* base58* base64* basenc* basez* batcat* bc* bconsole* beef* beef-xss* bettercap* bind* bind9 bind9* binutils* binwalk* bison* blue* bluetooth* bluez* bochs* bpf* bridge* build* build-essential* bundle* burp* burpsuite* busctl* byebug* bz* c89* c99* cabal* cabal-install* cancel capsh* cargo* cdist* certbot* check_by_ssh* check_cups* check_log* check_memory* check_raid* check_ssl_cert* check_statusfile* chef* choom* chroot* clam* clang* cmake* cmp* cobc* cockpit* column comm composer* container* containerd containerd.io containerd.io* courier* courier-mta cow* cowsay* cpan* cpio* cpulimit* crack* crackmapexec* cron* csh* csplit* csv* cup* cups cups* cups-browsed cups-daemon curl* cut dash* date dc* dd* debug* default-jdk* default-jre* dhcp* dhcpcd* dialog* diff dig* dirb* distcc* dm* dma* dnf* dns* dnsmasq docker* docker-ce docker-ce* docker-ce-cli docker-ce-cli* docker.io docker.io* dos2unix* dosbox* dotnet* dotnet-sdk-6.0* dotnet-sdk-7.0* dotnet-sdk-8.0* dropbear dropbear* dropbear-bin dropbear-initramfs dsniff* dstat* dvips* easy_install* eb ed efax* elf* elixir* elvish* emacs* enscript* enum* enum4linux* env eqn* erlang* espeak* ettercap* ettercap-common* ettercap-graphical* ex exif* exim* exim4 exim4* exim4-base exim4-daemon-heavy exim4-daemon-light expect* facter* fastfetch* finger* fish* flatpak* flex* flock* fmt* fold fonts-noto* foremost* fortune* fpc* fping* fprint* fs-kernel-server ftp* ftpd fuzz* g++* gcc* gcloud* gcore* gdb gdb* gdebi* gem* genie* geniso* gfortran* ghc ghc* ghost* gimp* ginsh* gnustep* gobuster* golang* golang-go* grc grep gtester gzip* hash* hashcat* hd* head hex* highlight* hping* hping3* hydra* hydra-gtk* iconv* iftop* image* imagemagick* impacket* impacket-scripts* inet* inetutils-telnetd ionice* irb* ispell* iw* jjs* joe* john* join* jrunscript* jtag* julia* knife* ksh* ksshell* ksu* kube* kubectl* kubernetes* latex* ld. ldconfig* lftp* libfprint* libsql* libtool* libvirt* libvirt-clients libvirt-daemon lighttpd lighttpd* links* lldb lldb* llvm* ln* loginctl* logsave* look lp* ltrace* lua* luajit* lwp* lxc lxc* lxc-utils lxcfs lxd lxd* lxd-client lxd-client* m4* macchanger* mail* make* maltego* man* masscan* medusa* meson* metagoofil* metasploit* metasploit-framework* minicom* mitm* mitmproxy* mobile* modem* mono-complete* more mosquit* mosquitto* msg* msguniq* mtr* multitime* mysql* nasm* nawk* nbtscan* nc ncat* ncdu* nct* neofetch* netcat* nfs* nfs-common nfs-common* nfs-kernel-server* nginx nginx* nginx-core nice* nikto* ninja* ninja-build* nl nm nmap* node nodejs nodejs* nohup* npm npm* nroff* nsenter* ntpdate* octave* od open-vm* open-vm-tools* openssh* openssh-client openssh-server openssh-sftp-server openssl* opensteg* openstego* openvpn* openvt* opkg* os-prober* outguess* pandoc* paste pax* pdb* pdf* perf perlbug pexec* pg php* php-cli* php-common* pic pico* pip pip3 pipx pk* pkg* pmount* podman podman* podman-compose posh* postfix postfix* ppp* pptp* pr print* proftp* proftpd* proftpd-basic proftpd-basic* proxy* proxychains* proxychains4* pry* psftp* psql* ptx* puppet* pure* pure-ftp* pure-ftpd pure-ftpd* pure-ftpd-common pwsh* python python-is-python3* python-pip* python2* python3-pip* qemu* qemu-system-arm qemu-system-x86 qemu-user qemu-utils r-base* radar* radare2* rake* rbdmap* rc* readelf* recon* recon-ng* red redcarpet* redis* responder* restic* rev rl* rlogin rlogin* rpc* rpcbind rpcbind* rpm* rsh* rsh-client rsh-client* rsh-redone-client* rsh-server rsync* rtorrent* ruby* ruby-full* run-mailcap* run-parts* runscript* rust* rustc* rview* rvim* salt-common* salt-minion* samba samba* samba-common-bin sane* sash* scalpel* scan* scapy* scp* screen* script* scrot* sed sendmail sendmail* sendmail-base sendmail-bin service set setarch* setfacl* setlock* sftp* shuf* sleuth* sleuthkit* slsh* smb* smbclient smbclient* smbd* smbmap* snap* snapd* sniff* snmp snmp* snmpd snmpd* snmptrapd* so* socat socat* social-engineer* social-engineer-toolkit* socket* soelim* softlimit* sort spee* spice* spice-vdagent* spiderfoot* split sql* sqlmap* ss* ssh* ssl* sslstrip* stdb* steg* steghide* stegosuite* strace* strings* swig* systemd-resolve* tac tail* tar task tasksel* taskset* tasksh* tbl* tcl* tcp* tcpdump* tdbtool* tee telnet telnet* telnetd telnetd* terraform* tex tftp* tftp-hpa* theharvester* tic tiger* tigervnc* tigervnc-common tigervnc-standalone-server timedatectl* timeout* tinyssh tinyssh* tinyssh-server tk* tmate* tmux* top tor* torsocks* traceroute* tripwire* troff* tshark* ul uml* unattended* unattended-upgrades* unexpand* unicornscan* uniq* unshare* unsquashfs* update-alternatives* util-linux-locales uuen* vagrant* valgrind* varnish* vbox* vigr* vim* vipw* virsh* virt* virt-manager virtinst virtualbox virtualbox-dkms virtualbox-qt vmw* volatil* volatility* vsftp* vsftpd vsftpd* w3m* wall watch* wc webmin* wfuzz* wget* whois* winbind* wireless* wireshark* wireshark-gtk* wireshark-qt* wish* wpa* wpa-supplicant* wpasupplicant* x11vnc x11vnc* xargs* xdotool* xelatex* xen* xen-hypervisor-common xen-utils-common xetex* xinetd* xmod* xmore* xpad* xrdp xrdp* xxd* xz* yarn* yash* yasm* yersinia* yum* zathura* zenmap* zip* zmap* zram* zsh* zsoelim* zypper*
Pin: release *
Pin-Priority: -1
EOF
 
chown root:root /etc/apt/preferences.d/deny.pref 2>/dev/null || true
chmod 0640 /etc/apt/preferences.d/deny.pref 2>/dev/null || true
chattr +i /etc/apt/preferences.d/deny.pref 2>/dev/null || true
 
# PACKAGE INSTALLATION
log_info "Installing required packages..."
apt install -y librewolf rsyslog libpam-tmpdir xfce4-panel xfce4-settings xfconf xfce4-pulseaudio-plugin breeze-gtk-theme dbus-user-session gedit pipewire pipewire-pulse wireplumber libavcodec-extra ffmpeg vainfo opensnitch opensnitch-ebpf-modules python3-opensnitch-ui labwc swaybg blackbox xdg-desktop-portal-wlr qtwayland5 qt5ct seatd --no-install-recommends
 
# WAYLAND
systemctl enable seatd.service
systemctl start seatd.service
 
mkdir -p /etc/environment.d
cat > /etc/environment.d/90-wayland.conf << 'EOF'
XDG_SESSION_TYPE=wayland
QT_QPA_PLATFORM=wayland
GDK_BACKEND=wayland
SDL_VIDEODRIVER=wayland
CLUTTER_BACKEND=wayland
MOZ_ENABLE_WAYLAND=1
EOF
 
# LABWC
mkdir -p /home/user/.config
chown -R user:user /home/user/.config
mkdir -p /home/user/.config/labwc
chown -R user:user /home/user/.config/labwc
cat > /home/user/.config/labwc/autostart << 'EOF'
#!/bin/sh
 
swaybg -c '#112233' &
xfce4-panel &
opensnitch-ui &
EOF
 
chown user:user /home/user/.config/labwc/autostart 2>/dev/null || true
chmod +x /home/user/.config/labwc/autostart 2>/dev/null || true
chattr +i /home/user/.config/labwc/autostart 2>/dev/null || true
 
cat > /home/user/.config/labwc/environment << 'EOF'
XDG_CURRENT_DESKTOP=XFCE
QT_QPA_PLATFORMTHEME=qt5ct
QT_QPA_PLATFORM=wayland
GDK_BACKEND=wayland
MOZ_ENABLE_WAYLAND=1
EOF
 
chown user:user /home/user/.config/labwc/environment 2>/dev/null || true
chattr +i /home/user/.config/labwc/environment 2>/dev/null || true
 
# ACCOUNTS/GROUPS
log_info "Purging and setting up accounts/groups..."
for grp in _ssh bluetooth nogroup fax floppy irc kvm voice games; do
    groupdel "$grp" --force 2>/dev/null || true
done
for usr in nobody games irc uucp proxy backup dhcpcd list news sync man mail lp www-data; do
    userdel "$usr" 2>/dev/null || true
done
for grp in render input video audio tty seat; do
    adduser user "$grp" 2>/dev/null || true
done
 
# MISC HARDENING
log_info "Applying miscellaneous hardening..."
cat >/etc/shells <<'EOF'
/bin/bash
EOF
 
chown root:root /etc/shells 2>/dev/null || true
chmod 0400 /etc/shells 2>/dev/null || true
chattr +i /etc/shells 2>/dev/null || true
 
cat >/etc/host.conf <<'EOF'
multi on
order hosts
EOF
 
cat > /etc/profile.d/umask.sh << 'EOF'
umask 077
EOF
 
chmod 644 /etc/profile.d/umask.sh
 
cat > /etc/security/limits.d/limits.conf <<'EOF'
*        soft    nproc         1024
*        hard    nproc         1024
*        -       maxlogins     1
*        -       maxsyslogins  1
user     soft    nproc         2048
user     hard    nproc         2048
user     -       maxlogins     1
user     -       maxsyslogins  1
root     soft    nproc         4096
root     hard    nproc         4096
root     -       maxlogins     1
root     -       maxsyslogins  1
EOF
 
chown root:root /etc/security/limits.d/limits.conf 2>/dev/null || true
chmod 0600 /etc/security/limits.d/limits.conf 2>/dev/null || true
 
mkdir -p /var/crash
chmod 0000 /var/crash 
mkdir -p /etc/systemd/coredump.conf.d
cat > /etc/systemd/coredump.conf.d/disable.conf << 'EOF'
[Coredump]
ProcessSizeMax=0
Storage=none
EOF
 
chown root:root /etc/systemd/coredump.conf.d/disable.conf 2>/dev/null || true
chmod 0644 /etc/systemd/coredump.conf.d/disable.conf 2>/dev/null || true
chattr +i /etc/systemd/coredump.conf.d/disable.conf 2>/dev/null || true
chattr -R +i /etc/systemd/coredump.conf.d 2>/dev/null || true
 
sed -i 's|^ENCRYPT_METHOD.*|ENCRYPT_METHOD YESCRYPT|' /etc/login.defs
sed -i 's|^UID_MIN.*|UID_MIN 1000|' /etc/login.defs
sed -i 's|^UID_MAX.*|UID_MAX 65535|' /etc/login.defs
sed -i 's|^PASS_MAX_DAYS.*|PASS_MAX_DAYS   99999|' /etc/login.defs
sed -i 's|^PASS_MIN_DAYS.*|PASS_MIN_DAYS   99999|' /etc/login.defs
sed -i 's|^CHFN_RESTRICT.*|CHFN_RESTRICT     rwh|' /etc/login.defs
sed -i 's|^#TTYGROUP.*|TTYGROUP       tty|' /etc/login.defs
sed -i 's|^LOGIN_RETRIES.*|LOGIN_RETRIES 2|' /etc/login.defs
sed -i 's|^LOG_OK_LOGINS.*|LOG_OK_LOGINS yes|' /etc/login.defs
sed -i 's|^DEFAULT_HOME.*|DEFAULT_HOME no|' /etc/login.defs
sed -i 's|^SHELL=.*|SHELL=/usr/sbin/nologin|' /etc/default/useradd
sed -i 's|^# HOME=.*|HOME=/home|' /etc/default/useradd
sed -i 's|^# SKEL=.*|SKEL=|' /etc/default/useradd
sed -i 's|^#DSHELL=.*|DSHELL=/usr/sbin/nologin|' /etc/adduser.conf
sed -i 's|^#DHOME=.*|DHOME=/home|' /etc/adduser.conf
sed -i 's|^#SKEL=/etc/skel.*|SKEL=|' /etc/adduser.conf
sed -i 's|^#DIR_MODE=.*|DIR_MODE=0700|' /etc/adduser.conf
sed -i 's|^#SYS_DIR_MODE=.*|SYS_DIR_MODE=0750|' /etc/adduser.conf
sed -i 's|^#ADD_EXTRA_GROUPS=.*|ADD_EXTRA_GROUPS=0|' /etc/adduser.conf
grep -q "ulimit -c 0" /etc/profile || echo "ulimit -c 0" >> /etc/profile
grep -q "^UMASK 077" /etc/login.defs || echo "UMASK 077" >> /etc/login.defs
grep -q "^umask 077" /etc/profile || echo "umask 077" >> /etc/profile
grep -q "^umask 077" /etc/bash.bashrc || echo "umask 077" >> /etc/bash.bashrc
echo "ALL: LOCAL, 127.0.0.1" > /etc/hosts.allow
echo "ALL: ALL" > /etc/hosts.deny
 
chown -R root:root /etc/login.defs /etc/default/useradd /etc/adduser.conf /etc/profile /etc/bash.bashrc /etc/host* 2>/dev/null || true
chmod 0644 /etc/login.defs /etc/default/useradd /etc/adduser.conf /etc/profile /etc/bash.bashrc /etc/host* 2>/dev/null || true
 
cat > /etc/security/access.conf << 'EOF'
+:user:LOCAL
-:ALL EXCEPT user:LOCAL
-:user:ALL EXCEPT LOCAL
-:root:ALL
-:ALL:REMOTE
-:ALL:ALL
EOF
 
chown -R root:root /etc/security/access.conf 2>/dev/null || true
chmod 644 /etc/security/access.conf 2>/dev/null || true
chattr +i /etc/security/access.conf 2>/dev/null || true
 
# SECURE PATH
log_info "Setting up secure paths..."
SECURE_SUPATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin"
SECURE_PATH="/usr/local/bin:/usr/bin"
sed -i "s|^ENV_SUPATH.*|ENV_SUPATH      PATH=$SECURE_SUPATH|" /etc/login.defs
sed -i "s|^ENV_PATH.*|ENV_PATH        PATH=$SECURE_PATH|" /etc/login.defs
sed -i "s|PATH=\"/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\"|PATH=\"$SECURE_SUPATH\"|g" /etc/profile
sed -i "s|PATH=\"/usr/local/bin:/usr/bin:/bin\"|PATH=\"$SECURE_PATH\"|g" /etc/profile
sed -i "s|^PATH=.*|PATH=\"$SECURE_SUPATH\"|" /etc/environment
 
# GRUB - AMD RYZEN 9 AI 370HX (ZEN 5 / RDNA 3.5) OPTIMIZED
log_info "Hardening GRUB bootloader (AMD Ryzen AI 370HX)..."
log_warn "Using AMD-specific kernel parameters (NOT Intel)"
sed -i 's/^#GRUB_DISABLE_OS_PROBER=.*/GRUB_DISABLE_OS_PROBER=true/' /etc/default/grub
sed -i 's/^#GRUB_DISABLE_LINUX_UUID=.*/GRUB_DISABLE_LINUX_UUID=true/' /etc/default/grub
sed -i 's/^#GRUB_DISABLE_RECOVERY=.*/GRUB_DISABLE_RECOVERY=true/' /etc/default/grub
sed -i 's|^GRUB_CMDLINE_LINUX_DEFAULT=.*|GRUB_CMDLINE_LINUX_DEFAULT="nosmt=force spectre_v2=on spectre_bhi=on spec_store_bypass_disable=on ssbd=force-on amd_iommu=on iommu=force iommu.passthrough=0 iommu.strict=1 init_on_alloc=1 init_on_free=1 pti=on vsyscall=none page_alloc.shuffle=1 randomize_kstack_offset=on slab_nomerge slab_debug=FZ debugfs=off oops=panic ipv6.disable=1 nowatchdog nmi_watchdog=0 vdso32=0 efi_pstore.pstore_disable=1 erst_disable bdev_allow_write_mounted=0 proc_mem.force_override=ptrace efi=disable_early_pci_dma random.trust_cpu=off random.trust_bootloader=off extra_latent_entropy rd.emergency=halt rd.shell=0 apparmor=1 security=apparmor amdgpu.dcdebugmask=0x10 amdgpu.sg_display=0 amdgpu.gfx_off=0"|' /etc/default/grub
update-grub
chown root:root /etc/default/grub 2>/dev/null || true
chmod 640 /etc/default/grub 2>/dev/null || true
chattr +i /etc/default/grub 2>/dev/null || true
 
# OPENSSL
log_info "Hardening OpenSSL..."
mkdir -p /etc/gnutls
 
cat >/etc/ssl/openssl.cnf <<EOF
# OpenSSL Hardened Configuration
openssl_conf=openssl_init
 
[openssl_init]
ssl_conf=ssl_sect
providers=provider_sect
 
[provider_sect]
default=default_sect
 
[default_sect]
activate=1
 
[ssl_sect]
system_default=system_default_sect
 
[system_default_sect]
# Minimum TLS version
MinProtocol=TLSv1.2
 
# TLS 1.3 ciphersuites (auth/kex negotiated separately)
CipherSuites=TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_SHA256
 
# TLS 1.2 ciphersuites (ECDHE/DHE only, AEAD only, RSA auth allowed)
CipherString=ECDHE+AESGCM:ECDHE+CHACHA20:DHE+AESGCM:DHE+CHACHA20:!aNULL:!eNULL:!EXPORT:!DES:!RC4:!3DES:!MD5:!PSK:!SHA1
 
# Strong curves only
Curves=X25519:secp384r1:secp256r1
 
# Signature algorithms
SignatureAlgorithms=ed25519:ed448:rsa_pss_pss_sha512:rsa_pss_pss_sha384:rsa_pss_pss_sha256:rsa_pss_rsae_sha512:rsa_pss_rsae_sha384:rsa_pss_rsae_sha256:ecdsa_secp384r1_sha384:ecdsa_secp256r1_sha256
 
# Options
Options=ServerPreference,PrioritizeChaCha,NoCompression
EOF
 
chown root:root /etc/ssl/openssl.cnf 2>/dev/null || true
chmod 0640 /etc/ssl/openssl.cnf 2>/dev/null || true
chattr +i /etc/ssl/openssl.cnf 2>/dev/null || true
 
cat > /etc/gnutls/config <<EOF
[global]
# Minimum TLS version
min-verification-profile=medium
 
[priorities]
SYSTEM=SECURE256:+SECURE128:-VERS-TLS1.0:-VERS-TLS1.1:-VERS-DTLS1.0:-VERS-DTLS1.2:-CIPHER-ALL:+AES-256-GCM:+AES-128-GCM:+CHACHA20-POLY1305:-MAC-ALL:+AEAD:-KX-ALL:+ECDHE-ECDSA:+ECDHE-RSA:+DHE-RSA:-CURVE-ALL:+CURVE-X25519:+CURVE-SECP384R1:+CURVE-SECP256R1:-SIGN-ALL:+SIGN-EDDSA-ED25519:+SIGN-ECDSA-SECP384R1-SHA384:+SIGN-ECDSA-SECP256R1-SHA256:+SIGN-RSA-PSS-RSAE-SHA512:+SIGN-RSA-PSS-RSAE-SHA384:+SIGN-RSA-PSS-RSAE-SHA256:%SAFE_RENEGOTIATION:%NO_SESSION_HASH
EOF
 
chown root:root /etc/gnutls/config 2>/dev/null || true
chmod 0640 /etc/gnutls/config 2>/dev/null || true
chattr +i /etc/gnutls/config 2>/dev/null || true
 
# SYSCTL 
log_info "Applying sysctl hardening..."
rm -rf /usr/lib/sysctl.d
mkdir -p /usr/lib/sysctl.d
cat > /usr/lib/sysctl.d/sysctl.conf << 'EOF'
abi.vsyscall32=0
dev.tty.ldisc_autoload=0
dev.tty.legacy_tiocsti=0
fs.protected_fifos=2
fs.protected_hardlinks=1
fs.protected_regular=2
fs.protected_symlinks=1
fs.suid_dumpable=0
kernel.core_pattern=|/bin/false
kernel.core_uses_pid=1
kernel.ctrl-alt-del=0
kernel.dmesg_restrict=1
kernel.ftrace_enabled=0
kernel.io_uring_disabled=2
kernel.kallsyms_restrict=1
kernel.kexec_load_disabled=1
kernel.kptr_restrict=2
kernel.nmi_watchdog=0
kernel.panic=1
kernel.panic_on_oops=1
kernel.perf_cpu_time_max_percent=1
kernel.perf_event_max_sample_rate=1
kernel.perf_event_paranoid=3
kernel.printk=3 3 3 3
kernel.printk_devkmsg=off
kernel.randomize_va_space=2
kernel.sched_autogroup_enabled=1
kernel.stack_tracer_enabled=0
kernel.sysrq=0
kernel.unprivileged_bpf_disabled=1
kernel.unprivileged_userns_clone=0
kernel.watchdog=0
kernel.yama.ptrace_scope=3
net.core.bpf_jit_enable=0
net.core.bpf_jit_harden=2
net.core.netdev_max_backlog=65535
net.core.optmem_max=65536
net.core.rmem_default=262144
net.core.rmem_max=6291456
net.core.somaxconn=65535
net.core.wmem_default=262144
net.core.wmem_max=6291456
net.ipv4.conf.all.accept_redirects=0
net.ipv4.conf.all.accept_source_route=0
net.ipv4.conf.all.arp_accept=0
net.ipv4.conf.all.arp_announce=2
net.ipv4.conf.all.arp_notify=0
net.ipv4.conf.all.bootp_relay=0
net.ipv4.conf.all.forwarding=0
net.ipv4.conf.all.log_martians=0
net.ipv4.conf.all.mc_forwarding=0
net.ipv4.conf.all.proxy_arp=0
net.ipv4.conf.all.rp_filter=1
net.ipv4.conf.all.secure_redirects=0
net.ipv4.conf.all.send_redirects=0
net.ipv4.conf.all.shared_media=0
net.ipv4.conf.default.accept_redirects=0
net.ipv4.conf.default.accept_source_route=0
net.ipv4.conf.default.forwarding=0
net.ipv4.conf.default.log_martians=0
net.ipv4.conf.default.mc_forwarding=0
net.ipv4.conf.default.proxy_arp=0
net.ipv4.conf.default.rp_filter=1
net.ipv4.conf.default.secure_redirects=0
net.ipv4.conf.default.send_redirects=0
net.ipv4.conf.default.shared_media=0
net.ipv4.icmp_echo_ignore_all=1
net.ipv4.icmp_echo_ignore_broadcasts=1
net.ipv4.icmp_ignore_bogus_error_responses=1
net.ipv4.icmp_ratelimit=10
net.ipv4.icmp_ratemask=88089
net.ipv4.ip_forward=0
net.ipv4.ping_group_range=65535 65535
net.ipv4.tcp_dsack=0
net.ipv4.tcp_fack=0
net.ipv4.tcp_fin_timeout=15
net.ipv4.tcp_invalid_ratelimit=500
net.ipv4.tcp_keepalive_intvl=15
net.ipv4.tcp_keepalive_probes=5
net.ipv4.tcp_keepalive_time=300
net.ipv4.tcp_limit_output_bytes=262144
net.ipv4.tcp_max_syn_backlog=4096
net.ipv4.tcp_max_tw_buckets=65536
net.ipv4.tcp_notsent_lowat=16384
net.ipv4.tcp_rfc1337=1
net.ipv4.tcp_sack=0
net.ipv4.tcp_syn_retries=2
net.ipv4.tcp_synack_retries=2
net.ipv4.tcp_syncookies=1
net.ipv4.tcp_timestamps=0
net.ipv4.tcp_tw_reuse=0
net.ipv6.conf.all.accept_ra=0
net.ipv6.conf.default.accept_ra=0
net.ipv6.conf.all.accept_source_route=0
net.ipv6.conf.default.accept_source_route=0
net.ipv6.conf.all.disable_ipv6=1
net.ipv6.conf.default.disable_ipv6=1
net.ipv6.conf.lo.disable_ipv6=1
net.ipv6.icmp.echo_ignore_all=1
net.netfilter.nf_conntrack_helper=0
net.netfilter.nf_conntrack_max=131072
net.netfilter.nf_conntrack_tcp_be_liberal=0
net.netfilter.nf_conntrack_tcp_loose=0
net.netfilter.nf_conntrack_tcp_max_retrans=3
net.netfilter.nf_conntrack_tcp_timeout_close=10
net.netfilter.nf_conntrack_tcp_timeout_close_wait=10
net.netfilter.nf_conntrack_tcp_timeout_established=1800
net.netfilter.nf_conntrack_tcp_timeout_fin_wait=20
net.netfilter.nf_conntrack_tcp_timeout_last_ack=20
net.netfilter.nf_conntrack_tcp_timeout_syn_recv=20
net.netfilter.nf_conntrack_tcp_timeout_syn_sent=20
net.netfilter.nf_conntrack_tcp_timeout_time_wait=10
user.max_user_namespaces=0
vm.max_map_count=1048576
vm.mmap_min_addr=65536
vm.mmap_rnd_bits=32
vm.mmap_rnd_compat_bits=16
vm.oom_kill_allocating_task=1
vm.overcommit_memory=0
vm.overcommit_ratio=100
vm.panic_on_oom=0
vm.swappiness=1
vm.unprivileged_userfaultfd=0
EOF
 
chown root:root /usr/lib/sysctl.d/sysctl.conf 2>/dev/null || true 
chmod 0640 /usr/lib/sysctl.d/sysctl.conf 2>/dev/null || true
 
# MODULES - AMD OPTIMIZED (Intel-specific modules removed)
log_info "Blacklisting kernel modules..."
cat > /etc/modprobe.d/harden.conf << 'EOF'
blacklist 9p
install 9p /bin/false
blacklist adfs
install adfs /bin/false
blacklist af_802154
install af_802154 /bin/false
blacklist affs
install affs /bin/false
blacklist afs
install afs /bin/false
blacklist amd76x_edac
install amd76x_edac /bin/false
blacklist appletalk
install appletalk /bin/false
blacklist asus_acpi
install asus_acpi /bin/false
blacklist ath10k_pci
install ath10k_pci /bin/false
blacklist ath10k_sdio
install ath10k_sdio /bin/false
blacklist ath10k_usb
install ath10k_usb /bin/false
blacklist ath11k
install ath11k /bin/false
blacklist ath11k_pci
install ath11k_pci /bin/false
blacklist ath6kl_sdio
install ath6kl_sdio /bin/false
blacklist ath6kl_usb
install ath6kl_usb /bin/false
blacklist ath9k
install ath9k /bin/false
blacklist ath9k_htc
install ath9k_htc /bin/false
blacklist ath_pci
install ath_pci /bin/false
blacklist atm
install atm /bin/false
blacklist aty128fb
install aty128fb /bin/false
blacklist atyfb
install atyfb /bin/false
blacklist ax25
install ax25 /bin/false
blacklist bcm43xx
install bcm43xx /bin/false
blacklist befs
install befs /bin/false
blacklist bluetooth
install bluetooth /bin/false
blacklist bluetooth_6lowpan
install bluetooth_6lowpan /bin/false
blacklist brcm80211
install brcm80211 /bin/false
blacklist brcmfmac
install brcmfmac /bin/false
blacklist brcmsmac
install brcmsmac /bin/false
blacklist bt3c_cs
install bt3c_cs /bin/false
blacklist btbcm
install btbcm /bin/false
blacklist btintel
install btintel /bin/false
blacklist btmrvl
install btmrvl /bin/false
blacklist btmrvl_sdio
install btmrvl_sdio /bin/false
blacklist btmtk
install btmtk /bin/false
blacklist btmtksdio
install btmtksdio /bin/false
blacklist btmtkuart
install btmtkuart /bin/false
blacklist btnxpuart
install btnxpuart /bin/false
blacklist btqca
install btqca /bin/false
blacklist btrsi
install btrsi /bin/false
blacklist btrtl
install btrtl /bin/false
blacklist btsdio
install btsdio /bin/false
blacklist btusb
install btusb /bin/false
blacklist c_can
install c_can /bin/false
blacklist c_can_pci
install c_can_pci /bin/false
blacklist c_can_platform
install c_can_platform /bin/false
blacklist can
install can /bin/false
blacklist can_bcm
install can_bcm /bin/false
blacklist can_dev
install can_dev /bin/false
blacklist can_gw
install can_gw /bin/false
blacklist can_isotp
install can_isotp /bin/false
blacklist can_j1939
install can_j1939 /bin/false
blacklist can_raw
install can_raw /bin/false
blacklist can327
install can327 /bin/false
blacklist ceph
install ceph /bin/false
blacklist cfg80211
install cfg80211 /bin/false
blacklist cifs
install cifs /bin/false
blacklist cifs_arc4
install cifs_arc4 /bin/false
blacklist cifs_md4
install cifs_md4 /bin/false
blacklist cirrusfb
install cirrusfb /bin/false
blacklist coda
install coda /bin/false
blacklist cramfs
install cramfs /bin/false
blacklist cyber2000fb
install cyber2000fb /bin/false
blacklist cyblafb
install cyblafb /bin/false
blacklist dccp
install dccp /bin/false
blacklist de4x5
install de4x5 /bin/false
blacklist decnet
install decnet /bin/false
blacklist dv1394
install dv1394 /bin/false
blacklist dvb_core
install dvb_core /bin/false
blacklist dvb_usb
install dvb_usb /bin/false
blacklist dvb_usb_v2
install dvb_usb_v2 /bin/false
blacklist econet
install econet /bin/false
blacklist ecryptfs
install ecryptfs /bin/false
blacklist eepro100
install eepro100 /bin/false
blacklist eth1394
install eth1394 /bin/false
blacklist evbug
install evbug /bin/false
blacklist firewire_core
install firewire_core /bin/false
blacklist firewire_net
install firewire_net /bin/false
blacklist firewire_ohci
install firewire_ohci /bin/false
blacklist firewire_sbp2
install firewire_sbp2 /bin/false
blacklist floppy
install floppy /bin/false
blacklist freevxfs
install freevxfs /bin/false
blacklist garmin_gps
install garmin_gps /bin/false
blacklist gfs2
install gfs2 /bin/false
blacklist gnss
install gnss /bin/false
blacklist gnss_mtk
install gnss_mtk /bin/false
blacklist gnss_serial
install gnss_serial /bin/false
blacklist gnss_sirf
install gnss_sirf /bin/false
blacklist gnss_ubx
install gnss_ubx /bin/false
blacklist gnss_usb
install gnss_usb /bin/false
blacklist gx1fb
install gx1fb /bin/false
blacklist hamradio
install hamradio /bin/false
blacklist hfs
install hfs /bin/false
blacklist hfsplus
install hfsplus /bin/false
blacklist hgafb
install hgafb /bin/false
blacklist i810fb
install i810fb /bin/false
blacklist ifi_canfd
install ifi_canfd /bin/false
blacklist ipv6
install ipv6 /bin/false
blacklist ipx
install ipx /bin/false
blacklist iwldvm
install iwldvm /bin/false
blacklist iwlmvm
install iwlmvm /bin/false
blacklist iwlwifi
install iwlwifi /bin/false
blacklist janz_ican3
install janz_ican3 /bin/false
blacklist jffs2
install jffs2 /bin/false
blacklist jfs
install jfs /bin/false
blacklist joydev
install joydev /bin/false
blacklist kafs
install kafs /bin/false
blacklist ksmbd
install ksmbd /bin/false
blacklist kvm
install kvm /bin/false
blacklist kvm_amd
install kvm_amd /bin/false
blacklist kvm_intel
install kvm_intel /bin/false
blacklist kyrofb
install kyrofb /bin/false
blacklist lp
install lp /bin/false
blacklist lxfb
install lxfb /bin/false
blacklist m_can
install m_can /bin/false
blacklist m_can_pci
install m_can_pci /bin/false
blacklist m_can_platform
install m_can_platform /bin/false
blacklist mac80211
install mac80211 /bin/false
blacklist matroxfb_base
install matroxfb_base /bin/false
blacklist minix
install minix /bin/false
blacklist msr
install msr /bin/false
blacklist mt76
install mt76 /bin/false
blacklist mt7601u
install mt7601u /bin/false
blacklist mt7615e
install mt7615e /bin/false
blacklist mt76_usb
install mt76_usb /bin/false
blacklist mt76x0u
install mt76x0u /bin/false
blacklist mt76x2u
install mt76x2u /bin/false
blacklist mt7921e
install mt7921e /bin/false
blacklist n_hdlc
install n_hdlc /bin/false
blacklist nbd
install nbd /bin/false
blacklist neofb
install neofb /bin/false
blacklist netrom
install netrom /bin/false
blacklist nfs
install nfs /bin/false
blacklist nfs_acl
install nfs_acl /bin/false
blacklist nfs_layout_flexfiles
install nfs_layout_flexfiles /bin/false
blacklist nfs_layout_nfsv41_files
install nfs_layout_nfsv41_files /bin/false
blacklist nfsd
install nfsd /bin/false
blacklist nfsv2
install nfsv2 /bin/false
blacklist nfsv3
install nfsv3 /bin/false
blacklist nfsv4
install nfsv4 /bin/false
blacklist nilfs2
install nilfs2 /bin/false
blacklist nouveau
install nouveau /bin/false
blacklist nvidiafb
install nvidiafb /bin/false
blacklist ocfs2
install ocfs2 /bin/false
blacklist ohci1394
install ohci1394 /bin/false
blacklist orangefs
install orangefs /bin/false
blacklist p8022
install p8022 /bin/false
blacklist p8023
install p8023 /bin/false
blacklist parport
install parport /bin/false
blacklist pcspkr
install pcspkr /bin/false
blacklist phy_can_transceiver
install phy_can_transceiver /bin/false
blacklist pm2fb
install pm2fb /bin/false
blacklist ppdev
install ppdev /bin/false
blacklist prism54
install prism54 /bin/false
blacklist psnap
install psnap /bin/false
blacklist r820t
install r820t /bin/false
blacklist radeonfb
install radeonfb /bin/false
blacklist raw1394
install raw1394 /bin/false
blacklist rds
install rds /bin/false
blacklist rds_rdma
install rds_rdma /bin/false
blacklist rds_tcp
install rds_tcp /bin/false
blacklist reiserfs
install reiserfs /bin/false
blacklist rivafb
install rivafb /bin/false
blacklist rndis_host
install rndis_host /bin/false
blacklist romfs
install romfs /bin/false
blacklist rose
install rose /bin/false
blacklist rt2800lib
install rt2800lib /bin/false
blacklist rt2800pci
install rt2800pci /bin/false
blacklist rt2800usb
install rt2800usb /bin/false
blacklist rtl2830
install rtl2830 /bin/false
blacklist rtl2832
install rtl2832 /bin/false
blacklist rtl2832_sdr
install rtl2832_sdr /bin/false
blacklist rtl2838
install rtl2838 /bin/false
blacklist rtl8188ee
install rtl8188ee /bin/false
blacklist rtl8192ce
install rtl8192ce /bin/false
blacklist rtl8192cu
install rtl8192cu /bin/false
blacklist rtl8192de
install rtl8192de /bin/false
blacklist rtl8192se
install rtl8192se /bin/false
blacklist rtl8723ae
install rtl8723ae /bin/false
blacklist rtl8723be
install rtl8723be /bin/false
blacklist rtl8821ae
install rtl8821ae /bin/false
blacklist rtl88x2bu
install rtl88x2bu /bin/false
blacklist rtl8xxxu
install rtl8xxxu /bin/false
blacklist s1d13xxxfb
install s1d13xxxfb /bin/false
blacklist savagefb
install savagefb /bin/false
blacklist sbp2
install sbp2 /bin/false
blacklist sctp
install sctp /bin/false
blacklist sctp_diag
install sctp_diag /bin/false
blacklist sisfb
install sisfb /bin/false
blacklist slcan
install slcan /bin/false
blacklist snd_aw2
install snd_aw2 /bin/false
blacklist snd_intel8x0
install snd_intel8x0 /bin/false
blacklist snd_intel8x0m
install snd_intel8x0m /bin/false
blacklist snd_pcsp
install snd_pcsp /bin/false
blacklist smbfs
install smbfs /bin/false
blacklist squashfs
install squashfs /bin/false
blacklist sstfb
install sstfb /bin/false
blacklist sysv
install sysv /bin/false
blacklist tdfxfb
install tdfxfb /bin/false
blacklist thunderbolt
install thunderbolt /bin/false
blacklist thunderbolt_net
install thunderbolt_net /bin/false
blacklist tipc
install tipc /bin/false
blacklist tipc_diag
install tipc_diag /bin/false
blacklist tls
install tls /bin/false
blacklist tridentfb
install tridentfb /bin/false
blacklist uas
install uas /bin/false
blacklist ubifs
install ubifs /bin/false
blacklist ucan
install ucan /bin/false
blacklist udf
install udf /bin/false
blacklist udlfb
install udlfb /bin/false
blacklist ueagle_atm
install ueagle_atm /bin/false
blacklist ufs
install ufs /bin/false
blacklist usb_f_rndis
install usb_f_rndis /bin/false
blacklist usb_storage
install usb_storage /bin/false
blacklist usbatm
install usbatm /bin/false
blacklist usbkbd
install usbkbd /bin/false
blacklist uvcvideo
install uvcvideo /bin/false
blacklist vboxdrv
install vboxdrv /bin/false
blacklist vboxnetadp
install vboxnetadp /bin/false
blacklist vboxnetflt
install vboxnetflt /bin/false
blacklist vcan
install vcan /bin/false
blacklist vesafb
install vesafb /bin/false
blacklist vfb
install vfb /bin/false
blacklist vhost
install vhost /bin/false
blacklist vhost_net
install vhost_net /bin/false
blacklist vhost_vsock
install vhost_vsock /bin/false
blacklist viafb
install viafb /bin/false
blacklist video1394
install video1394 /bin/false
blacklist videobuf2_common
install videobuf2_common /bin/false
blacklist videobuf2_v4l2
install videobuf2_v4l2 /bin/false
blacklist videodev
install videodev /bin/false
blacklist virtio_balloon
install virtio_balloon /bin/false
blacklist virtio_bt
install virtio_bt /bin/false
blacklist virtio_console
install virtio_console /bin/false
blacklist vivid
install vivid /bin/false
blacklist vmmon
install vmmon /bin/false
blacklist vmw_vmci
install vmw_vmci /bin/false
blacklist vt8623fb
install vt8623fb /bin/false
blacklist vxcan
install vxcan /bin/false
blacklist x25
install x25 /bin/false
blacklist xen
install xen /bin/false
blacklist xusbatm
install xusbatm /bin/false
blacklist zonefs
install zonefs /bin/false
EOF
 
chown root:root /etc/modprobe.d/harden.conf 2>/dev/null || true
chmod 0640 /etc/modprobe.d/harden.conf 2>/dev/null || true
update-initramfs -u -k all
 
# FSTAB 
log_info "Configuring filesystem mounts..."
cp /etc/fstab /etc/fstab.bak
 
if ! grep -q "proc.*hidepid=2" /etc/fstab; then
    cat >> /etc/fstab << 'EOF'
proc     /proc      proc      noatime,nodev,nosuid,noexec,hidepid=2,gid=proc    0 0
tmpfs    /tmp       tmpfs     size=2G,noatime,nodev,nosuid,noexec,mode=1777     0 0
tmpfs    /var/tmp   tmpfs     size=1G,noatime,nodev,nosuid,noexec,mode=1777     0 0
tmpfs    /dev/shm   tmpfs     size=512M,noatime,nodev,nosuid,noexec   0 0
tmpfs    /run       tmpfs     size=512M,noatime,nodev,nosuid,mode=0755          0 0
EOF
fi
 
chown root:root /etc/fstab 2>/dev/null || true
chmod 0640 /etc/fstab 2>/dev/null || true
groupadd -f proc
adduser root proc
adduser user proc
 
# PERMISSIONS
log_info "Securing file permissions..."
chmod 0700 /root 2>/dev/null || true
chown root:root /root 2>/dev/null || true
chmod 0700 /home/user 2>/dev/null || true
chown user:user /home/user 2>/dev/null || true
find /home/user -type f -exec chmod o-rwx {} \; 2>/dev/null || true
find /home/user -type d -exec chmod o-rwx {} \; 2>/dev/null || true
chmod 0600 /etc/shadow 2>/dev/null || true
chmod 0600 /etc/gshadow 2>/dev/null || true
chown root:root /etc/shadow 2>/dev/null || true
chown root:root /etc/gshadow 2>/dev/null || true
chmod 0644 /etc/passwd 2>/dev/null || true
chmod 0644 /etc/group 2>/dev/null || true
chown root:root /etc/passwd 2>/dev/null || true
chown root:root /etc/group 2>/dev/null || true
chmod 0440 /etc/sudoers 2>/dev/null || true
chown root:root /etc/sudoers 2>/dev/null || true
chmod 0000 /etc/sudoers.d 2>/dev/null || true
chown root:root /etc/sudoers.d 2>/dev/null || true
find /etc/sudoers.d -type f -exec chmod 0000 {} \; 2>/dev/null || true
chmod 0644 /etc/pam.d/* 2>/dev/null || true
chown root:root /etc/pam.d/* 2>/dev/null || true
chmod 0644 /etc/security/access.conf 2>/dev/null || true
chmod 0600 /etc/security/limits.conf 2>/dev/null || true
chmod 0600 /etc/security/namespace.conf 2>/dev/null || true
chown root:root /etc/security/* 2>/dev/null || true
if [[ -d /etc/ssh ]]; then
    rm -r /etc/ssh 2>/dev/null || true
    mkdir /etc/ssh 2>/dev/null || true
    chmod 0000 /etc/ssh 2>/dev/null || true
    chattr -R +i /etc/ssh 2>/dev/null || true
fi
rm -r /etc/cron*
 if [[ -f /etc/at.deny ]]; then
    chmod 0600 /etc/at.deny 2>/dev/null || true
fi
 chmod 0700 /boot 2>/dev/null || true
chown root:root /boot 2>/dev/null || true
find /boot -type f -name "vmlinuz*" -exec chmod 0600 {} \; 2>/dev/null || true
find /boot -type f -name "initrd*" -exec chmod 0600 {} \; 2>/dev/null || true
find /boot -type f -name "System.map*" -exec chmod 0600 {} \; 2>/dev/null || true
find /boot -type f -name "config-*" -exec chmod 0600 {} \; 2>/dev/null || true
if [[ -f /boot/grub/grub.cfg ]]; then
    chmod 0600 /boot/grub/grub.cfg 2>/dev/null || true
    chown root:root /boot/grub/grub.cfg 2>/dev/null || true
fi
log_info "Checking for world-writable and unknowned files"
WORLD_WRITABLE=$(find / -xdev -type f -perm -0002 \
    ! -path "/tmp/*" \
    ! -path "/var/tmp/*" \
    ! -path "/proc/*" \
    ! -path "/sys/*" \
    2>/dev/null || true)
 
if [[ -n "$WORLD_WRITABLE" ]]; then
    echo "[!] Found world-writable files:"
    echo "$WORLD_WRITABLE"
    echo "[*] Removing world-writable bit from these files"
    echo "$WORLD_WRITABLE" | xargs -r chmod o-w
fi
chown root:adm -R /var/log 2>/dev/null || true
chmod -R 0750 /var/log 2>/dev/null || true
 
UNOWNED=$(find / -xdev \( -nouser -o -nogroup \) \
    ! -path "/proc/*" \
    ! -path "/sys/*" \
    2>/dev/null || true)
 
if [[ -n "$UNOWNED" ]]; then
    echo "[!] Found unowned files (review manually):"
    echo "$UNOWNED"
fi
 
find / -xdev -type d -perm -0002 \
    ! -path "/proc/*" \
    ! -path "/sys/*" \
    -exec chmod +t {} \; 2>/dev/null || true
 
# USBGUARD
log_info "Installing and configuring USBGuard"
apt-get update
apt-get install -y usbguard usbutils
usbguard generate-policy > /etc/usbguard/rules.conf
 
# Add FIDO/U2F whitelist rules
cat >> /etc/usbguard/rules.conf << 'EOF'
# Yubico devices (YubiKey)
allow with-interface one-of { 03:01:01 03:00:00 0b:*:* } if { id-vendor == "1050" }
EOF
 
# USBGuard daemon configuration
cat > /etc/usbguard/usbguard-daemon.conf << 'EOF'
RuleFile=/etc/usbguard/rules.conf
ImplicitPolicyTarget=block
PresentDevicePolicy=apply-policy
PresentControllerPolicy=keep
InsertedDevicePolicy=apply-policy
RestoreControllerDeviceState=false
IPCAllowedUsers=root
IPCAllowedGroups=root usbguard
IPCAccessControlFiles=/etc/usbguard/IPCAccessControl.d/
AuditBackend=LinuxAudit
AuditFilePath=/var/log/usbguard/usbguard-audit.log
DeviceManagerBackend=uevent
EOF
 
# IPC access control
mkdir -p /etc/usbguard/IPCAccessControl.d
cat > /etc/usbguard/IPCAccessControl.d/root.conf << 'EOF'
user=root
EOF
 
cat > /etc/usbguard/IPCAccessControl.d/primary-user.conf << EOF
user=user
Devices=modify,list,listen
Policy=list
EOF
 
# Hardened rules file
cp /etc/usbguard/rules.conf /root/rules-autogenerated.conf
 
cat > /etc/usbguard/rules.conf << 'EOF'
# USB root hubs (internal controllers)
allow with-interface equals { 09:00:00 }
 
# HID devices (keyboard, mouse, touchpad)
allow with-interface one-of { 03:00:01 03:01:01 03:01:02 }
 
# U2F / SECURITY KEYS
allow id 1050:* name match /YubiKey/ with-interface one-of { 03:*:* 0b:*:* ff:*:* }
 
# MASS STORAGE: BLOCKED
reject with-interface equals { 08:*:* }
 
# NETWORK ADAPTERS: BLOCKED
reject with-interface equals { 02:*:* }
reject with-interface equals { 0a:*:* }
reject with-interface equals { e0:*:* }
 
# PRINTERS: BLOCKED
reject with-interface equals { 07:*:* }
 
EOF
 
# Append current device hashes
cat >> /etc/usbguard/rules.conf << 'EOF'
 
# DEVICE-SPECIFIC RULES: Generated from currently connected devices
EOF
 
usbguard generate-policy 2>/dev/null | while read -r line; do
    if echo "$line" | grep -q "09:00:00"; then
        continue
    fi
    echo "# Auto-detected device"
    echo "$line"
done >> /etc/usbguard/rules.conf
mkdir -p /var/log/usbguard
chmod 750 /var/log/usbguard
chown root:adm /var/log/usbguard
 
cat > /etc/logrotate.d/usbguard << 'EOF'
/var/log/usbguard/*.log {
    weekly
    rotate 12
    compress
    delaycompress
    missingok
    notifempty
    create 640 root adm
}
EOF
 
chmod 700 /etc/usbguard
chmod 600 /etc/usbguard/usbguard-daemon.conf
chmod 600 /etc/usbguard/rules.conf
chown -R root:root /etc/usbguard
if ! getent group usbguard &>/dev/null; then
    groupadd -r usbguard
fi
usermod -aG usbguard user
systemctl daemon-reload
systemctl enable usbguard
systemctl restart usbguard
 
# APPARMOR
APPARMOR_DIR="/etc/apparmor.d"
 
echo "[*] Ensuring AppArmor packages are installed"
apt-get update
apt-get install -y apparmor apparmor-utils apparmor-profiles apparmor-profiles-extra auditd
 
echo "[*] Creating Librewolf/Firefox AppArmor profile"
 
cat > "${APPARMOR_DIR}/usr.bin.librewolf" << 'EOF'
abi <abi/3.0>,
 
include <tunables/global>
 
@{librewolf_exec} = /usr/bin/librewolf /usr/lib/librewolf/librewolf /opt/librewolf/librewolf
@{firefox_exec} = /usr/bin/firefox /usr/lib/firefox/firefox /usr/lib/firefox-esr/firefox-esr
 
profile librewolf @{librewolf_exec} flags=(attach_disconnected) {
    include <abstractions/base>
    include <abstractions/audio>
    include <abstractions/dbus-session-strict>
    include <abstractions/dbus-accessibility-strict>
    include <abstractions/fonts>
    include <abstractions/freedesktop.org>
    include <abstractions/gnome>
    include <abstractions/mesa>
    include <abstractions/nameservice>
    include <abstractions/opencl-intel>
    include <abstractions/ssl_certs>
    include <abstractions/vulkan>
    include <abstractions/wayland>
 
    capability sys_admin,
    capability sys_chroot,
    capability sys_ptrace,
 
    network inet stream,
    network inet dgram,
    network inet6 stream,
    network inet6 dgram,
    network netlink raw,
 
    deny capability dac_override,
    deny capability dac_read_search,
    deny capability net_admin,
    deny capability sys_module,
    deny capability sys_rawio,
 
    @{librewolf_exec} mrix,
    /usr/lib/librewolf/** mrix,
    /opt/librewolf/** mrix,
 
    owner @{HOME}/.librewolf/ rw,
    owner @{HOME}/.librewolf/** rwk,
    owner @{HOME}/.mozilla/ rw,
    owner @{HOME}/.mozilla/** rwk,
 
    owner @{HOME}/.cache/librewolf/ rw,
    owner @{HOME}/.cache/librewolf/** rwk,
    owner @{HOME}/.cache/mozilla/ rw,
    owner @{HOME}/.cache/mozilla/** rwk,
 
    owner @{HOME}/Downloads/ rw,
    owner @{HOME}/Downloads/** rw,
 
    deny @{HOME}/.gnupg/** rw,
    deny @{HOME}/.ssh/** rw,
    deny @{HOME}/.pki/** rw,
    deny @{HOME}/.cert/** rw,
    deny @{HOME}/.password-store/** rw,
    deny @{HOME}/.local/share/keyrings/** rw,
    deny @{HOME}/.config/gnome-keyring/** rw,
    deny /etc/shadow r,
    deny /etc/gshadow r,
    deny /etc/security/** rw,
    deny /etc/sudoers r,
    deny /etc/sudoers.d/** r,
    deny /etc/pam.d/** rw,
    deny /etc/wireguard/** rw,
 
    /usr/share/** r,
    /usr/lib/** rm,
    /lib/** rm,
    /etc/fonts/** r,
    /etc/ssl/** r,
    /etc/ca-certificates/** r,
    /etc/mime.types r,
    /etc/mailcap r,
    /etc/machine-id r,
    /etc/localtime r,
    /etc/passwd r,
    /etc/group r,
    /etc/nsswitch.conf r,
    /etc/resolv.conf r,
    /etc/host.conf r,
    /etc/hosts r,
 
    @{PROC}/@{pid}/** r,
    @{PROC}/sys/kernel/random/uuid r,
    @{PROC}/sys/kernel/osrelease r,
    @{PROC}/sys/fs/inotify/max_user_watches r,
    owner @{PROC}/@{pid}/fd/ r,
    owner @{PROC}/@{pid}/task/ r,
    owner @{PROC}/@{pid}/mountinfo r,
    owner @{PROC}/@{pid}/cgroup r,
    owner @{PROC}/@{pid}/oom_score_adj rw,
 
    /sys/bus/ r,
    /sys/class/ r,
    /sys/devices/** r,
    /sys/fs/cgroup/** r,
    deny /sys/kernel/security/** rw,
 
    /dev/ r,
    /dev/null rw,
    /dev/zero r,
    /dev/random r,
    /dev/urandom r,
    /dev/shm/ r,
    owner /dev/shm/org.chromium.* rw,
    owner /dev/shm/org.mozilla.* rw,
    /dev/dri/** rw,
    /dev/video* rw,
 
    owner /run/user/@{uid}/pipewire-* rw,
    owner /run/user/@{uid}/pulse/ rw,
    owner /run/user/@{uid}/pulse/** rw,
 
    owner /run/user/@{uid}/wayland-* rw,
 
    owner /run/user/@{uid}/bus rw,
    owner /run/user/@{uid}/dconf/ rw,
    owner /run/user/@{uid}/dconf/** rw,
 
    owner /run/user/@{uid}/doc/ r,
    owner /run/user/@{uid}/doc/** rw,
    owner /run/user/@{uid}/.flatpak-helper/** rw,
 
    owner /tmp/librewolf*/ rw,
    owner /tmp/librewolf*/** rwk,
    owner /tmp/mozilla*/ rw,
    owner /tmp/mozilla*/** rwk,
    owner /tmp/Temp-*/ rw,
    owner /tmp/Temp-*/** rwk,
    owner /var/tmp/** rwk,
 
    deny /root/** rw,
 
    deny network raw,
    deny network packet,
 
    profile librewolf-content flags=(attach_disconnected) {
        include <abstractions/base>
        include <abstractions/fonts>
        include <abstractions/mesa>
        include <abstractions/wayland>
 
        /usr/lib/librewolf/** rm,
        /opt/librewolf/** rm,
        /usr/share/** r,
 
        owner @{HOME}/.librewolf/** rw,
        owner @{HOME}/.cache/librewolf/** rw,
 
        deny network,
        deny @{HOME}/.ssh/** rw,
        deny @{HOME}/.gnupg/** rw,
    }
}
EOF
 
echo "[*] Creating Blackbox Terminal profile"
 
cat > "${APPARMOR_DIR}/usr.bin.blackbox-terminal" << 'EOF'
abi <abi/3.0>,
 
include <tunables/global>
 
profile blackbox-terminal /usr/bin/blackbox-terminal flags=(attach_disconnected) {
    include <abstractions/base>
    include <abstractions/bash>
    include <abstractions/dbus-session-strict>
    include <abstractions/fonts>
    include <abstractions/freedesktop.org>
    include <abstractions/nameservice>
    include <abstractions/wayland>
 
    network inet stream,
    network inet dgram,
    network unix stream,
 
    # Blackbox binary
    /usr/bin/blackbox-terminal mr,
 
    # Shells (unconfined transition - shell commands need full access)
    /bin/bash Ux,
    /bin/sh Ux,
    /bin/dash Ux,
    /usr/bin/bash Ux,
    /usr/bin/zsh Ux,
 
    # User home (for shell)
    owner @{HOME}/ r,
    owner @{HOME}/** rwkl,
 
    # Blackbox config (GTK4 / libadwaita / dconf)
    owner @{HOME}/.config/blackbox/ rw,
    owner @{HOME}/.config/blackbox/** rw,
    owner @{HOME}/.local/share/blackbox/ rw,
    owner @{HOME}/.local/share/blackbox/** rw,
 
    # Shell configs
    owner @{HOME}/.bashrc r,
    owner @{HOME}/.bash_profile r,
    owner @{HOME}/.profile r,
    owner @{HOME}/.bash_history rw,
    owner @{HOME}/.bash_logout r,
 
    # System
    /etc/** r,
    /usr/share/** r,
    /usr/lib/** rm,
    /usr/bin/** mrix,
    /bin/** mrix,
 
    # Proc
    @{PROC}/** r,
 
    # Wayland / D-Bus / dconf
    owner /run/user/@{uid}/wayland-* rw,
    owner /run/user/@{uid}/bus rw,
    owner /run/user/@{uid}/dconf/ rw,
    owner /run/user/@{uid}/dconf/** rw,
 
    # PTY
    /dev/ptmx rw,
    /dev/pts/* rw,
}
EOF
 
echo "[*] Creating OpenSnitch UI profile"
 
cat > "${APPARMOR_DIR}/usr.bin.opensnitch-ui" << 'EOF'
abi <abi/3.0>,
 
include <tunables/global>
 
profile opensnitch-ui /usr/bin/opensnitch-ui flags=(attach_disconnected) {
    include <abstractions/base>
    include <abstractions/dbus-session-strict>
    include <abstractions/fonts>
    include <abstractions/gnome>
    include <abstractions/nameservice>
    include <abstractions/python>
    include <abstractions/wayland>
 
    network unix stream,
    network inet stream,
    network inet dgram,
    deny network inet6,
 
    /usr/bin/opensnitch-ui mr,
    /usr/bin/python3* ix,
    /usr/lib/python3/** mr,
 
    owner @{HOME}/.config/opensnitch/ rw,
    owner @{HOME}/.config/opensnitch/** rw,
    /etc/opensnitchd/** r,
 
    /usr/share/** r,
    /etc/fonts/** r,
 
    @{PROC}/ r,
    @{PROC}/@{pid}/** r,
    @{PROC}/sys/kernel/** r,
 
    owner /run/user/@{uid}/wayland-* rw,
    owner /run/user/@{uid}/bus rw,
 
    deny @{HOME}/.ssh/** rw,
    deny @{HOME}/.gnupg/** rw,
    deny /etc/shadow r,
}
EOF
 
echo "[*] Creating OpenSnitch daemon profile"
 
cat > "${APPARMOR_DIR}/usr.bin.opensnitchd" << 'EOF'
abi <abi/3.0>,
 
include <tunables/global>
 
profile opensnitchd /usr/bin/opensnitchd flags=(attach_disconnected) {
    include <abstractions/base>
    include <abstractions/nameservice>
 
    capability net_admin,
    capability net_raw,
    capability sys_ptrace,
    capability bpf,
    capability perfmon,
    capability sys_resource,
 
    deny capability sys_module,
    deny capability sys_rawio,
 
    network inet stream,
    network inet dgram,
    network inet raw,
    network inet6 stream,
    network inet6 dgram,
    network netlink raw,
    network unix stream,
    network unix dgram,
 
    /usr/bin/opensnitchd mr,
 
    /etc/opensnitchd/ r,
    /etc/opensnitchd/** rw,
 
    /etc/opensnitchd/rules/ rw,
    /etc/opensnitchd/rules/** rw,
 
    /var/log/opensnitchd.log rw,
 
    # eBPF maps and programs
    /sys/fs/bpf/ r,
    /sys/fs/bpf/** rw,
    /sys/kernel/btf/vmlinux r,
 
    # eBPF module paths
    /usr/lib/opensnitchd/** mr,
    /usr/share/opensnitchd/** r,
 
    @{PROC}/ r,
    @{PROC}/** r,
    @{PROC}/@{pid}/** r,
    @{PROC}/sys/kernel/** r,
    @{PROC}/sys/net/** r,
 
    /etc/hosts r,
    /etc/resolv.conf r,
    /etc/passwd r,
    /etc/group r,
    /etc/machine-id r,
 
    /run/opensnitchd/ rw,
    /run/opensnitchd/** rw,
    owner /tmp/osui.sock rw,
 
    /usr/lib/** rm,
    /lib/** rm,
 
    deny /etc/shadow r,
    deny /etc/gshadow r,
    deny @{HOME}/.ssh/** rw,
    deny @{HOME}/.gnupg/** rw,
}
EOF
 
echo "[*] Loading and enforcing AppArmor profiles"
 
apparmor_parser -r "${APPARMOR_DIR}/usr.bin.librewolf" 2>/dev/null || true
apparmor_parser -r "${APPARMOR_DIR}/usr.bin.blackbox-terminal" 2>/dev/null || true
apparmor_parser -r "${APPARMOR_DIR}/usr.bin.opensnitch-ui" 2>/dev/null || true
apparmor_parser -r "${APPARMOR_DIR}/usr.bin.opensnitchd" 2>/dev/null || true
 
echo "[*] Enforcing system profiles from apparmor-profiles package"
 
PROFILES_TO_ENFORCE=(
    "usr.bin.librewolf"
    "usr.bin.blackbox-terminal"
    "usr.bin.opensnitch-ui"
    "usr.bin.opensnitchd"
)
 
for profile in "${PROFILES_TO_ENFORCE[@]}"; do
    if [[ -f "${APPARMOR_DIR}/${profile}" ]]; then
        aa-enforce "${APPARMOR_DIR}/${profile}" 2>/dev/null || true
    fi
done
 
echo "[*] Setting all profiles to enforce mode"
aa-enforce /etc/apparmor.d/* 2>/dev/null || true
 
echo "[*] Enabling AppArmor service"
systemctl enable apparmor
systemctl restart apparmor
 
# AppArmor helper scripts
cat > /usr/local/bin/aa-denials << 'EOF'
#!/bin/bash
echo "=== Recent AppArmor Denials ==="
dmesg | grep -i "apparmor.*denied" | tail -50
echo ""
echo "=== From audit log ==="
ausearch -m AVC -ts recent 2>/dev/null | grep apparmor | tail -30
EOF
chmod 700 /usr/local/bin/aa-denials
 
cat > /usr/local/bin/aa-genprof-helper << 'EOF'
#!/bin/bash
if [[ -z "$1" ]]; then
    echo "Usage: aa-genprof-helper /path/to/binary"
    exit 1
fi
echo "Starting profile generation for: $1"
echo "Run the application and exercise all features, then press 'S' to scan logs"
aa-genprof "$1"
EOF
chmod 700 /usr/local/bin/aa-genprof-helper
 
cat > /usr/local/bin/aa-temp-disable << 'EOF'
#!/bin/bash
if [[ -z "$1" ]]; then
    echo "Usage: aa-temp-disable <profile-name>"
    echo "Available profiles:"
    aa-status --enabled 2>/dev/null | grep -v "^[0-9]"
    exit 1
fi
aa-complain "$1"
echo "Profile $1 set to complain mode (logging only, not blocking)"
echo "To re-enforce: aa-enforce $1"
EOF
chmod 700 /usr/local/bin/aa-temp-disable
 
# INTEGRITY MODULE
INTEGRITY_DIR="/var/lib/integrity"
CONFIG_FILE="/etc/integrity-monitor.conf"
 
echo "[*] Setting up integrity monitoring infrastructure"
 
mkdir -p "$INTEGRITY_DIR"
chmod 700 "$INTEGRITY_DIR"
chown root:root "$INTEGRITY_DIR"
 
mkdir -p /var/log/integrity
chmod 700 /var/log/integrity
chown root:root /var/log/integrity
 
# Integrity monitor configuration
cat > "$CONFIG_FILE" << 'EOF'
HASH_ALGO="sha256"
 
CRITICAL_FILES=(
    "/etc/passwd"
    "/etc/shadow"
    "/etc/group"
    "/etc/gshadow"
    "/etc/sudoers"
    "/etc/pam.d/common-auth"
    "/etc/pam.d/common-password"
    "/etc/pam.d/common-session"
    "/etc/pam.d/common-account"
    "/etc/pam.d/sudo"
    "/etc/pam.d/su"
    "/etc/pam.d/login"
    "/etc/pam.d/sshd"
    "/etc/security/access.conf"
    "/etc/security/limits.conf"
    "/etc/security/namespace.conf"
    "/etc/login.defs"
    "/etc/securetty"
    "/etc/hosts"
    "/etc/hosts.allow"
    "/etc/hosts.deny"
    "/etc/resolv.conf"
    "/etc/nsswitch.conf"
    "/etc/iptables/rules.v4"
    "/etc/iptables/rules.v6"
    "/etc/sysctl.conf"
    "/etc/default/grub"
    "/boot/grub/grub.cfg"
    "/etc/ld.so.preload"
    "/etc/ld.so.conf"
    "/etc/profile"
    "/etc/bash.bashrc"
    "/etc/environment"
    "/etc/apparmor/parser.conf"
    "/etc/usbguard/rules.conf"
    "/etc/usbguard/usbguard-daemon.conf"
    "/etc/audit/auditd.conf"
    "/etc/opensnitchd/default-config.json"
)
 
CRITICAL_DIRS=(
    "/etc/sudoers.d"
    "/etc/pam.d"
    "/etc/security"
    "/etc/apparmor.d"
    "/etc/audit/rules.d"
    "/etc/systemd/system"
    "/etc/modprobe.d"
    "/etc/sysctl.d"
    "/etc/usbguard/IPCAccessControl.d"
    "/etc/profile.d"
)
 
CRITICAL_BINARIES=(
    "/usr/bin/bash"
    "/usr/bin/sh"
    "/usr/bin/dash"
    "/usr/bin/sudo"
    "/usr/bin/login"
    "/usr/sbin/unix_chkpwd"
    "/usr/lib/systemd/systemd"
    "/usr/sbin/auditd"
    "/usr/sbin/auditctl"
    "/usr/bin/opensnitchd"
    "/usr/sbin/iptables"
    "/usr/sbin/ip6tables"
    "/usr/sbin/iptables-restore"
    "/usr/sbin/insmod"
    "/usr/sbin/rmmod"
    "/usr/sbin/modprobe"
)
 
TRACK_SUID_SGID=true
TRACK_KERNEL_MODULES=true
 
EXCLUSIONS=(
    "/etc/mtab"
    "/etc/resolv.conf.bak"
    "/etc/.pwd.lock"
    "/var/lib/integrity"
)
EOF
 
chmod 600 "$CONFIG_FILE"
 
# Main integrity monitoring script
cat > /usr/local/bin/integrity-monitor << 'SCRIPT_EOF'
#!/bin/bash
set -euo pipefail
 
CONFIG_FILE="/etc/integrity-monitor.conf"
INTEGRITY_DIR="/var/lib/integrity"
BASELINE_FILE="${INTEGRITY_DIR}/baseline.db"
LOG_FILE="/var/log/integrity/integrity.log"
ALERT_FILE="/var/log/integrity/alerts.log"
 
source "$CONFIG_FILE"
 
log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" | tee -a "$LOG_FILE"
}
 
alert() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] ALERT: $1" | tee -a "$ALERT_FILE" "$LOG_FILE"
    logger -t integrity-monitor -p auth.alert "$1"
}
 
hash_file() {
    local file="$1"
    if [[ -f "$file" ]]; then
        ${HASH_ALGO}sum "$file" 2>/dev/null | awk '{print $1}'
    else
        echo "MISSING"
    fi
}
 
get_perms() {
    local file="$1"
    if [[ -e "$file" ]]; then
        stat -c '%a:%U:%G' "$file" 2>/dev/null
    else
        echo "MISSING"
    fi
}
 
get_attrs() {
    local file="$1"
    if [[ -f "$file" ]]; then
        lsattr "$file" 2>/dev/null | awk '{print $1}' || echo "none"
    else
        echo "MISSING"
    fi
}
 
is_excluded() {
    local file="$1"
    for excl in "${EXCLUSIONS[@]}"; do
        if [[ "$file" == "$excl" ]]; then
            return 0
        fi
    done
    return 1
}
 
create_baseline() {
    log "Creating integrity baseline..."
    local temp_baseline="${BASELINE_FILE}.tmp"
    chattr -i "$BASELINE_FILE" 2>/dev/null || true
    echo "# Integrity Baseline - Generated $(date)" > "$temp_baseline"
    echo "# Format: TYPE|PATH|HASH|PERMS|ATTRS" >> "$temp_baseline"
 
    log "Processing critical files..."
    for file in "${CRITICAL_FILES[@]}"; do
        is_excluded "$file" && continue
        if [[ -f "$file" ]]; then
            echo "FILE|${file}|$(hash_file "$file")|$(get_perms "$file")|$(get_attrs "$file")" >> "$temp_baseline"
        fi
    done
 
    log "Processing critical directories..."
    for dir in "${CRITICAL_DIRS[@]}"; do
        if [[ -d "$dir" ]]; then
            find "$dir" -type f 2>/dev/null | while read -r file; do
                is_excluded "$file" && continue
                echo "FILE|${file}|$(hash_file "$file")|$(get_perms "$file")|$(get_attrs "$file")" >> "$temp_baseline"
            done
        fi
    done
 
    log "Processing critical binaries..."
    for file in "${CRITICAL_BINARIES[@]}"; do
        is_excluded "$file" && continue
        if [[ -f "$file" ]]; then
            echo "BINARY|${file}|$(hash_file "$file")|$(get_perms "$file")|$(get_attrs "$file")" >> "$temp_baseline"
        fi
    done
 
    if [[ "$TRACK_SUID_SGID" == "true" ]]; then
        log "Processing SUID/SGID binaries..."
        find / -xdev \( -perm -4000 -o -perm -2000 \) -type f 2>/dev/null | while read -r file; do
            is_excluded "$file" && continue
            echo "SUID|${file}|$(hash_file "$file")|$(get_perms "$file")|none" >> "$temp_baseline"
        done
    fi
 
    if [[ "$TRACK_KERNEL_MODULES" == "true" ]]; then
        log "Processing kernel modules..."
        find /lib/modules/$(uname -r) -name "*.ko*" -type f 2>/dev/null | while read -r file; do
            echo "MODULE|${file}|$(hash_file "$file")|644:root:root|none" >> "$temp_baseline"
        done
    fi
 
    sort -t'|' -k2 "$temp_baseline" -o "$temp_baseline"
    mv "$temp_baseline" "$BASELINE_FILE"
    chmod 600 "$BASELINE_FILE"
    chattr +i "$BASELINE_FILE"
    log "Baseline created with $(grep -c '^[A-Z]' "$BASELINE_FILE") entries"
}
 
verify_integrity() {
    if [[ ! -f "$BASELINE_FILE" ]]; then
        log "No baseline found, creating initial baseline..."
        create_baseline
        return 0
    fi
 
    log "Verifying integrity against baseline..."
    local violations=0
    local missing_files=0
 
    while IFS='|' read -r type path expected_hash expected_perms expected_attrs; do
        [[ "$type" =~ ^# ]] && continue
        [[ -z "$type" ]] && continue
 
        if [[ ! -e "$path" ]]; then
            alert "MISSING: $path (was $type)"
            ((missing_files++))
            continue
        fi
 
        current_hash=$(hash_file "$path")
        current_perms=$(get_perms "$path")
 
        if [[ "$current_hash" != "$expected_hash" ]]; then
            alert "MODIFIED: $path - hash changed"
            ((violations++))
        fi
 
        if [[ "$current_perms" != "$expected_perms" ]]; then
            alert "PERMISSIONS: $path - was $expected_perms, now $current_perms"
            ((violations++))
        fi
 
    done < "$BASELINE_FILE"
 
    if [[ "$TRACK_SUID_SGID" == "true" ]]; then
        find / -xdev \( -perm -4000 -o -perm -2000 \) -type f 2>/dev/null | while read -r file; do
            if ! grep -q "|${file}|" "$BASELINE_FILE" 2>/dev/null; then
                alert "NEW SUID/SGID: $file"
            fi
        done
    fi
 
    log "Verification complete: $violations violations, $missing_files missing"
 
    if [[ $violations -gt 0 || $missing_files -gt 0 ]]; then
        return 1
    fi
    return 0
}
 
generate_report() {
    echo "=============================================="
    echo "INTEGRITY VERIFICATION REPORT"
    echo "Generated: $(date)"
    echo "=============================================="
    echo ""
    if [[ -f "$BASELINE_FILE" ]]; then
        echo "Baseline date: $(stat -c '%y' "$BASELINE_FILE")"
        echo "Total entries: $(grep -c '^[A-Z]' "$BASELINE_FILE")"
    else
        echo "No baseline found!"
    fi
    echo ""
    echo "=== Recent Alerts ==="
    if [[ -f "$ALERT_FILE" ]]; then
        tail -20 "$ALERT_FILE"
    else
        echo "No alerts"
    fi
}
 
case "${1:-verify}" in
    baseline|init|create) create_baseline ;;
    verify|check) verify_integrity ;;
    report|status) generate_report ;;
    *)
        echo "Usage: integrity-monitor {baseline|verify|report}"
        exit 1
        ;;
esac
SCRIPT_EOF
 
chmod 700 /usr/local/bin/integrity-monitor
 
# Quick integrity check script
cat > /usr/local/bin/integrity-quick << 'EOF'
#!/bin/bash
echo "=== Quick Integrity Check ==="
echo ""
 
CRITICAL=(
    "/etc/passwd"
    "/etc/shadow"
    "/etc/sudoers"
    "/etc/pam.d/common-auth"
    "/etc/pam.d/sudo"
    "/usr/bin/sudo"
    "/bin/bash"
    "/etc/ld.so.preload"
)
 
BASELINE="/var/lib/integrity/baseline.db"
 
if [[ ! -f "$BASELINE" ]]; then
    echo "[!] No baseline found - run: integrity-monitor baseline"
    exit 1
fi
 
violations=0
 
for file in "${CRITICAL[@]}"; do
    if [[ ! -f "$file" ]]; then
        if [[ "$file" == "/etc/ld.so.preload" ]]; then
            echo "[+] $file - not present (OK)"
        else
            echo "[!] $file - MISSING"
            ((violations++))
        fi
        continue
    fi
 
    current=$(sha256sum "$file" 2>/dev/null | awk '{print $1}')
    expected=$(grep "|${file}|" "$BASELINE" 2>/dev/null | cut -d'|' -f3)
 
    if [[ -z "$expected" ]]; then
        echo "[?] $file - not in baseline"
    elif [[ "$current" == "$expected" ]]; then
        echo "[+] $file - OK"
    else
        echo "[!] $file - MODIFIED"
        ((violations++))
    fi
done
 
echo ""
if [[ $violations -eq 0 ]]; then
    echo "All critical files verified OK"
else
    echo "WARNING: $violations violations detected!"
    exit 1
fi
EOF
 
chmod 755 /usr/local/bin/integrity-quick
 
# Integrity timers
cat > /etc/systemd/system/integrity-monitor.service << 'EOF'
[Unit]
Description=Integrity Monitor Verification
After=local-fs.target
 
[Service]
Type=oneshot
ExecStart=/usr/local/bin/integrity-monitor verify
StandardOutput=journal
EOF
 
cat > /etc/systemd/system/integrity-monitor.timer << 'EOF'
[Unit]
Description=Hourly integrity verification
 
[Timer]
OnCalendar=hourly
RandomizedDelaySec=300
Persistent=true
 
[Install]
WantedBy=timers.target
EOF
 
systemctl daemon-reload
systemctl enable integrity-monitor.timer
systemctl start integrity-monitor.timer
 
# Boot-time integrity check
cat > /etc/systemd/system/integrity-boot.service << 'EOF'
[Unit]
Description=Boot-time Integrity Verification
After=local-fs.target
Before=display-manager.service
 
[Service]
Type=oneshot
ExecStart=/usr/local/bin/integrity-quick
RemainAfterExit=yes
 
[Install]
WantedBy=multi-user.target
EOF
 
systemctl daemon-reload
systemctl enable integrity-boot.service
 
# Escalation hook
cat > /usr/local/bin/integrity-escalation-hook << 'EOF'
#!/bin/bash
LOG="/var/log/integrity/escalation-triggered.log"
echo "[$(date)] Escalation event triggered integrity check" >> "$LOG"
/usr/local/bin/integrity-quick >> "$LOG" 2>&1
if [[ $? -ne 0 ]]; then
    echo "[$(date)] Quick check failed, running full verification" >> "$LOG"
    /usr/local/bin/integrity-monitor verify >> "$LOG" 2>&1
fi
EOF
 
chmod 700 /usr/local/bin/integrity-escalation-hook
 
# Create initial baseline
echo "[*] Creating initial integrity baseline"
/usr/local/bin/integrity-monitor baseline
 
echo ""
echo "[+] Integrity verification module complete"
echo ""
 
# PRIVILEGE ESCALATION HARDENING
log_info "Securing privilege escalation vectors..."
echo "tty1" > /etc/securetty 2>/dev/null || true
chown root:root /etc/securetty 2>/dev/null || true
chmod 0400 /etc/securetty 2>/dev/null || true
rm -r /etc/skel* 2>/dev/null || true
rm -r /etc/dhcp* 2>/dev/null || true
rm -r /etc/ssh* 2>/dev/null || true
rm -r /etc/ppp* 2>/dev/null || true
rm -r /etc/cron* 2>/dev/null || true
rm -r /etc/emacs* 2>/dev/null || true
rm -r /etc/xemacs* 2>/dev/null || true
rm -r /etc/gai* 2>/dev/null || true
rm -r /etc/vim* 2>/dev/null || true
rm -r /etc/wpa* 2>/dev/null || true
rm -r /etc/manpath* 2>/dev/null || true
rm -r /etc/libnl* 2>/dev/null || true
rm -r /etc/binfmt.d/ 2>/dev/null || true
rm -r /etc/cron.d* 2>/dev/null || true
rm -r /etc/dhcp/ 2>/dev/null || true
rm -r /etc/e2scrub.conf 2>/dev/null || true
rm -r /etc/gai.conf 2>/dev/null || true
rm -r /etc/gss 2>/dev/null || true
rm -r /etc/libnl-3/ 2>/dev/null || true
rm -r /etc/skel/ 2>/dev/null || true
rm -r /usr/bin/run0 2>/dev/null || true
rm -r /usr/bin/passwd* 2>/dev/null || true
rm -r /usr/bin/gpasswd* 2>/dev/null || true
rm -r /usr/bin/sudoreplay 2>/dev/null || true
rm -r /usr/bin/sudoedit 2>/dev/null || true
rm -r /usr/lib/emacs* 2>/dev/null || true
rm -r /usr/lib/gvfs* 2>/dev/null || true
rm -r /usr/lib/os-probe* 2>/dev/null || true
rm -r /usr/lib/man-db* 2>/dev/null || true
rm -r /usr/lib/ppp* 2>/dev/null || true
rm -r /usr/lib/systemd/ssh* 2>/dev/null || true
rm -r /usr/lib/systemd/systemd-ssh* 2>/dev/null || true
rm -r /usr/lib/systemd/systemd-socket* 2>/dev/null || true
rm -r /usr/lib/systemd/systemd-sulogin* 2>/dev/null || true
rm -r /usr/lib/systemd/systemd-rc* 2>/dev/null || true
rm -r /usr/lib/systemd/network/73* 2>/dev/null || true
rm -r /usr/lib/systemd/network/80-container* 2>/dev/null || true
rm -r /usr/lib/systemd/network/80-wifi* 2>/dev/null || true
rm -r /usr/lib/systemd/system-generators/systemd-ssh* 2>/dev/null || true
rm -r /usr/lib/systemd/systemd-ssh* 2>/dev/null || true
rm -r /usr/lib/systemd/ssh_config.d/ 2>/dev/null || true
rm -r /usr/lib/systemd/systemd-makefs 2>/dev/null || true
rm -r /usr/lib/systemd/system-generators/systemd-ssh-generator 2>/dev/null || true
rm -r /usr/lib/systemd/system-generators/systemd-factory-reset-generator 2>/dev/null || true
rm -r /usr/lib/systemd/system-generators/systemd-rc-local-generator 2>/dev/null || true
rm -r /usr/lib/systemd/system-generators/systemd-debug-generator 2>/dev/null || true
rm -r /usr/libexec/e2fsprogs/ 2>/dev/null || true
rm -r /usr/libexec/sudo/sudo_intercept.so 2>/dev/null || true
cd /usr/bin/
rm -rf z* xz* screendump slabtop mapscrn ischroot script* sensible-* sudoedit sudoreplay su bashbug bzip2* select-editor pipesz pinky stty grotty 2>/dev/null || true
cd /usr/sbin
rm -rf chroot debugfs e2* iw visudo sulogin swap* 2>/dev/null || true
cd /home/user
 
# BLOCK DEVICE NODES
log_info "Blocking device nodes..."
cat > /etc/udev/rules.d/99-deny-devices.rules << 'EOF'
KERNEL=="vhost-net",  OPTIONS+="static_node=vhost-net",  ACTION=="add", RUN+="/bin/rm -f /dev/vhost-net"
KERNEL=="vhost-vsock", OPTIONS+="static_node=vhost-vsock", ACTION=="add", RUN+="/bin/rm -f /dev/vhost-vsock"
KERNEL=="vfio*",      ACTION=="add", RUN+="/bin/rm -f /dev/%k"
KERNEL=="ng0n1",      ACTION=="add", RUN+="/bin/rm -f /dev/ng0n1"
KERNEL=="ppp",        ACTION=="add", RUN+="/bin/rm -f /dev/ppp"
KERNEL=="fuse",       ACTION=="add", RUN+="/bin/rm -f /dev/fuse"
KERNEL=="snapshot",   ACTION=="add", RUN+="/bin/rm -f /dev/snapshot"
KERNEL=="watchdog*",  ACTION=="add", RUN+="/bin/rm -f /dev/%k"
KERNEL=="tty[89]",          ACTION=="add", RUN+="/bin/rm -f /dev/%k"
KERNEL=="tty[1-6][0-9]",   ACTION=="add", RUN+="/bin/rm -f /dev/%k"
EOF
 
chown root:root /etc/udev/rules.d/99-deny-devices.rules 2>/dev/null || true
chmod 0644 /etc/udev/rules.d/99-deny-devices.rules 2>/dev/null || true
chattr +i /etc/udev/rules.d/99-deny-devices.rules 2>/dev/null || true
udevadm control --reload-rules 2>/dev/null || true 2>/dev/null || true
 
# BLOCK POLKIT
mkdir -p /etc/polkit-1/rules.d
cat > /etc/polkit-1/rules.d/00-deny-all.rules << 'EOF'
// Deny all polkit requests - hardened system
polkit.addRule(function(action, subject) {
    return polkit.Result.NO;
});
EOF
 
chown root:root /etc/polkit-1/rules.d/00-deny-all.rules 2>/dev/null || true
chmod 0644 /etc/polkit-1/rules.d/00-deny-all.rules 2>/dev/null || true
chattr -R +i /etc/polkit-1/rules.d/ 2>/dev/null || true
 
# SUDO
log_info "Configuring sudo..."
cat >/etc/sudoers <<'EOF'
Defaults        env_reset
Defaults        !setenv
Defaults        !rootpw
Defaults        !runaspw
Defaults        !targetpw
Defaults        timestamp_timeout=1
Defaults        passwd_timeout=1
Defaults        passwd_tries=1 
Defaults        use_pty
Defaults        always_set_home
Defaults        env_delete += "CDPATH"
Defaults        env_delete += "ENV"
Defaults        env_delete += "BASH_ENV"
Defaults        env_delete += "KRB5_CONFIG"
Defaults        env_delete += "KRB5_KTNAME"
Defaults        env_delete += "LD_*"
Defaults        env_delete += "_RLD_*"
Defaults        env_delete += "SHLIB_PATH"
Defaults        env_delete += "LIBPATH"
Defaults        env_delete += "DYLD_*"
Defaults        env_delete += "PERL5LIB"
Defaults        env_delete += "PERL5OPT"
Defaults        env_delete += "PERL5DB"
Defaults        env_delete += "PERLLIB"
Defaults        env_delete += "PERL_DEBUG"
Defaults        env_delete += "PYTHONPATH"
Defaults        env_delete += "PYTHONHOME"
Defaults        env_delete += "PYTHONINSPECT"
Defaults        env_delete += "RUBYLIB"
Defaults        env_delete += "RUBYOPT"
Defaults        env_keep += "LANG"
Defaults        env_keep += "LANGUAGE"
Defaults        env_keep += "LC_*"
Defaults        env_keep += "TERM"
Defaults        env_keep += "TZ"
Defaults        env_keep += "USER"
Defaults        env_keep += "LOGNAME"
Defaults        secure_path="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin"
Defaults        logfile="/var/log/sudo.log"
Defaults        log_input
Defaults        log_output
Defaults        iolog_dir="/var/log/sudo-io"
Defaults        iolog_file="%{user}/%{runas_user}/%{command}_%Y%m%d_%H%M%S"
Defaults        log_host
Defaults        !env_editor
Defaults        umask=0077 
Defaults        editor=/bin/false
Defaults        !env_editor
 
Cmnd_Alias FIREWALL=/usr/sbin/iptables -L
Cmnd_Alias MOUNTS=/usr/bin/umount *
Cmnd_Alias MAINT=/usr/bin/systemctl status *, /usr/bin/journalctl -xe, /usr/local/bin/escalation-monitor
 
user ALL=(ALL) ALL
#user ALL=(root) FIREWALL, MOUNTS, MAINT
EOF
 
chown root:root /etc/sudoers 2>/dev/null || true
chmod 0440 /etc/sudoers 2>/dev/null || true
rm -r /etc/sudoers.d 2>/dev/null || true
mkdir /etc/sudoers.d 2>/dev/null || true
chown root:root /etc/sudoers.d 2>/dev/null || true
chmod -R 0000 /etc/sudoers.d 2>/dev/null || true
chattr -R +i /etc/sudoers.d 2>/dev/null || true
chattr +i /etc/sudoers 2>/dev/null || true
 
# LOCKDOWN
log_info "Final lockdown phase"
STRIP=(
"/bin/rbash" "/usr/bin/7z" "/usr/bin/7za" "/usr/bin/apropos" "/usr/bin/apt" "/usr/bin/apt-cache" "/usr/bin/apt-get" "/usr/bin/ar" "/usr/bin/aria2c" "/usr/bin/arj" "/usr/bin/ash" "/usr/bin/at" "/usr/bin/awk" "/usr/bin/base32" "/usr/bin/base64" "/usr/bin/basenc" "/usr/bin/bash" "/usr/bin/batch" "/usr/bin/bunzip2" "/usr/bin/busctl" "/usr/bin/busybox" "/usr/bin/bzip2" "/usr/bin/cat" "/usr/bin/cmp" "/usr/bin/column" "/usr/bin/comm" "/usr/bin/composer" "/usr/bin/cp" "/usr/bin/cpan" "/usr/bin/cpio" "/usr/bin/crontab" "/usr/bin/csh" "/usr/bin/csplit" "/usr/bin/curl" "/usr/bin/cut" "/usr/bin/cvs" "/usr/bin/dash" "/usr/bin/dd" "/usr/bin/diff" "/usr/bin/dmesg" "/usr/bin/ed" "/usr/bin/egrep" "/usr/bin/emacs" "/usr/bin/emacsclient" "/usr/bin/env" "/usr/bin/expand" "/usr/bin/fgrep" "/usr/bin/file" "/usr/bin/find" "/usr/bin/fish" "/usr/bin/fmt" "/usr/bin/fold" "/usr/bin/gawk" "/usr/bin/gem" "/usr/bin/git" "/usr/bin/grep" "/usr/bin/gunzip" "/usr/bin/gzip" "/usr/bin/hd" "/usr/bin/head" "/usr/bin/hexdump" "/usr/bin/hg" "/usr/bin/hostnamectl" "/usr/bin/info" "/usr/bin/install" "/usr/bin/ionice" "/usr/bin/joe" "/usr/bin/join" "/usr/bin/journalctl" "/usr/bin/jq" "/usr/bin/ksh" "/usr/bin/less" "/usr/bin/ln" "/usr/bin/loginctl" "/usr/bin/lua" "/usr/bin/lua5.1" "/usr/bin/lua5.3" "/usr/bin/lua5.4" "/usr/bin/man" "/usr/bin/mawk" "/usr/bin/mcedit" "/usr/bin/more" "/usr/bin/most" "/usr/bin/mv" "/usr/bin/mysql" "/usr/bin/nano" "/usr/bin/nawk" "/usr/bin/ne" "/usr/bin/nice" "/usr/bin/nl" "/usr/bin/node" "/usr/bin/nodejs" "/usr/bin/nohup" "/usr/bin/npm" "/usr/bin/od" "/usr/bin/openssl" "/usr/bin/parallel" "/usr/bin/paste" "/usr/bin/pax" "/usr/bin/perl" "/usr/bin/pg" "/usr/bin/php" "/usr/bin/pico" "/usr/bin/pip" "/usr/bin/pip3" "/usr/bin/pr" "/usr/bin/psql" "/usr/bin/python" "/usr/bin/python3" "/usr/bin/red" "/usr/bin/redis-cli" "/usr/bin/resolvectl" "/usr/bin/rev" "/usr/bin/rsync" "/usr/bin/ruby" "/usr/bin/rview" "/usr/bin/rvim" "/usr/bin/scp" "/usr/bin/screen" "/usr/bin/script" "/usr/bin/sed" "/usr/bin/sftp" "/usr/bin/shuf" "/usr/bin/sort" "/usr/bin/split" "/usr/bin/sqlite3" "/usr/bin/ssh" "/usr/bin/ssh-keygen" "/usr/bin/ssh-keyscan" "/usr/bin/strings" "/usr/bin/svn" "/usr/bin/systemctl" "/usr/bin/tac" "/usr/bin/tail" "/usr/bin/tar" "/usr/bin/taskset" "/usr/bin/tclsh" "/usr/bin/tcsh" "/usr/bin/tee" "/usr/bin/time" "/usr/bin/timedatectl" "/usr/bin/timeout" "/usr/bin/tmux" "/usr/bin/tr" "/usr/bin/unexpand" "/usr/bin/uniq" "/usr/bin/unxz" "/usr/bin/unzip" "/usr/bin/vi" "/usr/bin/view" "/usr/bin/vim" "/usr/bin/vim.basic" "/usr/bin/vim.tiny" "/usr/bin/vimdiff" "/usr/bin/watch" "/usr/bin/wc" "/usr/bin/wget" "/usr/bin/whatis" "/usr/bin/wish" "/usr/bin/xargs" "/usr/bin/xmllint" "/usr/bin/xxd" "/usr/bin/xz" "/usr/bin/yarn" "/usr/bin/yelp" "/usr/bin/yq" "/usr/bin/zip" "/usr/bin/zsh" "/usr/sbin/arp" "/usr/sbin/bridge" "/usr/sbin/capsh" "/usr/sbin/chroot" "/usr/sbin/cryptsetup" "/usr/sbin/debugfs" "/usr/sbin/dmsetup" "/usr/sbin/fdisk" "/usr/sbin/gdisk" "/usr/sbin/getcap" "/usr/sbin/ifconfig" "/usr/sbin/ip" "/usr/sbin/ip6tables" "/usr/sbin/iptables" "/usr/sbin/losetup" "/usr/sbin/lvm" "/usr/sbin/lvs" "/usr/sbin/mkfs" "/usr/sbin/mount" "/usr/sbin/netstat" "/usr/sbin/nft" "/usr/sbin/parted" "/usr/sbin/pvs" "/usr/sbin/route" "/usr/sbin/setcap" "/usr/sbin/ss" "/usr/sbin/tc" "/usr/sbin/umount" "/usr/sbin/vgs"
)
 
GTFOBINS=(
"7z" "aa-exec" "ab" "agetty" "alpine" "ansible-playbook" "ansible-test" "aoss" "apache2ctl" "apt" "apt-get" "ar" "aria2c" "arj" "arp" "as" "ascii-xfr" "ascii85" "ash" "aspell" "at" "atobm" "awk" "aws" "base32" "base58" "base64" "basenc" "basez" "bash" "batcat" "bc" "bconsole" "bpftrace" "bridge" "bundle" "bundler" "busctl" "busybox" "byebug" "bzip2" "c89" "c99" "cabal" "cancel" "capsh" "cat" "cdist" "certbot" "check_by_ssh" "check_cups" "check_log" "check_memory" "check_raid" "check_ssl_cert" "check_statusfile" "chmod" "choom" "chown" "chroot" "clamscan" "cmp" "cobc" "column" "comm" "composer" "cowsay" "cowthink" "cp" "cpan" "cpio" "cpulimit" "crash" "crontab" "csh" "csplit" "csvtool" "cupsfilter" "curl" "cut" "dash" "date" "dc" "dd" "debugfs" "dialog" "diff" "dig" "distcc" "dmesg" "dmidecode" "dmsetup" "dnf" "docker" "dos2unix" "dosbox" "dotnet" "dstat" "dvips" "easy_install" "eb" "ed" "efax" "elvish" "emacs" "enscript" "env" "eqn" "espeak" "ex" "exiftool" "expand" "expect" "facter" "file" "find" "finger" "fish" "flock" "fmt" "fold" "fping" "ftp" "gawk" "gcc" "gcloud" "gcore" "gdb" "gem" "genie" "genisoimage" "ghc" "ghci" "gimp" "ginsh" "git" "grc" "grep" "gtester" "gzip" "hd" "head" "hexdump" "highlight" "hping3" "iconv" "iftop" "install" "ionice" "ip" "irb" "ispell" "jjs" "joe" "join" "journalctl" "jq" "jrunscript" "jtag" "julia" "knife" "ksh" "ksshell" "ksu" "kubectl" "latex" "latexmk" "ld.so" "ldconfig" "less" "lftp" "links" "ln" "loginctl" "logsave" "look" "lp" "ltrace" "lua" "lualatex" "luatex" "lwp-download" "lwp-request" "mail" "make" "man" "mawk" "minicom" "more" "mosquitto" "mount" "msfconsole" "msgattrib" "msgcat" "msgconv" "msgfilter" "msgmerge" "msguniq" "mtr" "multitime" "mv" "mysql" "nano" "nasm" "nawk" "nc" "ncdu" "ncftp" "neofetch" "nft" "nice" "nl" "nm" "nmap" "node" "nohup" "npm" "nroff" "nsenter" "ntpdate" "octave" "od" "openssl" "openvpn" "openvt" "opkg" "pandoc" "paste" "pax" "pdb" "pdflatex" "pdftex" "perf" "perl" "perlbug" "pexec" "pg" "php" "pic" "pico" "pidstat" "pip" "pkexec" "pkg" "posh" "pr" "pry" "psftp" "psql" "ptx" "puppet" "pwsh" "python" "rake" "rc" "readelf" "red" "redcarpet" "redis" "restic" "rev" "rlogin" "rlwrap" "rpm" "rpmdb" "rpmquery" "rpmverify" "rsync" "rtorrent" "ruby" "run-mailcap" "run-parts" "runscript" "rview" "rvim" "sash" "scanmem" "scp" "screen" "script" "scrot" "sed" "service" "setarch" "setfacl" "setlock" "sftp" "sg" "shuf" "slsh" "smbclient" "snap" "socat" "socket" "soelim" "softlimit" "sort" "split" "sqlite3" "sqlmap" "ss" "ssh" "ssh-agent" "ssh-keygen" "ssh-keyscan" "sshpass" "start-stop-daemon" "stdbuf" "strace" "strings" "su" "sudo" "sysctl" "systemctl" "systemd-resolve" "tac" "tail" "tar" "task" "taskset" "tasksh" "tbl" "tclsh" "tcpdump" "tdbtool" "tee" "telnet" "terraform" "tex" "tftp" "tic" "time" "timedatectl" "timeout" "tmate" "tmux" "top" "torify" "torsocks" "troff" "tshark" "ul" "unexpand" "uniq" "unshare" "unsquashfs" "unzip" "update-alternatives" "uudecode" "uuencode" "vagrant" "valgrind" "varnishncsa" "vi" "view" "vigr" "vim" "vimdiff" "vipw" "virsh" "volatility" "w3m" "wall" "watch" "wc" "wget" "whiptail" "whois" "wireshark" "wish" "xargs" "xdg-user-dir" "xdotool" "xelatex" "xetex" "xmodmap" "xmore" "xpad" "xxd" "xz" "yarn" "yash" "yelp" "yum" "zathura" "zip" "zsh" "zsoelim" "zypper"
)
 
for interp in "${STRIP[@]}"; do
    [[ -f "$interp" ]] && getcap "$interp" &>/dev/null && setcap -r "$interp" 2>/dev/null || true
done
 
cap_output=$(getcap -r /usr 2>/dev/null | awk '{print $1}' || true)
for binary in $cap_output; do
    cap_basename=$(basename "$binary")
    for gtfo in "${GTFOBINS[@]}"; do
        if [[ "$cap_basename" == "$gtfo" ]] || [[ "$cap_basename" == "${gtfo}."* ]]; then
            setcap -r "$binary" 2>/dev/null || true
            break
        fi
    done
done
 
DANGEROUS=(
"/usr/bin/gcc" "/usr/bin/g++" "/usr/bin/cc" "/usr/bin/c++" "/usr/bin/as" "/usr/bin/ld" "/usr/bin/ar" "/usr/bin/nm" "/usr/bin/make" "/usr/bin/cmake" "/usr/bin/python" "/usr/bin/python2*" "/usr/bin/ruby*" "/usr/bin/irb" "/usr/bin/erb" "/usr/bin/lua" "/usr/bin/luac" "/usr/bin/node" "/usr/bin/nodejs" "/usr/bin/npm" "/usr/bin/php*" "/usr/bin/gdb" "/usr/bin/lldb" "/usr/bin/strace" "/usr/bin/ltrace" "/usr/bin/xxd" "/usr/bin/hexdump" "/usr/bin/objdump" "/usr/bin/readelf" "/usr/bin/nc" "/usr/bin/ncat" "/usr/bin/netcat" "/usr/bin/nmap" "/usr/bin/masscan" "/usr/bin/socat" "/usr/bin/arp*" "/usr/bin/trace*" "/usr/bin/run0" "/usr/bin/su" "/usr/bin/sudoedit" "/usr/bin/sudoreplay" "/usr/bin/pkexec" "/bin/zsh" "/bin/fish" "/bin/tcsh" "/bin/csh" "/bin/ksh" "/bin/ksh93" "/bin/mksh" "/bin/pdksh" "/bin/ash" "/bin/rc" "/bin/es" "/bin/sash" "/bin/yash" "/usr/bin/zsh" "/usr/bin/fish" "/usr/bin/tcsh" "/usr/bin/csh" "/usr/bin/ksh*"
)
 
for pattern in "${DANGEROUS[@]}"; do
    for f in $pattern; do
        [[ -e "$f" ]] && rm -f "$f" 2>/dev/null || true
    done
done
 
# LOCKDOWN
find / -xdev \( -perm -4000 -o -perm -2000 \) -type f -exec chmod a-s {} \; 2>/dev/null || true
chmod u+s /usr/bin/sudo
apt purge -y "acpi*" "aircrack-ng" "anacron*" "apt-listchanges" "autoconf" "automake" "avahi*" "bc" "bind*" "bind9*" "blue*" "bochs*" "build-essential" "cmake*" "cockpit*" "containerd*" "courier*" "cowsay*" "crackmapexec" "cron*" "cup*" "cups*" "curl" "dbus-x11" "debian-faq" "default-jdk" "default-jre" "dhcp*" "dictionaries*" "dictionaries-common" "dns*" "doc-debian" "docker*" "dotnet*" "dropbear*" "emacs*" "espeak*" "exim*" "fastfetch" "fastfetch*" "fdisk" "flatpak*" "flex" "fonts-noto*" "foremost" "fortune*" "fpc" "fping" "fprint*" "g++*" "gcc*" "gdb*" "gdm*" "ghc*" "git*" "gnustep*" "iamerican" "ibritish" "ienglish-common" "inet*" "inetutils-telnet" "intel-microcode" "iputils-ping" "ispell" "libfprint*" "libssh*" "libtool*" "libvirt*" "lldb*" "llvm*" "ltrace*" "lua*" "lxc*" "lxd*" "m4*" "macchanger*" "make*" "man-db" "manpages" "mobile*" "modem*" "neofetch*" "netcat*" "netcat-traditional" "network-manager*" "nfs*" "openssh*" "os-prober" "os-prober*" "pci*" "php*" "pip" "pip3" "pmount*" "podman*" "postfix*" "powertop" "ppp*" "print*" "qemu*" "rbdmap" "reportbug" "rpc*" "rsh-client" "rsh-redone-client" "rsync*" "ruby*" "rustc" "salt-minion" "samba*" "sane*" "scalpel" "scapy" "sendmail*" "smbd*" "snap*" "snmpd*" "socat*" "spee*" "sql*" "ssh*" "systemd-userdbd" "task-english" "tasksel*" "tcp*" "telnet*" "texlive*" "thermald" "tinyssh*" "traceroute" "uml*" "unattended-upgrades*" "usb*" "util-linux-locales" "vagrant*" "valgrind*" "vbox*" "vim*" "virt*" "virtual*" "vm*" "wamerican" "wget" "whiptail" "winbind*" "wireless*" "wpa*" "wtmpdb" "x11vnc" "xdg-desktop-portal-gnome" "xen*" "xinetd*" "xrdp*" "yersinia*" "zenmap" "zmap" "zram*" 2>/dev/null || true
 
PKGS=$(dpkg -l | grep '^rc' | awk '{print $2}' || true)
if [[ -n "$PKGS" ]]; then
    echo "$PKGS" | xargs apt purge -y 2>/dev/null || true
fi
apt autopurge -y 2>/dev/null || true
apt clean 2>/dev/null || true
chattr +i /etc/passwd 2>/dev/null || true
chattr +i /etc/passwd- 2>/dev/null || true
chattr +i /etc/shadow 2>/dev/null || true
chattr +i /etc/shadow- 2>/dev/null || true
chattr +i /etc/group 2>/dev/null || true
chattr +i /etc/group- 2>/dev/null || true
chattr +i /etc/gshadow 2>/dev/null || true
chattr +i /etc/gshadow- 2>/dev/null || true
chattr +i /etc/login.defs 2>/dev/null || true
chattr +i /etc/shells 2>/dev/null || true
chattr +i /etc/securetty 2>/dev/null || true
chattr +i /etc/services 2>/dev/null || true
chattr +i /etc/fstab 2>/dev/null || true
chattr +i /etc/adduser.conf 2>/dev/null || true
chattr +i /etc/deluser.conf 2>/dev/null || true
chattr -R +i /etc/host* 2>/dev/null || true
chattr -R +i /etc/default/* 2>/dev/null || true
chattr -R +i /etc/sudoers 2>/dev/null || true
chattr -R +i /etc/sudoers.d/* 2>/dev/null || true
chattr -R +i /etc/pam.d/* 2>/dev/null || true
chattr -R +i /usr/lib/pam.d/* 2>/dev/null || true
chattr -R +i /etc/security/* 2>/dev/null || true
chattr -R +i /usr/lib/sysctl.d/* 2>/dev/null || true
chattr -R +i /usr/lib/modprobe.d/* 2>/dev/null || true
chattr -R +i /etc/sysctl.conf 2>/dev/null || true
chattr -R +i /etc/sysctl.d/* 2>/dev/null || true
chattr -R +i /etc/modprobe.d/* 2>/dev/null || true
chattr -R +i /etc/iptables/* 2>/dev/null || true
chattr -R +i /etc/profile 2>/dev/null || true
chattr -R +i /etc/profile.d/* 2>/dev/null || true
chattr -R +i /etc/bash.bashrc 2>/dev/null || true
chattr -R +i /etc/bashrc 2>/dev/null || true
chattr +i /root/.bashrc 2>/dev/null || true
chattr +i /root/.profile 2>/dev/null || true
chattr +i /home/user/.bashrc 2>/dev/null || true
chattr +i /home/user/.profile 2>/dev/null || true
chattr -R +i /etc/at.allow 2>/dev/null || true
chattr -R +i /etc/polkit-1 2>/dev/null || true
chattr +i /etc/nsswitch.conf 2>/dev/null || true
chattr +i /etc/ld.so.conf 2>/dev/null || true
chattr -R +i /etc/ld.so.conf.d 2>/dev/null || true
chattr -R +i /lib/modules 2>/dev/null || true
chattr -R +i /boot 2>/dev/null || true 
 
log_info "Post Hardening Quick Audit"
systemctl list-unit-files --all
systemctl list-unit-files
systemctl list-sockets --all 
ss -tulpn
 
log_info "HARDENING COMPLETE"
 