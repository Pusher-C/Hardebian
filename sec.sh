#!/bin/bash

###############-WARNING-#################
###-THIS THE SHIT THAT KILLED BELUSHI-###
#########-RUN HER LOW AND SLOW-##########

set -euo pipefail

# PRE-CONFIG 
apt install -y extrepo iptables iptables-persistent netfilter-persistent --no-install-recommends
extrepo enable librewolf
apt modernize-sources
apt update
apt install -y librewolf --no-install-recommends

# SYSTEMD HARDENING
systemctl disable --now ssh.service ssh.socket vino-server.service x11vnc.service tigervnc.service xrdp.service xrdp-sesman.service serial-getty@*.service systemd-journal-remote.socket systemd-journal-gatewayd.socket systemd-journal-upload.service cockpit.socket cockpit.service webmin.service nfs-client.target nfs-common.service nfs-mountd.service nfs-server.service rpcbind.socket rpcbind.service iscsid.socket iscsid.service iscsi.service open-iscsi.service nvmf-autoconnect.service nvmefc-boot-connections.service smbd.service nmbd.service samba.service samba-ad-dc.service vsftpd.service proftpd.service pure-ftpd.service sssd.service krb5-kdc.service krb5-admin-server.service nslcd.service nscd.service winbind.service libvirtd.service libvirtd.socket libvirtd-ro.socket libvirtd-admin.socket virtlogd.service virtlogd.socket virtlockd.service virtlockd.socket qemu-guest-agent.service vboxdrv.service vboxballoonctrl-service.service vboxautostart-service.service vboxweb-service.service vmtoolsd.service vmware-vmblock-fuse.service hv-fcopy-daemon.service hv-kvp-daemon.service hv-vss-daemon.service docker.service docker.socket containerd.service podman.socket podman.service lxd.socket lxd.service lxc.service lxc-net.service multipassd.service snmpd.service snmptrapd.service salt-minion.service puppet.service chef-client.service cloud-init.service cloud-init-local.service cloud-config.service cloud-final.service spice-vdagentd.service spice-vdagentd.socket usbmuxd.service ModemManager.service unattended-upgrades wpa_supplicant speech-dispatcher bluez bluetooth.service apport.service avahi-daemon.socket avahi-daemon.service cups-browsed cups.socket cups.path cups.service debug-shell.service accounts-daemon.service colord.service geoclue.service switcheroo-control.service power-profiles-daemon.service bolt.service fwupd.service packagekit.service rtkit-daemon.service iio-sensor-proxy.service apt-daily.timer apt-daily-upgrade.timer man-db.timer e2scrub_all.timer motd-news.timer kerneloops.service anacron.timer anacron.service cron.service rsync.service pcscd.socket udisks2.service fprintd.service systemd-binfmt.service 2>/dev/null || true

systemctl mask ssh.service ssh.socket telnet.socket inetd.service xinetd.service vino-server.service x11vnc.service tigervnc.service xrdp.service xrdp-sesman.service xrdp.socket serial-getty@.service getty@ttyS0.service console-getty.service debug-shell.service systemd-journal-remote.socket systemd-journal-gatewayd.socket systemd-journal-upload.service cockpit.socket cockpit.service webmin.service nfs-client.target nfs-common.service nfs-mountd.service nfs-server.service nfs-blkmap.service nfs-idmapd.service rpcbind.socket rpcbind.service rpcbind.target iscsid.socket iscsid.service iscsi.service open-iscsi.service nvmf-autoconnect.service nvmefc-boot-connections.service smbd.service nmbd.service samba.service samba-ad-dc.service remote-fs.target remote-fs-pre.target remote-cryptsetup.target vsftpd.service proftpd.service pure-ftpd.service sssd.socket sssd-nss.socket sssd-pam.socket sssd-sudo.socket sssd-autofs.socket sssd-ssh.socket sssd-pac.socket sssd-kcm.socket krb5-kdc.service krb5-admin-server.service nslcd.service winbind.service libvirtd.service libvirtd.socket libvirtd-ro.socket libvirtd-admin.socket virtlogd.service virtlogd.socket virtlockd.service virtlockd.socket libvirt-guests.service qemu-guest-agent.service vboxdrv.service vboxballoonctrl-service.service vboxautostart-service.service vboxweb-service.service vboxadd.service vboxadd-service.service vmtoolsd.service vmware-vmblock-fuse.service vmware-tools.service open-vm-tools.service hv-fcopy-daemon.service hv-kvp-daemon.service hv-vss-daemon.service hyperv-daemons.service docker.service docker.socket containerd.service podman.socket podman.service lxd.socket lxd.service lxc.service lxc-net.service systemd-nspawn@.service machines.target multipassd.service snmpd.service snmptrapd.service salt-minion.service puppet.service chef-client.service cloud-init.target cloud-init.service cloud-init-local.service cloud-config.service cloud-final.service spice-vdagentd.service spice-vdagentd.socket usbip.service usbipd.service usbmuxd.service usbmuxd.socket ModemManager.service debug-shell.service ctrl-alt-del.target kexec.target systemd-kexec.service proc-sys-fs-binfmt_misc.mount proc-sys-fs-binfmt_misc.automount printer.target remote-fs.target remote-cryptsetup.target usb-gadget.target systemd-coredump.socket 2>/dev/null || true

cat >/etc/apt/apt.conf.d/98-hardening <<'EOF'
APT::Get::AllowUnauthenticated "false";
Acquire::http::AllowRedirect "false";
APT::Install-Recommends "false";
APT::Install-Suggests "false";
EOF
apt update

# FIREWALL
apt purge -y nftables
systemctl enable netfilter-persistent
service netfilter-persistent start
iptables -F
iptables -X
iptables -Z
iptables -t nat -F
iptables -t nat -X
iptables -t nat -Z
iptables -t mangle -F
iptables -t mangle -X
iptables -t mangle -Z
iptables -P INPUT DROP
iptables -P FORWARD DROP
iptables -P OUTPUT ACCEPT
iptables -A INPUT -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
iptables -A INPUT -i lo -j ACCEPT
iptables -A INPUT -m conntrack --ctstate INVALID -j DROP
iptables -A INPUT -i wg0 -j ACCEPT
iptables -A INPUT -p udp -j DROP
iptables -A INPUT -p tcp -j DROP
iptables -A INPUT -j DROP
ip6tables -F
ip6tables -X
ip6tables -Z
ip6tables -P INPUT DROP
ip6tables -P FORWARD DROP
ip6tables -P OUTPUT DROP
iptables-save > /etc/iptables/rules.v4
ip6tables-save > /etc/iptables/rules.v6
netfilter-persistent save

# PACKAGE REMOVAL/RESTRICTING
apt purge -y zram* pci* pmount* cron* avahi* bc bind9* dns* fastfetch fonts-noto* fprint* dhcp* lxc* docker* podman* xen* bochs* uml* vagrant* ssh* openssh* samba* winbind* qemu* libvirt* virt* avahi* cup* print* rsync* nftables* virtual* sane* rpc* bind* nfs* blue* spee* espeak* mobile* wireless* inet* util-linux-locales tasksel* vim* os-prober* netcat* gcc g++ gdb lldb strace* ltrace* build-essential automake autoconf libtool cmake ninja-build meson traceroute

install -d /etc/apt/preferences.d
cat >/etc/apt/preferences.d/deny.pref <<'EOF'
Package: openssh*
Pin: release *
Pin-Priority: -1

Package: dropbear*
Pin: release *
Pin-Priority: -1

Package: ssh*
Pin: release *
Pin-Priority: -1

Package: tinyssh*
Pin: release *
Pin-Priority: -1

Package: qemu*
Pin: release *
Pin-Priority: -1

Package: libvirt*
Pin: release *
Pin-Priority: -1

Package: uml*
Pin: release *
Pin-Priority: -1

Package: virt*
Pin: release *
Pin-Priority: -1

Package: courier*
Pin: release *
Pin-Priority: -1

Package: dma*
Pin: release *
Pin-Priority: -1

Package: tripwire*
Pin: release *
Pin-Priority: -1

Package: avahi*
Pin: release *
Pin-Priority: -1

Package: samba*
Pin: release *
Pin-Priority: -1

Package: pmount*
Pin: release *
Pin-Priority: -1

Package: sane*
Pin: release *
Pin-Priority: -1

Package: netcat*
Pin: release *
Pin-Priority: -1

Package: os-prober*
Pin: release *
Pin-Priority: -1

Package: bluetooth*
Pin: release *
Pin-Priority: -1

Package: bluez*
Pin: release *
Pin-Priority: -1

Package: rpcbind*
Pin: release *
Pin-Priority: -1

Package: nfs-common*
Pin: release *
Pin-Priority: -1

Package: nfs-kernel-server*
Pin: release *
Pin-Priority: -1

Package: cups*
Pin: release *
Pin-Priority: -1

Package: anacron*
Pin: release *
Pin-Priority: -1

Package: exim*
Pin: release *
Pin-Priority: -1

Package: postfix*
Pin: release *
Pin-Priority: -1

Package: sendmail*
Pin: release *
Pin-Priority: -1

Package: printer-driver*
Pin: release *
Pin-Priority: -1

Package: vagrant*
Pin: release *
Pin-Priority: -1

Package: lxc*
Pin: release *
Pin-Priority: -1

Package: docker*
Pin: release *
Pin-Priority: -1

Package: podman*
Pin: release *
Pin-Priority: -1

Package: xen*
Pin: release *
Pin-Priority: -1

Package: bochs*
Pin: release *
Pin-Priority: -1

Package: gnustep*
Pin: release *
Pin-Priority: -1

Package: modemmanager*
Pin: release *
Pin-Priority: -1

Package: wpasupplicant*
Pin: release *
Pin-Priority: -1

Package: wireless*
Pin: release *
Pin-Priority: -1

Package: inet*
Pin: release *
Pin-Priority: -1

Package: nftables*
Pin: release *
Pin-Priority: -1

Package: gcc-[0-9]*
Pin: release *
Pin-Priority: -1

Package: g++-[0-9]*
Pin: release *
Pin-Priority: -1

Package: gdb*
Pin: release *
Pin-Priority: -1

Package: lldb*
Pin: release *
Pin-Priority: -1

Package: strace*
Pin: release *
Pin-Priority: -1

Package: ltrace*
Pin: release *
Pin-Priority: -1

Package: build-essential*
Pin: release *
Pin-Priority: -1

Package: automake*
Pin: release *
Pin-Priority: -1

Package: autoconf*
Pin: release *
Pin-Priority: -1

Package: cmake*
Pin: release *
Pin-Priority: -1

Package: nasm*
Pin: release *
Pin-Priority: -1

Package: yasm*
Pin: release *
Pin-Priority: -1

Package: nodejs*
Pin: release *
Pin-Priority: -1

Package: npm*
Pin: release *
Pin-Priority: -1

Package: php*
Pin: release *
Pin-Priority: -1

Package: ruby*
Pin: release *
Pin-Priority: -1

Package: traceroute*
Pin: release *
Pin-Priority: -1
EOF

# PACKAGE INSTALLATION
apt install -y apparmor apparmor-utils apparmor-profiles apparmor-profiles-extra rsyslog chrony libpam-tmpdir acct rkhunter chkrootkit debsums unzip patch pavucontrol pipewire pipewire-audio-client-libraries pipewire-pulse wireplumber lynis macchanger unhide tcpd fonts-liberation xfce4 libxfce4ui-utils xfce4-panel xfce4-session xfce4-settings xfconf xfdesktop4 xfwm4 xserver-xorg xinit xserver-xorg-legacy xfce4-pulseaudio-plugin xfce4-whiskermenu-plugin gnome-terminal gnome-brave-icon-theme breeze-gtk-theme bibata-cursor-theme gdebi-core opensnitch python3-opensnitch*

systemctl enable acct
systemctl start acct

systemctl enable apparmor
systemctl start apparmor
aa-enforce /etc/apparmor.d/*

# AUDITD
apt install -y auditd audispd-plugins
systemctl enable auditd

install -d /etc/audit/rules.d
cat >/etc/audit/rules.d/privilege-escalation.rules <<'EOF'
# Delete all existing rules
-D

# Buffer size
-b 8192

# Failure mode (2 = panic)
-f 2

# Identity file changes
-w /etc/passwd -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/group -p wa -k identity
-w /etc/gshadow -p wa -k identity
-w /etc/sudoers -p wa -k privilege_escalation
-w /etc/sudoers.d -p wa -k privilege_escalation
-w /etc/pam.d -p wa -k pam_config
-w /etc/security -p wa -k security_config
-w /usr/bin/sudo -p x -k privilege_escalation
-w /usr/bin/su -p x -k privilege_escalation
-w /usr/bin/passwd -p x -k privilege_escalation
-w /usr/bin/chsh -p x -k privilege_escalation
-w /usr/bin/chfn -p x -k privilege_escalation
-w /usr/bin/newgrp -p x -k privilege_escalation
-w /sbin/insmod -p x -k module_load
-w /sbin/rmmod -p x -k module_load
-w /sbin/modprobe -p x -k module_load
-w /etc/hosts -p wa -k network_config
-w /etc/iptables -p wa -k firewall_config

-a always,exit -F arch=b64 -S execve -F euid=0 -F auid>=1000 -F auid!=4294967295 -k root_commands
-a always,exit -F arch=b32 -S execve -F euid=0 -F auid>=1000 -F auid!=4294967295 -k root_commands
-e 2
EOF

chmod 640 /etc/audit/rules.d/privilege-escalation.rules
chown root:root /etc/audit/rules.d/privilege-escalation.rules

# PAM/U2F
pamu2fcfg -u dev > /etc/security/u2f_keys
chmod 0400 /etc/security/u2f_keys
chown root:root /etc/security/u2f_keys
chattr +i /etc/security/u2f_keys
mkdir -p /var/log/faillock
chmod 0700 /var/log/faillock
rm -f /etc/pam.d/remote
rm -f /etc/pam.d/cron

cat > /etc/security/faillock.conf <<'EOF'
deny = 3
unlock_time = 900
silent
EOF
chattr +i /etc/security/faillock.conf

cat >/etc/pam.d/chfn <<'EOF'
#%PAM-1.0
auth      sufficient  pam_rootok.so
auth      include     common-auth
account   include     common-account
session   include     common-session
EOF

cat >/etc/pam.d/chpasswd <<'EOF'
#%PAM-1.0
password  include     common-password
EOF

cat >/etc/pam.d/chsh <<'EOF'
#%PAM-1.0
auth      required    pam_shells.so
auth      sufficient  pam_rootok.so
auth      include     common-auth
account   include     common-account
session   include     common-session
EOF

cat > /etc/pam.d/common-auth <<'EOF'
#%PAM-1.0
auth      required    pam_faildelay.so delay=3000000
auth      required    pam_faillock.so preauth silent deny=3 unlock_time=900 fail_interval=900
auth     [success=1 default=ignore] pam_u2f.so authfile=/etc/security/u2f_keys/%u cue nouserok
auth      requisite   pam_deny.so
auth      required    pam_faillock.so authfail deny=3 unlock_time=900 fail_interval=900
EOF

cat >/etc/pam.d/common-account <<'EOF'
#%PAM-1.0
account   required    pam_access.so accessfile=/etc/security/access.conf
account   required    pam_faillock.so
account   required    pam_nologin.so
EOF

cat >/etc/pam.d/common-password <<'EOF'
#%PAM-1.0
password  requisite   pam_deny.so
EOF

cat >/etc/pam.d/common-session <<'EOF'
#%PAM-1.0
session   required    pam_limits.so
session   required    pam_env.so
session   optional    pam_systemd.so
session   optional    pam_umask.so umask=077
session   optional    pam_tmpdir.so
session   required    pam_unix.so
EOF

cat >/etc/pam.d/common-session-noninteractive <<'EOF'
#%PAM-1.0
session   required    pam_limits.so
session   required    pam_env.so
session   optional    pam_systemd.so
session   optional    pam_umask.so umask=077
session   optional    pam_tmpdir.so
session   required    pam_unix.so
EOF

cat >/etc/pam.d/sudo <<'EOF'
#%PAM-1.0
auth       required   pam_u2f.so authfile=/etc/security/u2f_keys/%u cue
auth       required   pam_faillock.so preauth silent deny=3 unlock_time=900
account    include    common-account
session    required   pam_limits.so
session    include    common-session
EOF

cat >/etc/pam.d/sudo-i <<'EOF'
#%PAM-1.0
auth       required   pam_u2f.so authfile=/etc/security/u2f_keys/%u cue
auth       required   pam_faillock.so preauth silent deny=3 unlock_time=900
account    include    common-account
session    required   pam_limits.so
session    include    common-session
EOF

cat >/etc/pam.d/su <<'EOF'
#%PAM-1.0
auth       required   pam_u2f.so authfile=/etc/security/u2f_keys/%u cue
auth       required   pam_faillock.so preauth silent deny=3 unlock_time=900
account    include    common-account
session    required   pam_limits.so
session    include    common-session
EOF

cat >/etc/pam.d/su-l <<'EOF'
#%PAM-1.0
auth       required    pam_u2f.so      authfile=/etc/security/u2f_keys/%u cue
auth       required    pam_faillock.so preauth silent deny=3 unlock_time=900
account    include     common-account
session    required    pam_limits.so
session    include     common-session
EOF

cat >/etc/pam.d/sshd <<'EOF'
#%PAM-1.0
auth       required    pam_deny.so
account    required    pam_deny.so
password   required    pam_deny.so
session    required    pam_deny.so
EOF

cat >/etc/pam.d/other <<'EOF'
#%PAM-1.0
auth       required    pam_deny.so
account    required    pam_deny.so
password   required    pam_deny.so
session    required    pam_deny.so
EOF

cat >/etc/pam.d/login <<'EOF'
#%PAM-1.0
auth       required    pam_securetty.so
auth       required    pam_nologin.so
auth       include     common-auth
account    include     common-account
session    required    pam_limits.so
session    required    pam_loginuid.so
session    include     common-session
EOF

cat >/etc/pam.d/newusers <<'EOF'
#%PAM-1.0
password  include     common-password
EOF

cat >/etc/pam.d/passwd <<'EOF'
#%PAM-1.0
password  include     common-password
EOF

cat >/etc/pam.d/runuser <<'EOF'
#%PAM-1.0
auth      sufficient  pam_rootok.so
session   required    pam_limits.so
session   required    pam_unix.so
EOF

cat >/etc/pam.d/runuser-l <<'EOF'
#%PAM-1.0
auth      include     runuser
session   include     runuser
EOF

# SUDO
cat >/etc/sudoers <<'EOF'
Defaults timestamp_timeout=5
Defaults passwd_timeout=1
Defaults passwd_tries=2
Defaults use_pty
Defaults secure_path="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin"
Defaults requiretty
Defaults logfile="/var/log/sudo.log"
Defaults log_input,log_output
root  ALL=(ALL) ALL
%sudo ALL=(ALL) ALL
EOF
chmod 0440 /etc/sudoers
chmod -R 0440 /etc/sudoers.d

# MISC HARDENING
cat >/etc/shells <<'EOF'
/bin/bash
EOF

passwd -l root
echo "needs_root_rights=no" >> /etc/X11/Xwrapper.config
dpkg-reconfigure xserver-xorg-legacy

cat >/etc/host.conf <<'EOF'
multi on
order hosts,bind
EOF

cat >/etc/security/limits.d/limits.conf <<'EOF'
*           hard    nproc         2048
*            -      maxlogins     1
*            -      maxsyslogins  1
dev          -      maxlogins     1
dev          -      maxsyslogins  1
root         -      maxlogins     1
root         -      maxsyslogin   1
root        hard    nproc         65536
*           hard    core          0
EOF

echo "ProcessSizeMax=0
Storage=none" >> /etc/systemd/coredump.conf
echo "ulimit -c 0" >> /etc/profile

sed -i 's/^ENCRYPT_METHOD.*/ENCRYPT_METHOD YESCRYPT/' /etc/login.defs
sed -i 's/^UID_MIN.*/UID_MIN 1000/' /etc/login.defs
sed -i 's/^UID_MAX.*/UID_MAX 60000/' /etc/login.defs
sed -i 's/^SHELL=.*/SHELL=\/usr\/sbin\/nologin/' /etc/default/useradd
sed -i 's/^DSHELL=.*/DSHELL=\/usr\/sbin\/nologin/' /etc/adduser.conf
echo "UMASK 077" >> /etc/login.defs
echo "umask 077" >> /etc/profile
echo "umask 077" >> /etc/bash.bashrc
echo "ALL: LOCAL, 127.0.0.1" >> /etc/hosts.allow
echo "ALL: ALL" > /etc/hosts.deny
chmod 644 /etc/hosts.allow
chmod 644 /etc/hosts.deny

cat > /etc/profile.d/autologout.sh <<'EOF'
TMOUT=600
readonly TMOUT
export TMOUT
EOF

cat > /etc/security/access.conf << EOF
# Single user access
+ : dev : LOCAL
+ : root : LOCAL
# Deny everyone else
- : ALL : ALL
EOF
chmod 644 /etc/security/access.conf

# GRUB 
sed -i 's|^GRUB_CMDLINE_LINUX_DEFAULT=.*|GRUB_CMDLINE_LINUX_DEFAULT="auto,nosmt spectre_v2=on spec_store_bypass_disable=on l1tf=full,force mds=full,nosmt tsx=off tsx_async_abort=full,nosmt mmio_stale_data=full,nosmt retbleed=auto,nosmt srbds=on gather_data_sampling=force reg_file_data_sampling=on intel_iommu=on iommu=force iommu.passthrough=0 iommu.strict=1 efi=disable_early_pci_dma lockdown=confidentiality init_on_alloc=1 init_on_free=1 page_alloc.shuffle=1 randomize_kstack_offset=on slab_nomerge vsyscall=none debugfs=off oops=panic module.sig_enforce=1 ipv6.disable=1 nosmt nowatchdog nmi_watchdog=0"|' /etc/default/grub
update-grub
chown root:root /etc/default/grub
chmod 640 /etc/default/grub

# SYSCTL 
rm -rf /usr/lib/sysctl.d
mkdir -p /usr/lib/sysctl.d
cat > /usr/lib/sysctl.d/sysctl.conf << 'EOF'
# Restrict kernel pointer exposure
kernel.kptr_restrict = 2
kernel.dmesg_restrict = 1
kernel.perf_event_paranoid = 3
kernel.kexec_load_disabled = 1
kernel.unprivileged_bpf_disabled = 1
net.core.bpf_jit_harden = 2
kernel.sysrq = 0
kernel.yama.ptrace_scope = 2
kernel.randomize_va_space = 2
kernel.unprivileged_userns_clone = 1
kernel.core_pattern = |/bin/false
fs.suid_dumpable = 0
fs.protected_symlinks = 1
fs.protected_hardlinks = 1
fs.protected_fifos = 2
fs.protected_regular = 2
net.ipv4.ip_forward = 0
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.secure_redirects = 0
net.ipv4.conf.default.secure_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.log_martians = 1
net.ipv4.icmp_echo_ignore_all = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_max_syn_backlog = 4096
net.ipv4.tcp_synack_retries = 2
net.ipv4.tcp_syn_retries = 3
net.ipv4.tcp_rfc1337 = 1
net.ipv4.tcp_timestamps = 0
net.ipv4.tcp_sack = 0
net.ipv4.tcp_dsack = 0
net.ipv4.tcp_fack = 0
net.ipv4.ip_local_port_range = 32768 60999
net.ipv4.ip_unprivileged_port_start = 1024
net.ipv6.conf.all.disable_ipv6 = 1
net.ipv6.conf.default.disable_ipv6 = 1
net.ipv6.conf.lo.disable_ipv6 = 1
net.netfilter.nf_conntrack_max = 131072
net.netfilter.nf_conntrack_tcp_timeout_established = 3600
net.netfilter.nf_conntrack_tcp_timeout_time_wait = 60
vm.mmap_min_addr = 65536
vm.mmap_rnd_bits = 32
vm.mmap_rnd_compat_bits = 16
kernel.printk = 3 3 3 3
kernel.sysrq = 0
vm.panic_on_oom = 0
vm.oom_kill_allocating_task = 1
vm.swappiness = 1
vm.dirty_ratio = 5
vm.dirty_background_ratio = 3
EOF
sysctl --system

# MODULES
cat > /etc/modprobe.d/harden.conf << 'EOF'
blacklist af_802154
install af_802154 /bin/false
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
blacklist atm
install atm /bin/false
blacklist ax25
install ax25 /bin/false
blacklist bluetooth
install bluetooth /bin/false
blacklist brcmsmac
install brcmsmac /bin/false
blacklist brcmfmac
install brcmfmac /bin/false
blacklist btbcm
install btbcm /bin/false
blacklist btintel
install btintel /bin/false
blacklist btusb
install btusb /bin/false
blacklist btrtl
install btrtl /bin/false
blacklist can
install can /bin/false
blacklist cramfs
install cramfs /bin/false
blacklist cfg80211
install cfg80211 /bin/false
blacklist dccp
install dccp /bin/false
blacklist decnet
install decnet /bin/false
blacklist dvb_core
install dvb_core /bin/false
blacklist dvb_usb
install dvb_usb /bin/false
blacklist dvb_usb_v2
install dvb_usb_v2 /bin/false
blacklist econet
install econet /bin/false
blacklist firewire-core
install firewire-core /bin/false
blacklist firewire-ohci
install firewire-ohci /bin/false
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
blacklist gnss-serial
install gnss-serial /bin/false
blacklist gnss-usb
install gnss-usb /bin/false
blacklist hfs
install hfs /bin/false
blacklist hfsplus
install hfsplus /bin/false
blacklist hamradio
install hamradio /bin/false
blacklist ipx
install ipx /bin/false
blacklist iwlwifi
install iwlwifi /bin/false
blacklist jffs2
install jffs2 /bin/false
blacklist joydev
install joydev /bin/false
blacklist jfs
install jfs /bin/false
blacklist kvm
install kvm /bin/false
blacklist kvm_amd
install kvm_amd /bin/false
blacklist kvm_intel
install kvm_intel /bin/false
blacklist lp
install lp /bin/false
blacklist mac80211
install mac80211 /bin/false
blacklist mt76
install mt76 /bin/false
blacklist mt76_usb
install mt76_usb /bin/false
blacklist mt76x0u
install mt76x0u /bin/false
blacklist mt76x2u
install mt76x2u /bin/false
blacklist mt7601u
install mt7601u /bin/false
blacklist mt7615e
install mt7615e /bin/false
blacklist mt7921e
install mt7921e /bin/false
blacklist netrom
install netrom /bin/false
blacklist p8022
install p8022 /bin/false
blacklist p8023
install p8023 /bin/false
blacklist parport
install parport /bin/false
blacklist ppdev
install ppdev /bin/false
blacklist psnap
install psnap /bin/false
blacklist r820t
install r820t /bin/false
blacklist rds
install rds /bin/false
blacklist reiserfs
install reiserfs /bin/false
blacklist rose
install rose /bin/false
blacklist rt2800lib
install rt2800lib /bin/false
blacklist rt2800pci
install rt2800pci /bin/false
blacklist rt2800usb
install rt2800usb /bin/false
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
blacklist rtl2830
install rtl2830 /bin/false
blacklist rtl2832
install rtl2832 /bin/false
blacklist rtl2832_sdr
install rtl2832_sdr /bin/false
blacklist rtl2838
install rtl2838 /bin/false
blacklist sctp
install sctp /bin/false
blacklist squashfs
install squashfs /bin/false
blacklist tipc
install tipc /bin/false
blacklist uas
install uas /bin/false
blacklist udf
install udf /bin/false
blacklist usb_storage
install usb_storage /bin/false
blacklist uvcvideo
install uvcvideo /bin/false
blacklist vboxdrv
install vboxdrv /bin/false
blacklist vboxnetadp
install vboxnetadp /bin/false
blacklist vboxnetflt
install vboxnetflt /bin/false
blacklist vhost
install vhost /bin/false
blacklist vhost_net
install vhost_net /bin/false
blacklist vhost_vsock
install vhost_vsock /bin/false
blacklist video1394
install video1394 /bin/false
blacklist vmmon
install vmmon /bin/false
blacklist vmw_vmci
install vmw_vmci /bin/false
blacklist xen
install xen /bin/false
blacklist x25
install x25 /bin/false
blacklist mei
install mei /bin/false
blacklist mei_me
install mei_me /bin/false
blacklist mei_hdcp
install mei_hdcp /bin/false
blacklist mei_pxp
install mei_pxp /bin/false
blacklist thunderbolt
install thunderbolt /bin/false
blacklist iwlmvm
install iwlmvm /bin/false
blacklist iwldvm
install iwldvm /bin/false
blacklist ipv6
install ipv6 /bin/false
EOF

# FSTAB 
cp /etc/fstab /etc/fstab.bak

cp /etc/fstab /etc/fstab.bak
BOOT_LINE=$(grep -E '^\s*UUID=.*\s+/boot\s+' /etc/fstab || echo "")
BOOT_EFI_LINE=$(grep -E '^\s*UUID=.*\s+/boot/efi\s+' /etc/fstab || echo "")

if [ -n "$BOOT_LINE" ]; then
    BOOT_UUID=$(echo "$BOOT_LINE" | grep -oP 'UUID=[A-Za-z0-9-]+')
    echo "${BOOT_UUID}    /boot    ext4    noatime,nodev,nosuid,noexec,ro 0 2" >> /etc/fstab
fi
if [ -n "$BOOT_EFI_LINE" ]; then
    BOOT_EFI_UUID=$(echo "$BOOT_EFI_LINE" | grep -oP 'UUID=[A-Za-z0-9-]+')
    echo "${BOOT_EFI_UUID}    /boot/efi    vfat    noatime,nodev,nosuid,noexec,umask=0077,ro 0 2" >> /etc/fstab
fi

cat > /etc/fstab << 'EOF'
/dev/mapper/lvg-root       /              ext4    noatime,nodev,errors=remount-ro    0 1
/dev/mapper/lvg-usr        /usr           ext4    noatime,nodev,ro                   0 2
/dev/mapper/lvg-var        /var           ext4    noatime,nodev,nosuid               0 2
/dev/mapper/lvg-var_log    /var/log       ext4    noatime,nodev,nosuid,noexec        0 2
/dev/mapper/lvg-home       /home          ext4    noatime,nodev,nosuid,noexec        0 2
proc     /proc      proc      noatime,nodev,nosuid,noexec,hidepid=2,gid=proc    0 0
tmpfs    /tmp       tmpfs     size=2G,noatime,nodev,nosuid,noexec,mode=1777     0 0
tmpfs    /var/tmp   tmpfs     size=1G,noatime,nodev,nosuid,noexec,mode=1777     0 0
tmpfs    /dev/shm   tmpfs     size=512M,noatime,nodev,nosuid,noexec,mode=1777   0 0
tmpfs    /run       tmpfs     size=512M,noatime,nodev,nosuid,mode=0755          0 0
tmpfs    /home/dev/.cache    tmpfs    size=1G,noatime,nodev,nosuid,noexec,mode=700,uid=1000,gid=1000    0 0
EOF

groupadd -f proc
gpasswd -a root proc

# PERMISSIONS
chown root:root /etc/group /etc/group- /etc/passwd /etc/passwd- /etc/security /etc/iptables /etc/default /etc/sudoers /etc/fstab /etc/hosts /etc/host.conf 2>/dev/null || true
chmod 0644 /etc/passwd
chmod 0644 /etc/group
chmod 0640 /etc/shadow
chmod 0640 /etc/gshadow
chmod 0600 /etc/passwd-
chmod 0600 /etc/group-
chmod 0600 /etc/shadow-
chmod 0640 /etc/gshadow-
chmod 0640 /etc/fstab 
chmod 0600 /root/.bashrc
chmod 0600 /root/.profile
chmod 0700 /etc/security
chown dev:dev /home/dev
chmod 0700 /home/dev
chmod 0700 /root 
chmod 0700 /boot
chown root:root /boot/grub/grub.cfg
chmod 0400 /boot/grub/grub.cfg
chmod -R 0400 /etc/iptables
chown root:root /var/run/dbus 2>/dev/null || true
chmod 0755 /var/run/dbus 2>/dev/null || true
chown root:root /run/systemd 2>/dev/null || true
chmod 0755 /run/systemd 2>/dev/null || true
touch /etc/security/opasswd
chown root:root /etc/security/opasswd
chmod 0600 /etc/security/opasswd
chown root:adm -R /var/log
chmod -R 0640 /var/log
chmod 0750 /var/log

# OPENSNITCH 
cat > /etc/systemd/system/opensnitchd.service << 'EOF'
[Unit]
Description=OpenSnitch Firewall Daemon
After=network.target
After=netfilter-persistent.service
Wants=network.target

[Service]
Type=simple
ExecStart=/usr/bin/opensnitchd -rules-path /etc/opensnitchd/rules -log-file /var/log/opensnitchd.log
Restart=on-failure
RestartSec=5
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF

# Create rules directory if it doesn't exist
mkdir -p /etc/opensnitchd/rules
chmod 750 /etc/opensnitchd
chmod 750 /etc/opensnitchd/rules

# Create log file with proper permissions
touch /var/log/opensnitchd.log
chmod 640 /var/log/opensnitchd.log

# Enable and start the daemon
systemctl daemon-reload
systemctl enable opensnitchd.service
systemctl start opensnitchd.service

# Install Blocklists
apt install git 
git clone --depth 1 https://github.com/DXC-0/Respect-My-Internet.git
cd Respect-My-Internet
chmod +x install.sh
./install.sh
systemctl restart opensnitchd
cd

# PRIVILEGE ESCALATION HARDENING
echo "" > /etc/securetty
chmod 600 /etc/securetty

# Restrict cron/at to dev only
echo "dev" > /etc/cron.allow
echo "dev" > /etc/at.allow
chmod 600 /etc/cron.allow
chmod 600 /etc/at.allow
echo "" > /etc/cron.deny 2>/dev/null || true
echo "" > /etc/at.deny 2>/dev/null || true


# PRIVILEGE ESCALATION MONITORING 
cat > /usr/local/bin/escalation-monitor <<'EOF'
#!/bin/bash

LOG="/var/log/escalation-monitor.log"
BASELINE_FILE="/var/lib/escalation-monitor-baseline"
MODULES_BASELINE="/var/lib/modules-baseline"

HALT_ON_VIOLATION=1

EXCLUDE_DIRS=(
    "/timeshift"
)

log_alert() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] ALERT: $1" >> "$LOG"
    logger -t ESCALATION_MONITOR -p security.crit "$1"
}

log_info() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] INFO: $1" >> "$LOG"
}

# Build the find exclusion string
build_exclusions() {
    local excludes=""
    for dir in "${EXCLUDE_DIRS[@]}"; do
        if [ -d "$dir" ]; then
            excludes="$excludes -path '$dir' -prune -o"
        fi
    done
    echo "$excludes"
}

# SUID/SGID CHECK
PRUNE_PATTERN=""
for dir in "${EXCLUDE_DIRS[@]}"; do
    if [ -d "$dir" ]; then
        PRUNE_PATTERN="$PRUNE_PATTERN -path $dir -prune -o"
    fi
done

# Get current SUID files
CURRENT_SUID=$(eval "find / -xdev $PRUNE_PATTERN \( -perm -4000 -o -perm -2000 \) -type f -print 2>/dev/null" | sort)
CURRENT_SUID_COUNT=$(echo "$CURRENT_SUID" | grep -c . || echo "0"
if [ ! -f "$BASELINE_FILE" ]; then
    log_info "First run - establishing SUID baseline with $CURRENT_SUID_COUNT files"
    echo "$CURRENT_SUID" > "$BASELINE_FILE"
    chmod 600 "$BASELINE_FILE"
    chattr +i "$BASELINE_FILE" 2>/dev/null || true
    log_info "Baseline files:"
    echo "$CURRENT_SUID" >> "$LOG"
else
    # Compare against baseline
    chattr -i "$BASELINE_FILE" 2>/dev/null || true
    BASELINE_SUID=$(cat "$BASELINE_FILE")
    chattr +i "$BASELINE_FILE" 2>/dev/null || true
    
# Check for new SUID files
    NEW_SUID=$(comm -23 <(echo "$CURRENT_SUID") <(echo "$BASELINE_SUID") 2>/dev/null)
    
# Check for removed SUID files
    REMOVED_SUID=$(comm -13 <(echo "$CURRENT_SUID") <(echo "$BASELINE_SUID") 2>/dev/null)
    
    if [ -n "$NEW_SUID" ] && [ "$NEW_SUID" != "" ]; then
        log_alert "NEW SUID/SGID files detected:"
        echo "$NEW_SUID" >> "$LOG"
        
        if [ $HALT_ON_VIOLATION -eq 1 ]; then
            log_alert "Halting system due to unauthorized SUID files"
            sync
            systemctl halt
        fi
    fi
    
    if [ -n "$REMOVED_SUID" ] && [ "$REMOVED_SUID" != "" ]; then
        log_info "SUID/SGID files removed (may be normal):"
        echo "$REMOVED_SUID" >> "$LOG"
        # Don't halt on removal - that's usually fine
    fi
fi

# KERNEL MODULE CHECK 
if [ -f "$MODULES_BASELINE" ]; then
    # Create temp file for current state
    CURRENT_MODULES=$(mktemp)
    find /lib/modules -name "*.ko" -type f -exec md5sum {} \; 2>/dev/null | sort > "$CURRENT_MODULES"
    
    chattr -i "$MODULES_BASELINE" 2>/dev/null || true
    BASELINE_SORTED=$(mktemp)
    sort "$MODULES_BASELINE" > "$BASELINE_SORTED"
    chattr +i "$MODULES_BASELINE" 2>/dev/null || true
    
    if ! diff -q "$CURRENT_MODULES" "$BASELINE_SORTED" >/dev/null 2>&1; then
        # Get specific changes
        CHANGES=$(diff "$BASELINE_SORTED" "$CURRENT_MODULES" 2>/dev/null | head -20)
        log_alert "Kernel modules have been modified:"
        echo "$CHANGES" >> "$LOG"
        
        if [ $HALT_ON_VIOLATION -eq 1 ]; then
            log_alert "Halting system due to kernel module tampering"
            rm -f "$CURRENT_MODULES" "$BASELINE_SORTED"
            sync
            systemctl halt
        fi
    fi
    
    rm -f "$CURRENT_MODULES" "$BASELINE_SORTED"
else
    log_info "No module baseline found - creating one"
    find /lib/modules -name "*.ko" -type f -exec md5sum {} \; 2>/dev/null | sort > "$MODULES_BASELINE"
    chmod 600 "$MODULES_BASELINE"
    chattr +i "$MODULES_BASELINE" 2>/dev/null || true
fi

# U2F AUTHENTICATION FAILURES 
if [ -f /var/log/auth.log ]; then
    # Check for recent failures (last 10 minutes)
    RECENT_FAILS=$(grep "pam_u2f.*fail" /var/log/auth.log 2>/dev/null | tail -20 | wc -l || echo "0")
    
    if [ "$RECENT_FAILS" -ge 3 ]; then
        log_alert "Multiple U2F authentication failures detected: $RECENT_FAILS"
    fi
fi

# ROOTKIT CHECK
if command -v rkhunter >/dev/null 2>&1; then
    # Only run full check once per day to avoid performance hit
    LAST_CHECK="/var/lib/rkhunter-last-check"
    CURRENT_DAY=$(date +%Y%m%d)
    
    if [ ! -f "$LAST_CHECK" ] || [ "$(cat $LAST_CHECK 2>/dev/null)" != "$CURRENT_DAY" ]; then
        log_info "Running daily rkhunter check"
        RKHUNTER_OUTPUT=$(rkhunter --check --skip-keypress --report-warnings-only 2>&1 || true)
        
        if [ -n "$RKHUNTER_OUTPUT" ]; then
            log_alert "rkhunter warnings:"
            echo "$RKHUNTER_OUTPUT" >> "$LOG"
        fi
        
        echo "$CURRENT_DAY" > "$LAST_CHECK"
    fi
fi

# CRITICAL FILE INTEGRITY 
# Check if critical files have been modified (quick hash check)
CRITICAL_FILES=(
    "/etc/passwd"
    "/etc/shadow"
    "/etc/group"
    "/etc/gshadow"
    "/etc/iptables/rules.v4"
    "/etc/default/grub"
    "/etc/sudoers"
    "/etc/security/access.conf"
    "/usr/lib/sysctl.d/sysctl.conf"  
    "/etc/pam.d/common-auth"
    "/etc/pam.d/sudo" 
    "/etc/security/limits.d/limits.conf"
    "/etc/shells"
    "/etc/securetty”
    "/etc/fstab”
    "/etc/modeprobe.d/harden.conf"
)

CRITICAL_BASELINE="/var/lib/critical-files-baseline"

if [ ! -f "$CRITICAL_BASELINE" ]; then
    log_info "Creating critical files baseline"
    for f in "${CRITICAL_FILES[@]}"; do
        if [ -f "$f" ]; then
            md5sum "$f" >> "$CRITICAL_BASELINE"
        fi
    done
    chmod 600 "$CRITICAL_BASELINE"
    chattr +i "$CRITICAL_BASELINE" 2>/dev/null || true
else
    chattr -i "$CRITICAL_BASELINE" 2>/dev/null || true
    CHANGED_FILES=""
    for f in "${CRITICAL_FILES[@]}"; do
        if [ -f "$f" ]; then
            CURRENT_HASH=$(md5sum "$f" | awk '{print $1}')
            BASELINE_HASH=$(grep "$f" "$CRITICAL_BASELINE" 2>/dev/null | awk '{print $1}')
            if [ -n "$BASELINE_HASH" ] && [ "$CURRENT_HASH" != "$BASELINE_HASH" ]; then
                CHANGED_FILES="$CHANGED_FILES $f"
            fi
        fi
    done
    chattr +i "$CRITICAL_BASELINE" 2>/dev/null || true
    
    if [ -n "$CHANGED_FILES" ]; then
        log_alert "Critical security files modified:$CHANGED_FILES"
        # Don't auto-halt on this - could be legitimate changes
        # But definitely want to know about it
    fi
fi

log_info "Escalation monitor check completed successfully"
EOF

chmod 700 /usr/local/bin/escalation-monitor
chattr +i /usr/local/bin/escalation-monitor

# Use systemd timer instead of cron (since cron is purged)
cat >/etc/systemd/system/escalation-monitor.service <<'EOF'
[Unit]
Description=Escalation Monitor Security Check

[Service]
Type=oneshot
ExecStart=/usr/local/bin/escalation-monitor
EOF

cat >/etc/systemd/system/escalation-monitor.timer <<'EOF'
[Unit]
Description=Run escalation monitor every 30 minutes

[Timer]
OnBootSec=5min
OnUnitActiveSec=30min

[Install]
WantedBy=timers.target
EOF

systemctl daemon-reload
systemctl enable escalation-monitor.timer
systemctl start escalation-monitor.timer

# MAC RANDOMIZE
cat >/etc/systemd/system/macchanger@.service <<'EOF'
[Unit]
Description=MAC Address Randomization for %i
Wants=network-pre.target
Before=network-pre.target
BindsTo=sys-subsystem-net-devices-%i.device
After=sys-subsystem-net-devices-%i.device

[Service]
Type=oneshot
ExecStart=/usr/bin/macchanger -e %i
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOF

systemctl enable macchanger@enp0s31f6.service

# LOCKDOWN
find / -xdev \( -perm -4000 -o -perm -2000 \) -type f -exec chmod a-s {} \; 2>/dev/null || true
chmod u+s /usr/bin/sudo
apt clean
apt autopurge -y
RC_PKGS=$(dpkg -l | grep '^rc' | awk '{print $2}' || true)
[ -n "$RC_PKGS" ] && apt purge -y $RC_PKGS || true

chattr +i /etc/conf 2>/dev/null || true
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
chattr -R +i /etc/host.conf 2>/dev/null || true
chattr +i /etc/hosts 2>/dev/null || true
chattr +i /etc/hosts.allow 2>/dev/null || true
chattr +i /etc/hosts.deny 2>/dev/null || true
chattr -R +i /etc/default 2>/dev/null || true
chattr -R +i /etc/sudoers 2>/dev/null || true
chattr -R +i /etc/sudoers.d 2>/dev/null || true
chattr -R +i /etc/pam.d 2>/dev/null || true
chattr -R +i /usr/lib/pam.d 2>/dev/null || true
chattr -R +i /etc/security 2>/dev/null || true
chattr +i /usr/lib/sysctl.d/sysctl.conf 2>/dev/null || true
chattr -R +i /usr/lib/sysctl.d 2>/dev/null || true
chattr -R +i /etc/sysctl.conf 2>/dev/null || true
chattr -R +i /etc/sysctl.d 2>/dev/null || true
chattr -R +i /etc/modprobe.d 2>/dev/null || true
chattr -R +i /usr/lib/modprobe.d 2>/dev/null || true
chattr -R +i /etc/iptables 2>/dev/null || true
chattr -R +i /etc/profile 2>/dev/null || true
chattr -R +i /etc/profile.d 2>/dev/null || true
chattr -R +i /etc/bash.bashrc 2>/dev/null || true
chattr -R +i /etc/bashrc 2>/dev/null || true
chattr +i /root/.bashrc 2>/dev/null || true
chattr +i /home/dev/.bashrc 2>/dev/null || true
chattr -R +i /etc/cron.allow 2>/dev/null || true
chattr -R +i /etc/at.allow 2>/dev/null || true
chattr -R +i /etc/cron.d 2>/dev/null || true
chattr -R +i /etc/cron.daily 2>/dev/null || true
chattr -R +i /etc/cron.hourly 2>/dev/null || true
chattr -R +i /etc/cron.monthly 2>/dev/null || true
chattr -R +i /etc/cron.weekly 2>/dev/null || true
chattr -R +i /etc/polkit-1 2>/dev/null || true
chattr +i /etc/nsswitch.conf 2>/dev/null || true
chattr +i /etc/ld.so.conf 2>/dev/null || true
chattr -R +i /etc/ld.so.conf.d 2>/dev/null || true
chattr -R +i /lib/modules 2>/dev/null || true
chattr -R +i /etc 2>/dev/null || true
chattr -R +i /usr 2>/dev/null || true
chattr -R +i /boot 2>/dev/null || true 

echo “HARDENING COMPLETE”