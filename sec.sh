#!/bin/bash

set -euo pipefail

###--ULTRA-HARDENING SCRIPT--###

# PRE-CONFIG 
apt install -y extrepo iptables iptables-persistent netfilter-persistent
extrepo enable librewolf
apt modernize-sources
apt update
apt install -y librewolf

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
iptables -N UDP 2>/dev/null || iptables -F UDP
iptables -N TCP 2>/dev/null || iptables -F TCP
iptables -P INPUT DROP
iptables -P FORWARD DROP
iptables -P OUTPUT ACCEPT
iptables -A INPUT -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
iptables -A INPUT -i lo -j ACCEPT
iptables -A INPUT -m conntrack --ctstate INVALID -j DROP
iptables -A INPUT -i wg0 -j ACCEPT
iptables -A INPUT -p udp -m conntrack --ctstate NEW -j UDP
iptables -A INPUT -p tcp --syn -m conntrack --ctstate NEW -j TCP
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

# PACKAGE RESTRICTIONS
apt purge -y zram* pci* pmount* cron* avahi* bc bind9* dns* fastfetch fonts-noto* fprint* dhcp* lxc* docker* podman* xen* bochs* uml* vagrant* ssh* openssh* samba* winbind* qemu* libvirt* virt* avahi* cup* print* rsync* nftables* virtual* sane* rpc* bind* nfs* blue* spee* espeak* mobile* wireless* inet* util-linux-locales tasksel* vim* os-prober* netcat* gcc g++ gdb lldb strace* ltrace* build-essential automake autoconf libtool cmake ninja-build meson 2>/dev/null || true

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

Package: printer*
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

Package: wireless-tools*
Pin: release *
Pin-Priority: -1

Package: inetutils*
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
EOF

# INSTALL PACKAGES
apt install -y apparmor apparmor-utils apparmor-profiles apparmor-profiles-extra pamu2fcfg libpam-u2f rsyslog chrony libpam-tmpdir needrestart acct rkhunter chkrootkit debsums unzip patch alsa-utils pavucontrol pipewire pipewire-audio-client-libraries pipewire-pulse wireplumber lynis macchanger unhide tcpd fonts-liberation opensnitch python3-opensnitch libxfce4ui-utils xfce4-panel xfce4-session xfce4-settings xfce4-terminal xfconf xfdesktop4 xfwm4 xserver-xorg xinit xserver-xorg-legacy xfce4-pulseaudio-plugin xfce4-whiskermenu-plugin timeshift gnome-terminal gnome-brave-icon-theme breeze-gtk-theme bibata-cursor-theme

systemctl enable acct
systemctl start acct
chattr +i /var/log/account/pacct 2>/dev/null || true

systemctl enable apparmor
systemctl start apparmor
aa-enforce /etc/apparmor.d/* 2>/dev/null || true

# AUDITD SETUP
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

# PAM configuration
-w /etc/pam.d -p wa -k pam_config
-w /etc/security -p wa -k security_config

# Privilege escalation binaries
-w /usr/bin/sudo -p x -k privilege_escalation
-w /usr/bin/su -p x -k privilege_escalation
-w /usr/bin/passwd -p x -k privilege_escalation
-w /usr/bin/chsh -p x -k privilege_escalation
-w /usr/bin/chfn -p x -k privilege_escalation
-w /usr/bin/newgrp -p x -k privilege_escalation

# Module loading
-w /sbin/insmod -p x -k module_load
-w /sbin/rmmod -p x -k module_load
-w /sbin/modprobe -p x -k module_load

# Network configuration
-w /etc/hosts -p wa -k network_config
-w /etc/iptables -p wa -k firewall_config

# Root command execution
-a always,exit -F arch=b64 -S execve -F euid=0 -F auid>=1000 -F auid!=4294967295 -k root_commands
-a always,exit -F arch=b32 -S execve -F euid=0 -F auid>=1000 -F auid!=4294967295 -k root_commands

# Make rules immutable (must be last)
-e 2
EOF

chmod 640 /etc/audit/rules.d/privilege-escalation.rules
chown root:root /etc/audit/rules.d/privilege-escalation.rules

# PAM/U2F
pamu2fcfg -u dev > /etc/conf
chmod 400 /etc/conf
chown root:root /etc/conf
chattr +i /etc/conf
mkdir -p /var/log/faillock
chmod 0700 /var/log/faillock
sed -i '1iauth      sufficient  pam_u2f.so authfile=/etc/conf' /usr/lib/pam.d/*
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
auth      sufficient    pam_rootok.so
auth      include       common-auth
account   include       common-account
session   include       common-session
EOF

cat >/etc/pam.d/chpasswd <<'EOF'
#%PAM-1.0
password  include       common-password
EOF

cat >/etc/pam.d/chsh <<'EOF'
#%PAM-1.0
auth      required      pam_shells.so
auth      sufficient    pam_rootok.so
auth      include       common-auth
account   include       common-account
session   include       common-session
EOF

cat > /etc/pam.d/common-auth <<'EOF'
#%PAM-1.0
auth      required      pam_faillock.so preauth deny=3 unlock_time=900
auth      sufficient    pam_u2f.so authfile=/etc/conf
auth      [default=die] pam_faillock.so authfail deny=3 unlock_time=900
auth      requisite     pam_deny.so
EOF

cat >/etc/pam.d/common-account <<'EOF'
#%PAM-1.0
account   required      pam_unix.so
EOF

cat >/etc/pam.d/common-password <<'EOF'
#%PAM-1.0
password  [success=1 default=ignore] pam_unix.so obscure use_authtok try_first_pass yescrypt
password  requisite     pam_deny.so
EOF

cat >/etc/pam.d/common-session <<'EOF'
#%PAM-1.0
session   required      pam_limits.so
session   required      pam_env.so
session   optional      pam_systemd.so
session   optional      pam_umask.so umask=077
session   optional      pam_tmpdir.so
session   required      pam_unix.so
EOF

cat >/etc/pam.d/common-session-noninteractive <<'EOF'
#%PAM-1.0
session   required      pam_limits.so
session   required      pam_env.so
session   optional      pam_systemd.so
session   optional      pam_umask.so umask=077
session   optional      pam_tmpdir.so
session   required      pam_unix.so
EOF

cat >/etc/pam.d/sudo <<'EOF'
#%PAM-1.0
auth      required       pam_faillock.so preauth deny=3 unlock_time=900
auth      sufficient     pam_u2f.so authfile=/etc/conf
auth      [default=die]  pam_faillock.so authfail deny=3 unlock_time=900
auth      requisite      pam_deny.so
account   include        common-account
password  include        common-password
session   include        common-session
EOF

cat >/etc/pam.d/sudo-i <<'EOF'
#%PAM-1.0
auth      required       pam_faillock.so preauth deny=3 unlock_time=900
auth      sufficient     pam_u2f.so authfile=/etc/conf
auth      [default=die]  pam_faillock.so authfail deny=3 unlock_time=900
auth      requisite      pam_deny.so
account   include        common-account
password  include        common-password
session   include        common-session
EOF

cat >/etc/pam.d/su <<'EOF'
#%PAM-1.0
auth      required       pam_faillock.so preauth deny=3 unlock_time=900
auth      sufficient     pam_u2f.so authfile=/etc/conf
auth      [default=die]  pam_faillock.so authfail deny=3 unlock_time=900
auth      requisite      pam_deny.so
account   include        common-account
password  include        common-password
session   include        common-session
EOF

cat >/etc/pam.d/su-l <<'EOF'
#%PAM-1.0
auth      required       pam_faillock.so preauth deny=3 unlock_time=900
auth      sufficient     pam_u2f.so authfile=/etc/conf
auth      [default=die]  pam_faillock.so authfail deny=3 unlock_time=900
auth      requisite      pam_deny.so
account   include        common-account
password  include        common-password
session   include        common-session
EOF

cat >/etc/pam.d/sshd <<'EOF'
#%PAM-1.0
auth      required       pam_deny.so
account   required       pam_deny.so
password  required       pam_deny.so
session   required       pam_deny.so
EOF

cat >/etc/pam.d/other <<'EOF'
#%PAM-1.0
auth      required       pam_deny.so
account   required       pam_deny.so
password  required       pam_deny.so
session   required       pam_deny.so
EOF

cat >/etc/pam.d/login <<'EOF'
#%PAM-1.0
auth      required       pam_faillock.so preauth deny=3 unlock_time=900
auth      sufficient     pam_u2f.so authfile=/etc/conf
auth      [default=die]  pam_faillock.so authfail deny=3 unlock_time=900
auth      requisite      pam_nologin.so
auth      requisite      pam_deny.so
auth      optional       pam_faildelay.so delay=3000000
account   required       pam_access.so
account   include        common-account
password  include        common-password
session   include        common-session
EOF

cat >/etc/pam.d/lightdm <<'EOF'
#%PAM-1.0
auth      required       pam_faillock.so preauth deny=3 unlock_time=900
auth      sufficient     pam_u2f.so authfile=/etc/conf
auth      [default=die]  pam_faillock.so authfail deny=3 unlock_time=900
auth      requisite      pam_nologin.so
auth      requisite      pam_deny.so
account   include        common-account
password  include        common-password
session   include        common-session
EOF

cat >/etc/pam.d/lightdm-greeter <<'EOF'
#%PAM-1.0
auth      required       pam_faillock.so preauth deny=3 unlock_time=900
auth      sufficient     pam_u2f.so authfile=/etc/conf
auth      [default=die]  pam_faillock.so authfail deny=3 unlock_time=900
auth      requisite      pam_nologin.so
auth      requisite      pam_deny.so
account   include        common-account
password  include        common-password
session   include        common-session
EOF

cat >/etc/pam.d/newusers <<'EOF'
#%PAM-1.0
password  include        common-password
EOF

cat >/etc/pam.d/passwd <<'EOF'
#%PAM-1.0
password  include        common-password
EOF

cat >/etc/pam.d/runuser <<'EOF'
#%PAM-1.0
auth      sufficient     pam_rootok.so
session   required       pam_limits.so
session   required       pam_unix.so
EOF

cat >/etc/pam.d/runuser-l <<'EOF'
#%PAM-1.0
auth      include        runuser
session   include        runuser
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
dpkg-reconfigure -f noninteractive xserver-xorg-legacy || true

cat >/etc/host.conf <<'EOF'
multi on
order hosts
EOF

cat >/etc/security/limits.d/limits.conf <<'EOF'
*           hard    core       0
*           hard    nproc      2048
*            -      maxlogins  1
root         -      maxlogins  5
root        hard    nproc      65536
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

cat > /etc/security/access.conf << 'EOF'
+:dev:tty1 tty2 tty3 tty4 tty5 tty6
-:ALL EXCEPT dev:LOCAL
-:dev:ALL EXCEPT LOCAL
-:root:ALL
-:ALL:ALL
EOF

# GRUB
sed -i 's|^GRUB_CMDLINE_LINUX_DEFAULT=.*|GRUB_CMDLINE_LINUX_DEFAULT="slab_nomerge init_on_alloc=1 init_on_free=1 pti=on page_alloc.shuffle=1 debugfs=off kfence.sample_interval=100 efi_pstore.pstore_disable=1 efi=disable_early_pci_dma random.trust_bootloader=off random.trust_cpu=off extra_latent_entropy iommu=force iommu.strict=1 intel_iommu=on amd_iommu=force_isolation vdso32=0 spectre_v2=on spec_store_bypass_disable=on l1tf=full mds=full tsx=off tsx_async_abort=full retbleed=auto gather_data_sampling=force vsyscall=none kvm.nx_huge_pages=force mitigations=auto quiet ipv6.disable=1 loglevel=3 apparmor=1 security=apparmor audit=1 hardened_usercopy=1 lockdown=confidentiality module.sig_enforce=1 oops=panic"|' /etc/default/grub
update-grub
chown root:root /etc/default/grub
chmod 640 /etc/default/grub

# SYCTL
rm -rf /usr/lib/sysctl.d
mkdir -p /usr/lib/sysctl.d
cat > /usr/lib/sysctl.d/sysctl.conf << 'EOF'
dev.tty.ldisc_autoload=0
dev.tty.legacy_tiocsti=0
kernel.io_uring_disabled=2
fs.protected_fifos=2
fs.protected_hardlinks=1
fs.protected_regular=2
fs.protected_symlinks=1
fs.suid_dumpable=0
kernel.core_pattern=|/bin/false
kernel.core_uses_pid=1
kernel.ctrl-alt-del=0
kernel.dmesg_restrict=1
kernel.kexec_load_disabled=1
kernel.kptr_restrict=2
kernel.panic_on_oops=1
kernel.sysrq=0
kernel.perf_cpu_time_max_percent=1
kernel.perf_event_max_sample_rate=1
kernel.perf_event_paranoid=3
kernel.pid_max=65536
kernel.printk=3 3 3 3
kernel.randomize_va_space=2
kernel.unprivileged_bpf_disabled=1
kernel.unprivileged_userns_clone=0
kernel.yama.ptrace_scope=3
kernel.keys.root_maxkeys=1000000
kernel.keys.root_maxbytes=25000000
kernel.watchdog=0
kernel.modules_disabled=0
kernel.acct=1
kernel.cap_last_cap=38
net.core.default_qdisc=fq
net.core.bpf_jit_enable=1
net.core.bpf_jit_harden=2
net.core.netdev_max_backlog=65535
net.core.optmem_max=65535
net.core.rmem_max=6291456
net.core.somaxconn=65535
net.core.wmem_max=6291456
net.ipv4.icmp_echo_ignore_all=1
net.ipv4.icmp_echo_ignore_broadcasts=1
net.ipv4.icmp_ignore_bogus_error_responses=1
net.ipv4.ip_forward=0
net.ipv4.tcp_max_syn_backlog=4096
net.ipv4.tcp_synack_retries=2
net.ipv4.tcp_syn_retries=2
net.ipv4.tcp_abort_on_overflow=1
net.ipv4.tcp_fin_timeout=15
net.ipv4.tcp_orphan_retries=2
net.ipv4.tcp_rfc1337=1
net.ipv4.tcp_syncookies=1
net.ipv4.tcp_tw_reuse=1
net.ipv4.conf.all.accept_redirects=0
net.ipv4.conf.all.accept_source_route=0
net.ipv4.conf.all.log_martians=0
net.ipv4.conf.all.rp_filter=1
net.ipv4.conf.all.secure_redirects=0
net.ipv4.conf.all.send_redirects=0
net.ipv4.conf.all.shared_media=0
net.ipv4.conf.default.accept_redirects=0
net.ipv4.conf.default.accept_source_route=0
net.ipv4.conf.default.log_martians=0
net.ipv4.conf.default.rp_filter=1
net.ipv4.conf.default.secure_redirects=0
net.ipv4.conf.default.send_redirects=0
net.ipv4.conf.default.shared_media=0
net.ipv4.tcp_challenge_ack_limit=2147483647
net.ipv4.tcp_invalid_ratelimit=500
net.ipv6.conf.all.disable_ipv6=1
net.ipv6.conf.default.disable_ipv6=1
net.ipv6.conf.lo.disable_ipv6=1
net.netfilter.nf_conntrack_max=2000000
net.netfilter.nf_conntrack_tcp_loose=0
vm.unprivileged_userfaultfd=0
vm.mmap_min_addr=65536
vm.max_map_count=1048576
vm.swappiness=1
vm.overcommit_memory=1
vm.panic_on_oom=1
vm.oom_kill_allocating_task=1
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
EOF

# MOUNTS
cp /etc/fstab /etc/fstab.bak
BOOT_LINE=$(grep -E '^\s*UUID=.*\s+/boot\s+' /etc/fstab || echo "")
BOOT_EFI_LINE=$(grep -E '^\s*UUID=.*\s+/boot/efi\s+' /etc/fstab || echo "")

cat > /etc/fstab << 'EOF'
/dev/mapper/lvg-root              /                   ext4       noatime,nodev,errors=remount-ro 0 1
/dev/mapper/lvg-usr               /usr                ext4       noatime,nodev,ro 0 2
/dev/mapper/lvg-opt               /opt                ext4       noatime,nodev,nosuid,noexec 0 2
/dev/mapper/lvg-home              /home               ext4       noatime,nodev,nosuid,noexec 0 2
/dev/mapper/lvg-var               /var                ext4       noatime,nodev,nosuid 0 2
/dev/mapper/lvg-var--log          /var/log            ext4       noatime,nodev,nosuid,noexec 0 2
/dev/mapper/lvg-var--log--audit   /var/log/audit      ext4       noatime,nodev,nosuid,noexec 0 2
proc                              /proc               proc       noatime,nodev,nosuid,noexec,hidepid=2,gid=proc 0 0
sysfs                             /sys                sysfs      nodev,nosuid,noexec 0 0
udev                              /dev                devtmpfs   nosuid,mode=0755 0 0
tmpfs                             /tmp                tmpfs      size=2G,noatime,nodev,nosuid,noexec,mode=1777 0 0
tmpfs                             /var/tmp            tmpfs      size=1G,noatime,nodev,nosuid,noexec,mode=1777 0 0
tmpfs                             /dev/shm            tmpfs      size=512M,noatime,nodev,nosuid,noexec,mode=1777 0 0
tmpfs                             /run                tmpfs      size=512M,noatime,nodev,nosuid,mode=0755 0 0
tmpfs                             /home/dev/.cache    tmpfs      size=1G,noatime,nodev,nosuid,noexec,mode=700,uid=1000,gid=1000 0 0
EOF

if [ -n "$BOOT_LINE" ]; then
    BOOT_UUID=$(echo "$BOOT_LINE" | grep -oP 'UUID=[A-Za-z0-9-]+')
    echo "${BOOT_UUID}    /boot    ext4    noatime,nodev,nosuid,noexec,ro 0 2" >> /etc/fstab
fi
if [ -n "$BOOT_EFI_LINE" ]; then
    BOOT_EFI_UUID=$(echo "$BOOT_EFI_LINE" | grep -oP 'UUID=[A-Za-z0-9-]+')
    echo "${BOOT_EFI_UUID}    /boot/efi    vfat    noatime,nodev,nosuid,noexec,umask=0077,ro 0 2" >> /etc/fstab
fi
groupadd -f proc
gpasswd -a root proc

# FILE/DIRECTORY PERMISSIONS
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

# OPENSNITCH CONFIGURATION
systemctl enable opensnitch
systemctl start opensnitch
git clone --depth 1 https://github.com/DXC-0/Respect-My-Internet.git
cd Respect-My-Internet
chmod +x install.sh
./install.sh
systemctl restart opensnitch
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

# KERNEL MODULE LOCKDOWN SERVICE
cat >/etc/systemd/system/lock-modules.service <<'EOF'
[Unit]
Description=Disable kernel module loading
After=multi-user.target
After=graphical.target
After=opensnitch.service

[Service]
Type=oneshot
ExecStart=/bin/bash -c 'echo 1 > /proc/sys/kernel/modules_disabled'
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable lock-modules.service

# ESCALATION HARDENING
cat > /usr/local/bin/escalation-monitor <<'EOF'
#!/bin/bash
# Detects privilege escalation attempts and self-destructs system

LOG="/var/log/escalation-monitor.log"
HALT_ON_VIOLATION=1

log_alert() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] ALERT: $1" >> "$LOG"
    logger -t ESCALATION_MONITOR -p security.crit "$1"
}

# Check for unauthorized SUID/SGID bits
SUID_FILES=$(find / -xdev \( -perm -4000 -o -perm -2000 \) 2>/dev/null | wc -l)
EXPECTED_SUID=3

if [ "$SUID_FILES" -gt "$EXPECTED_SUID" ]; then
    log_alert "Unauthorized SUID files detected: $SUID_FILES (expected $EXPECTED_SUID)"
    find / -xdev \( -perm -4000 -o -perm -2000 \) 2>/dev/null >> "$LOG"
    if [ $HALT_ON_VIOLATION -eq 1 ]; then
        systemctl halt
    fi
fi

# Check for kernel module tampering
if [ -f /var/lib/modules-baseline ]; then
    if ! find /lib/modules -name "*.ko" -type f -exec md5sum {} \; | diff -q - /var/lib/modules-baseline >/dev/null 2>&1; then
        log_alert "Kernel modules have been modified"
        if [ $HALT_ON_VIOLATION -eq 1 ]; then
            systemctl halt
        fi
    fi
fi

# Check for rootkit signatures
if command -v rkhunter >/dev/null 2>&1; then
    rkhunter --check --skip-keypress --report-warnings-only >> "$LOG" 2>&1 || true
fi

# Check for suspicious processes
if grep -q "pam_u2f.*failure" /var/log/auth.log 2>/dev/null; then
    RECENT_FAILS=$(grep "pam_u2f.*failure" /var/log/auth.log | tail -5)
    FAIL_COUNT=$(echo "$RECENT_FAILS" | wc -l)
    if [ "$FAIL_COUNT" -ge 3 ]; then
        log_alert "Multiple U2F authentication failures detected ($FAIL_COUNT)"
    fi
fi

# Check for privilege escalation syscall attempts
if journalctl -u auditd --no-pager 2>/dev/null | grep -E "syscall=(2|22|36|39|49|56|234|235)" >/dev/null 2>&1; then
    log_alert "Suspicious privilege escalation syscall detected"
fi
EOF

chmod 700 /usr/local/bin/escalation-monitor
chattr +i /usr/local/bin/escalation-monitor

# Baseline kernel modules
find /lib/modules -name "*.ko" -type f -exec md5sum {} \; > /var/lib/modules-baseline 2>/dev/null || true
chattr +i /var/lib/modules-baseline

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

# CLEANUP
ln -sf /bin/bash /bin/sh
# Remove other unused shells
rm -f /bin/csh /bin/ksh /bin/zsh 2>/dev/null || true

# Lock down package managers at runtime
# chmod 000 /usr/bin/apt /usr/bin/apt-get /usr/bin/dpkg /usr/bin/snap 2>/dev/null || true

# Remove documentation (information disclosure)
rm -rf /usr/share/man/* /usr/share/doc/* 2>/dev/null || true

# Remove locale data
rm -rf /usr/share/locale/* 2>/dev/null || true

# Remove static libraries
find /usr/lib -name "*.a" -delete 2>/dev/null || true
find /usr/lib -name "*.la" -delete 2>/dev/null || true

# LOCKDOWN
find / -xdev \( -perm -4000 -o -perm -2000 \) -type f -exec chmod a-s {} \; 2>/dev/null || true
chmod u+s /usr/bin/sudo
apt clean
apt autopurge -y
RC_PKGS=$(dpkg -l | grep '^rc' | awk '{print $2}' || true)
[ -n "$RC_PKGS" ] && apt purge -y $RC_PKGS || true

# Critical auth files
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

# Config files
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

# PAM
chattr -R +i /etc/pam.d 2>/dev/null || true
chattr -R +i /usr/lib/pam.d 2>/dev/null || true
chattr -R +i /etc/security 2>/dev/null || true

# Sysctl and modules
chattr +i /usr/lib/sysctl.d/sysctl.conf 2>/dev/null || true
chattr -R +i /usr/lib/sysctl.d 2>/dev/null || true
chattr -R +i /etc/sysctl.conf 2>/dev/null || true
chattr -R +i /etc/sysctl.d 2>/dev/null || true
chattr -R +i /etc/modprobe.d 2>/dev/null || true
chattr -R +i /usr/lib/modprobe.d 2>/dev/null || true

# Firewall
chattr -R +i /etc/iptables 2>/dev/null || true

# Shell configs
chattr -R +i /etc/profile 2>/dev/null || true
chattr -R +i /etc/profile.d 2>/dev/null || true
chattr -R +i /etc/bash.bashrc 2>/dev/null || true
chattr -R +i /etc/bashrc 2>/dev/null || true
chattr +i /root/.bashrc 2>/dev/null || true
chattr +i /home/dev/.bashrc 2>/dev/null || true

# Cron/at (if any remain)
chattr -R +i /etc/cron.allow 2>/dev/null || true
chattr -R +i /etc/at.allow 2>/dev/null || true
chattr -R +i /etc/cron.d 2>/dev/null || true
chattr -R +i /etc/cron.daily 2>/dev/null || true
chattr -R +i /etc/cron.hourly 2>/dev/null || true
chattr -R +i /etc/cron.monthly 2>/dev/null || true
chattr -R +i /etc/cron.weekly 2>/dev/null || true

# Polkit and name resolution
chattr -R +i /etc/polkit-1 2>/dev/null || true
chattr +i /etc/nsswitch.conf 2>/dev/null || true
chattr +i /etc/ld.so.conf 2>/dev/null || true
chattr -R +i /etc/ld.so.conf.d 2>/dev/null || true

# NOTE: /etc/resolv.conf left mutable for DHCP/VPN updates
# NOTE: /etc and /usr blanket immutable removed - too aggressive
# Apply these manually after testing if desired:
# chattr -R +i /usr 2>/dev/null || true
# chattr -R +i /lib/modules 2>/dev/null || true
# chattr -R +i /boot 2>/dev/null || true

echo "HARDENING SCRIPT COMPLETE"
