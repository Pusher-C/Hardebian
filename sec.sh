#!/bin/bash

#######-DEBIAN-HARDENING-#########

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

# PACKAGE REMOVAL/RESTRICTING
apt purge -y zram* print* rsync* bc wpasupplicant modemmanager xinetd bind9 telnet vsftpd apache2 gcc g++ make cmake perl python3 ruby anacron* pp* perl python3 zram* pci* pmount* cron* avahi* bc bind9* dns* fastfetch fonts-noto* fprint* dhcp* lxc* docker* podman* xen* bochs* uml* vagrant* ssh* openssh* libssh* usb* acpi* samba* winbind* qemu* libvirt* virt* avahi* cup* print* rsync* nftables* virtual* sane* rpc* bind* nfs* blue* spee* espeak* mobile* wireless* inet* util-linux-locales tasksel* vim* os-prober* netcat* gcc g++ gdb lldb strace* ltrace* build-essential automake autoconf libtool cmake ninja-build meson traceroute libavahi* libcup*

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

Package: rpc*
Pin: release *
Pin-Priority: -1

Package: nfs*
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

Package: print*
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

Package: gcc*
Pin: release *
Pin-Priority: -1

Package: g++*
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

# Explicitly DO NOT disable these GNOME-essential services

GNOME_SERVICES=(
"gdm.service"
"gdm3.service"
"accounts-daemon.service"
"colord.service"
"rtkit-daemon.service"
"switcheroo-control.service"
"upower.service"
"power-profiles-daemon.service"
)

for svc in "${GNOME_SERVICES[@]}"; do
systemctl unmask "$svc" 2>/dev/null || true
systemctl enable "$svc" 2>/dev/null || true
done

# APT
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
iptables -A INPUT -j DROP
ip6tables -F
ip6tables -X
ip6tables -Z
ip6tables -P INPUT DROP
ip6tables -P FORWARD DROP
ip6tables -P OUTPUT DROP
iptables-save > /etc/iptables/rules.v4
ip6tables-save > /etc/iptables/rules.v6
netfilter-persistent 

# Block dangerous/unnecessary packages
cat >/etc/apt/preferences.d/denyy.pref << 'EOF'
Package: 7z aa-exec ab agetty aircrack-ng alpine anacron* ansible* aoss apache* ar aria2c arj arp* as ascii-xfr ascii85 ash aspell at atobm autoconf* automake* autopsy awk aws base32 base58 base64 basenc basez batcat bc bconsole beef* bettercap bind* binwalk bochs* bpftrace bridge build-essential build* bundle bundler busctl byebug bzip2 c89 c99 cabal cabal-install cancel capsh cargo cdist certbot check_by_ssh check_cups check_log check_memory check_raid check_ssl_cert check_statusfile choom chroot clam* cmake* cmp cobc column comm composer container* courier* cowsay cowthink cp cpan cpio cpulimit crackmapexec crash crontab csh csplit csvtool curl cut dash date dc dd debugfs dhcp* dialog diff dig dirb distcc dma* dmesg dmidecode dmsetup dnf dns* docker* dos2unix dosbox dotnet* dropbear* dsniff dstat dvips easy_install eb ed efax elixir elvish emacs* enscript enum4linux env eqn erlang ettercap* ex exiftool exim* expand expect facter fastfetch finger fish flatpak flock fmt fold foremost fping ftp gawk gcc gcc* gcloud gcore gdb gdb* gem genie genisoimage ghc ghci ghostscript gimp ginsh gnustep* gobuster golang* grc grep gtester gzip hashcat hd head hexdump highlight hping3 hydra* iconv iftop imagemagick impacket-scripts ionice irb ispell jjs joe john join jq jrunscript jtag julia knife ksh ksshell ksu kubectl latex latexmk ld.so ldconfig lftp libtool libvirt* links lldb lldb* ln loginctl logsave look lp ltrace ltrace* lua* lualatex luatex lwp-download lwp-request lxc* lxd* macchanger mail make maltego man masscan mawk medusa metagoofil metasploit-framework minicom mitmproxy mono-complete more mosquitto msfconsole msgattrib msgcat msgconv msgfilter msgmerge msguniq mtr multitime mysql nano nasm nasm* nawk nbtscan nc ncat ncdu ncftp neofetch netcat* nfs* nft nftables* nice nikto ninja-build nl nm nmap node nodejs* nohup npm* nroff nsenter ntpdate octave od openssh* openssl openstego openvpn openvt opkg os-prober* outguess pandoc paste pax pdb pdflatex pdftex perf perlbug pexec pg php* pic pico pidstat pip pkg pmount* podman* posh postfix* pr proftpd-basic proxychains* pry psftp psql ptx puppet pure-ftpd pwsh qemu* r-base radare2 rake rc readelf recon-ng red redcarpet redis responder restic rev rlogin rlwrap rpc* rpm rpmdb rpmquery rpmverify rsh* rtorrent ruby* run-mailcap run-parts runscript rustc rview rvim sane* sash scanmem scp screen script scrot sed sendmail* service set setarch setfacl setlock sftp sg shuf sleuthkit slsh smb* snap snapd socat social-engineer-toolkit socket soelim softlimit sort spiderfoot split sql* ss ssh* sslstrip start-stop-daemon stdbuf steghide stegosuite strace* strings su systemd-resolve tac tail tar task tasksel* taskset tasksh tbl tcl tclsh tcpdump tdbtool tee telnet* terraform tex tftp* theharvester tic time timedatectl timeout tinyssh* tk tmate tmux top tor* traceroute* tripwire* troff tshark ul uml* unexpand unicornscan uniq unshare unsquashfs update-alternatives uuencode vagrant* valgrind varnishncsa view vigr vim* vimdiff vipw virsh virt* virtual* volatility vsftpd w3m wall watch wc wfuzz wget whiptail whois winbind* wireshark* wish xargs xdg-user-dir xdotool xelatex xen* xetex xmodmap xmore xpad xxd xz yarn yash yasm* yersinia yum zathura zip zmap zram* zsh zsoelim zypper
Pin: release *
Pin-Priority: -1
EOF

# GNOME PACKAGE INSTALLATION
apt install -y gnome-session gdm3 gnome-shell gnome-terminal gnome-control-center gnome-tweaks gnome-system-monitor gnome-text-editor dbus-x11 xdg-utils librewolf gnome-shell-extensions gnome-shell-extension-appindicator gnome-shell-extension-caffeine gnome-shell-extension-user-theme gnome-shell-extension-runcat gnome-shell-extension-dash-to-panel gnome-shell-extension-arc-menu gnome-shell-extension-manager pavucontrol pipewire pipewire-audio-client-libraries pipewire-pulse wireplumber unhide fonts-liberation libxfce4ui-utils xfce4-panel xfce4-session xfce4-settings xfconf xfdesktop4 xfwm4 xserver-xorg xinit xserver-xorg-legacy xfce4-pulseaudio-plugin xfce4-whiskermenu-plugin xfce4-terminal gnome-brave-icon-theme breeze-gtk-theme bibata-cursor-theme gdebi timeshift qt5ct opensnitch* python3-opensnitch* selinux-basics selinux-policy-default

selinux-activate
selinux-config-enforcing

# PAM/U2F
pamu2fcfg -u dev > /etc/security/u2f_keys
chmod 0400 /etc/security/u2f_keys
chown root:root /etc/security/u2f_keys
mkdir -p /var/log/faillock
chmod 0700 /var/log/faillock
rm -f /etc/pam.d/remote
rm -f /etc/pam.d/cron

# Faillock configuration
cat > /etc/security/faillock.conf << 'EOF'
deny = 3
unlock_time = 900
fail_interval = 900
silent
EOF

cat > /etc/pam.d/common-auth << 'EOF'
#%PAM-1.0
auth      required    pam_faildelay.so delay=2000000
auth      required    pam_faillock.so preauth silent deny=5 unlock_time=600 fail_interval=900
auth      [success=1 default=ignore] pam_u2f.so authfile=/etc/security/u2f_keys cue
auth      requisite   pam_deny.so
auth      optional    pam_faillock.so authsucc
EOF

cat > /etc/pam.d/common-account << 'EOF'
#%PAM-1.0
account   required    pam_faillock.so
account   required    pam_unix.so
EOF

cat > /etc/pam.d/common-password << 'EOF'
#%PAM-1.0
password  requisite   pam_deny.so
EOF

cat > /etc/pam.d/common-session << 'EOF'
#%PAM-1.0
session   required    pam_limits.so
session   required    pam_unix.so
session   required    pam_env.so
session   optional    pam_systemd.so
session   optional    pam_umask.so umask=077
session   optional    pam_tmpdir.so
EOF

cat > /etc/pam.d/common-session-noninteractive << 'EOF'
#%PAM-1.0
session   required    pam_limits.so
session   required    pam_unix.so
session   required    pam_env.so
session   optional    pam_systemd.so
session   optional    pam_umask.so umask=077
session   optional    pam_tmpdir.so
EOF

cat > /etc/pam.d/gdm-password << 'EOF'
#%PAM-1.0
auth      requisite   pam_nologin.so
auth      required    pam_faildelay.so delay=2000000
auth      required    pam_faillock.so preauth silent deny=5 unlock_time=600 fail_interval=900
auth      [success=1 default=ignore] pam_u2f.so authfile=/etc/security/u2f_keys cue
auth      requisite   pam_deny.so
auth      optional    pam_gnome_keyring.so
auth      optional    pam_faillock.so authsucc
account   required    pam_faillock.so
account   include     common-account
password  include     common-password
session   required    pam_loginuid.so
session   optional    pam_gnome_keyring.so auto_start
session   include     common-session
EOF

cat > /etc/pam.d/gdm-autologin << 'EOF'
#%PAM-1.0
auth      requisite   pam_nologin.so
auth      optional    pam_gnome_keyring.so
account   include     common-account
password  include     common-password
session   required    pam_loginuid.so
session   optional    pam_gnome_keyring.so auto_start
session   include     common-session
EOF

cat > /etc/pam.d/sudo << 'EOF'
#%PAM-1.0
auth      include     common-auth
account   include     common-account
session   required    pam_limits.so
session   include     common-session
EOF

cat > /etc/pam.d/sudo-i << 'EOF'
#%PAM-1.0
auth      include     common-auth
account   include     common-account
session   required    pam_limits.so
session   include     common-session
EOF

cat > /etc/pam.d/su << 'EOF'
#%PAM-1.0
auth      include     common-auth
account   include     common-account
session   required    pam_limits.so
session   include     common-session
EOF

cat > /etc/pam.d/su-l << 'EOF'
#%PAM-1.0
auth      include     common-auth
account   include     common-account
session   required    pam_limits.so
session   include     common-session
EOF

cat > /etc/pam.d/login << 'EOF'
#%PAM-1.0
auth      requisite   pam_nologin.so
auth      include     common-auth
account   required    pam_access.so
account   include     common-account
session   required    pam_limits.so
session   required    pam_loginuid.so
session   optional    pam_lastlog.so showfailed
session   include     common-session
EOF

cat > /etc/pam.d/chfn << 'EOF'
#%PAM-1.0
auth      sufficient  pam_rootok.so
auth      include     common-auth
account   include     common-account
session   include     common-session
EOF

cat > /etc/pam.d/chsh << 'EOF'
#%PAM-1.0
auth      required    pam_shells.so
auth      sufficient  pam_rootok.so
auth      include     common-auth
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
session   required    pam_limits.so
session   required    pam_unix.so
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

cat > /etc/pam.d/systemd-user << 'EOF'
#%PAM-1.0
account   include     common-account
session   required    pam_limits.so
session   required    pam_unix.so
session   required    pam_env.so user_readenv=0
session   optional    pam_systemd.so
EOF

chmod 644 /etc/pam.d/*
chown root:root /etc/pam.d/*

# SUDO
cat >/etc/sudoers <<'EOF'
Defaults env_reset
Defaults !setenv
Defaults always_set_home
Defaults timestamp_timeout=0
Defaults passwd_timeout=0
Defaults passwd_tries=1
Defaults use_pty
Defaults secure_path="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin"
Defaults logfile="/var/log/sudo.log"
Defaults log_input,log_output
Defaults editor=/bin/false
Defaults !env_editor

dev  ALL=(ALL) /usr/sbin/, /usr/bin/
EOF

chmod 0440 /etc/sudoers
chmod -R 0440 /etc/sudoers.d

# MISC HARDENING
cat >/etc/shells <<'EOF'
/bin/bash
EOF

cat >/etc/host.conf <<'EOF'
multi on
order hosts
EOF

cat >/etc/security/limits.d/limits.conf <<'EOF'
*           hard    nproc         4096
*            -      maxlogins     3
*            -      maxsyslogins  3
dev          -      maxlogins     3
dev          -      maxsyslogins  3
root         -      maxlogins     2
root         -      maxsyslogin   2
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

cat > /etc/security/access.conf << EOF
+:dev:LOCAL
-:dev:ALL EXCEPT LOCAL
-:root:ALL
-:ALL:REMOTE
-:ALL:ALL
EOF
chmod 644 /etc/security/access.conf

# GRUB 
sed -i 's|^GRUB_CMDLINE_LINUX_DEFAULT=.*|GRUB_CMDLINE_LINUX_DEFAULT="quiet mitigations=auto spectre_v2=on spec_store_bypass_disable=on amd_iommu=on iommu=pt init_on_alloc=1 init_on_free=1 page_alloc.shuffle=1 randomize_kstack_offset=on slab_nomerge vsyscall=none debugfs=off oops=panic ipv6.disable=1 processor.max_cstate=1 idle=nomwait"|' /etc/default/grub
update-grub
chown root:root /etc/default/grub
chmod 640 /etc/default/grub

# SYSCTL 
rm -rf /usr/lib/sysctl.d
mkdir -p /usr/lib/sysctl.d
cat > /usr/lib/sysctl.d/sysctl.conf << 'EOF'
kernel.kptr_restrict = 2
kernel.dmesg_restrict = 1
kernel.unprivileged_bpf_disabled = 1
kernel.kexec_load_disabled = 1
kernel.yama.ptrace_scope = 2
kernel.sysrq = 4
kernel.watchdog = 0
kernel.core_uses_pid = 1
kernel.suid_dumpable = 0
kernel.core_pattern = |/bin/false
kernel.io_uring_disabled = 2
kernel.randomize_va_space = 2
kernel.panic_on_oops = 1
kernel.ctrl-alt-del = 0
kernel.acct = 1
kernel.perf_event_paranoid = 3
kernel.perf_cpu_time_max_percent = 1
kernel.perf_event_max_sample_rate = 1
vm.max_map_count = 1048576
vm.mmap_min_addr = 65536
vm.oom_kill_allocating_task = 0
vm.panic_on_oom = 0
vm.overcommit_memory = 1
vm.overcommit_ratio = 50
vm.swappiness = 10
vm.unprivileged_userfaultfd = 0
fs.protected_hardlinks = 1
fs.protected_symlinks = 1
fs.protected_regular = 2
fs.protected_fifos = 2
net.ipv4.icmp_echo_ignore_all = 1
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv4.conf.all.shared_media = 0
net.ipv4.conf.default.shared_media = 0
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_max_syn_backlog = 4096
net.ipv4.tcp_syn_retries = 2
net.ipv4.tcp_synack_retries = 2
net.ipv4.tcp_fin_timeout = 15
net.ipv4.tcp_invalid_ratelimit = 500
net.ipv4.tcp_rfc1337 = 1
net.ipv4.ip_forward = 0
net.ipv6.conf.all.disable_ipv6 = 1
net.ipv6.conf.default.disable_ipv6 = 1
net.ipv6.conf.lo.disable_ipv6 = 1
net.core.netdev_max_backlog = 65535
net.core.somaxconn = 65535
net.core.rmem_max = 16777216
net.core.wmem_max = 16777216
net.core.optmem_max = 65535
net.netfilter.nf_conntrack_max = 2000000
net.netfilter.nf_conntrack_tcp_loose = 0
net.core.bpf_jit_enable = 0
net.core.bpf_jit_harden = 2
kernel.unprivileged_userns_clone = 0
dev.tty.legacy_tiocsti = 0
dev.tty.ldisc_autoload = 0
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

echo "proc     /proc      proc      noatime,nodev,nosuid,noexec,hidepid=2,gid=proc    0 0
tmpfs    /tmp       tmpfs     size=4G,noatime,nodev,nosuid,noexec,mode=1777     0 0
tmpfs    /var/tmp   tmpfs     size=2G,noatime,nodev,nosuid,noexec,mode=1777     0 0
tmpfs    /dev/shm   tmpfs     size=1G,noatime,nodev,nosuid,noexec,mode=1777   0 0
tmpfs    /run       tmpfs     size=1G,noatime,nodev,nosuid,mode=0755          0 0
tmpfs    /home/dev/.cache    tmpfs    size=1G,noatime,nodev,nosuid,noexec,mode=700,uid=1000,gid=1000    0 0" >> /etc/fstab

groupadd -f proc
gpasswd -a root proc

# PERMISSIONS
chmod 700 /root
chown root:root /root
chmod 700 /home/dev
chown dev:dev /home/dev

# Remove world-readable from all files in home
find /home/dev -type f -exec chmod o-rwx {} \; 2>/dev/null || true
find /home/dev -type d -exec chmod o-rwx {} \; 2>/dev/null || true

chmod 600 /etc/shadow
chmod 600 /etc/gshadow
chown root:root /etc/shadow
chown root:root /etc/gshadow
chmod 644 /etc/passwd
chmod 644 /etc/group
chown root:root /etc/passwd
chown root:root /etc/group
chmod 440 /etc/sudoers
chown root:root /etc/sudoers
chmod 750 /etc/sudoers.d
chown root:root /etc/sudoers.d
find /etc/sudoers.d -type f -exec chmod 440 {} \;
chmod 644 /etc/pam.d/*
chown root:root /etc/pam.d/*
chmod 600 /etc/security/access.conf
chmod 600 /etc/security/limits.conf
chmod 600 /etc/security/namespace.conf
chown root:root /etc/security/*
if [[ -d /etc/ssh ]]; then
    chmod 700 /etc/ssh
    chmod 600 /etc/ssh/*_key 2>/dev/null || true
    chmod 644 /etc/ssh/*.pub 2>/dev/null || true
    chmod 644 /etc/ssh/sshd_config 2>/dev/null || true
    chown -R root:root /etc/ssh
fi
chmod 700 /etc/cron.d 2>/dev/null || true
chmod 700 /etc/cron.daily 2>/dev/null || true
chmod 700 /etc/cron.hourly 2>/dev/null || true
chmod 700 /etc/cron.weekly 2>/dev/null || true
chmod 700 /etc/cron.monthly 2>/dev/null || true
chmod 600 /etc/crontab 2>/dev/null || true
if [[ -f /etc/at.deny ]]; then
    chmod 600 /etc/at.deny
fi
chmod 700 /boot
chown root:root /boot
find /boot -type f -name "vmlinuz*" -exec chmod 600 {} \;
find /boot -type f -name "initrd*" -exec chmod 600 {} \;
find /boot -type f -name "System.map*" -exec chmod 600 {} \;
find /boot -type f -name "config-*" -exec chmod 600 {} \;
if [[ -f /boot/grub/grub.cfg ]]; then
    chmod 600 /boot/grub/grub.cfg
    chown root:root /boot/grub/grub.cfg
fi

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

UNOWNED=$(find / -xdev \( -nouser -o -nogroup \) \
    ! -path "/proc/*" \
    ! -path "/sys/*" \
    2>/dev/null || true)

if [[ -n "$UNOWNED" ]]; then
    echo "[!] Found unowned files (review manually):"
    echo "$UNOWNED"
fi
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

rm /usr/bin/run0
rm /usr/bin/su

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
chattr -R +i /usr 2>/dev/null || true
chattr -R +i /boot 2>/dev/null || true 
chattr -R +i /etc 2>/dev/null || true

echo "HARDENING COMPLETE"