#!/bin/bash

#######-DEBIAN-HARDENING-#########

set -euo pipefail

# PRE-CONFIG

apt install -y extrepo iptables iptables-persistent netfilter-persistent --no-install-recommends
extrepo enable librewolf --no-install-recommends
apt update
apt install -y librewolf


# PACKAGE DENY LIST
install -d /etc/apt/preferences.d

# Offensive / pentest tools
cat > /etc/apt/preferences.d/10-deny-offensive.pref << 'EOF'
Package: aircrack-ng* autopsy* beef-xss* bettercap* binwalk* burpsuite* crackmapexec* dirb* dsniff* enum4linux* ettercap* ettercap-common* ettercap-graphical* foremost* fping* gobuster* hashcat* hping3* hydra* hydra-gtk* impacket* impacket-scripts* john* macchanger* maltego* masscan* medusa* metagoofil* metasploit* metasploit-framework* mitmproxy* nbtscan* nikto* nmap* opensteg* openstego* outguess* radare2* recon-ng* responder* scalpel* scapy* sleuthkit* smbclient* smbmap* social-engineer* social-engineer-toolkit* spiderfoot* sqlmap* sslstrip* steghide* stegosuite* theharvester* tshark* unicornscan* volatility* wfuzz* wireshark* wireshark-gtk* wireshark-qt* yersinia* zenmap* zmap*
Pin: release *
Pin-Priority: -1
EOF

# Remote access / network services
cat > /etc/apt/preferences.d/20-deny-remote.pref << 'EOF'
Package: openssh* dropbear* tinyssh* telnet* telnetd* rsh* rsh-client* rsh-redone-client* rlogin* x11vnc* xrdp* tigervnc* openvpn* proxychains* proxychains4* apache2* nginx* lighttpd* proftpd* proftpd-basic* vsftpd* pure-ftpd* postfix* sendmail* exim4* courier* xinetd* webmin* cockpit* mosquitto*
Pin: release *
Pin-Priority: -1
EOF

# Dev toolchains / compilers / interpreters
cat > /etc/apt/preferences.d/30-deny-dev.pref << 'EOF'
Package: build-essential* gcc* g++* gfortran* gdb* binutils* autoconf* automake* bison* flex* cmake* make* m4* libtool* clang* llvm* lldb* nasm* cargo* rustc* golang* golang-go* default-jdk* default-jre* nodejs* npm* ruby* ruby-full* perl* php* php-cli* php-common* lua* luajit* python-is-python3* pip* cabal* cabal-install* ghc* fpc* erlang* elixir* julia* mono-complete* dotnet* dotnet-sdk-6.0* dotnet-sdk-7.0* dotnet-sdk-8.0* r-base* octave* meson* ninja-build* swig* cpan* composer*
Pin: release *
Pin-Priority: -1
EOF

# Containers / VMs / orchestration
cat > /etc/apt/preferences.d/40-deny-containers.pref << 'EOF'
Package: docker* docker-ce* docker-ce-cli* docker.io* podman* containerd.io* lxc* lxd* lxd-client* qemu* libvirt* vbox* vagrant* snap* snapd* flatpak* kubernetes* kubectl* ansible* chef* puppet* salt-minion* salt-common* terraform*
Pin: release *
Pin-Priority: -1
EOF

# Unwanted network/system tools
cat > /etc/apt/preferences.d/50-deny-network.pref << 'EOF'
Package: avahi* bind9* bluetooth* bluez* cups* dhcpcd* fprint* libfprint* nfs-common* nfs-kernel-server* nftables* rpcbind* rsync* samba* smbd* snmpd* snmptrapd* socat* strace* tcpdump* tftp* tftp-hpa* traceroute* tor* torsocks* wpa-supplicant* wpasupplicant* iw*
Pin: release *
Pin-Priority: -1
EOF

# Unwanted desktop / misc
cat > /etc/apt/preferences.d/60-deny-misc.pref << 'EOF'
Package: anacron* alpine* emacs* espeak* fastfetch* fortune* cowsay* gimp* imagemagick* neofetch* screen* tmux* vim* open-vm-tools* unattended-upgrades* valgrind* bochs* dosbox* spice-vdagent*
Pin: release *
Pin-Priority: -1
EOF

chmod 644 /etc/apt/preferences.d/*.pref

# SERVICES
DISABLE=(
    # Remote access / network services
    "ssh.service" "ssh.socket" "sshd.service"
    "telnet.socket"
    "inetd.service" "xinetd.service"
    "rpcbind.service" "rpcbind.socket" "rpcbind.target"
    "nfs-blkmap.service" "nfs-client.target" "nfs-common.service"
    "nfs-idmapd.service" "nfs-mountd.service" "nfs-server.service"
    "postfix.service" "sendmail.service" "exim4.service"
    "proftpd.service" "vsftpd.service" "pure-ftpd.service"
    "samba.service" "samba-ad-dc.service" "smbd.service" "nmbd.service" "winbind.service"
    "rsync.service"
    "webmin.service"
    "cockpit.service" "cockpit.socket"
    # VNC / RDP / remote desktop
    "x11vnc.service" "xrdp.service" "xrdp.socket" "xrdp-sesman.service"
    "tigervnc.service" "vino-server.service" "gnome-remote-desktop.service"
    # Display managers / GNOME
    "gdm3.service" "gnome-software-service.service"
    # Containers / VMs
    "containerd.service"
    "docker.service" "docker.socket"
    "podman.service" "podman.socket"
    "lxc.service" "lxc-net.service" "lxd.service" "lxd.socket"
    "libvirtd.service" "libvirtd.socket" "libvirtd-admin.socket" "libvirtd-ro.socket"
    "libvirt-guests.service"
    "virtlockd.service" "virtlockd.socket" "virtlogd.service" "virtlogd.socket"
    "qemu-guest-agent.service"
    "machines.target"
    "systemd-nspawn@.service"
    # VirtualBox / VMware / Hyper-V / SPICE
    "vboxadd.service" "vboxadd-service.service" "vboxautostart-service.service"
    "vboxballoonctrl-service.service" "vboxdrv.service" "vboxweb-service.service"
    "vmtoolsd.service" "vmware-tools.service" "vmware-vmblock-fuse.service"
    "open-vm-tools.service"
    "hv-fcopy-daemon.service" "hv-kvp-daemon.service" "hv-vss-daemon.service"
    "hyperv-daemons.service"
    "spice-vdagentd.service" "spice-vdagentd.socket"
    # Bluetooth / wireless / hardware
    "bluetooth.service" "bluetooth.target"
    "ModemManager.service"
    "wpa_supplicant.service"
    "bolt.service"
    "brltty.service"
    "fprintd.service"
    "fwupd.service" "fwupd-refresh.timer"
    "iio-sensor-proxy.service"
    "pcscd.socket"
    "usb-gadget.target" "usbip.service" "usbipd.service"
    "usbmuxd.service" "usbmuxd.socket"
    # Scheduling / maintenance timers
    "anacron.service" "anacron.timer"
    "cron.service"
    "apt-daily.timer" "apt-daily-upgrade.timer"
    "e2scrub_all.timer"
    "man-db.timer"
    "motd-news.timer"
    "unattended-upgrades.service"
    # Cloud / orchestration
    "cloud-init.service" "cloud-init-local.service"
    "cloud-config.service" "cloud-final.service" "cloud-init.target"
    "chef-client.service" "puppet.service" "salt-minion.service"
    "multipassd.service"
    # Storage
    "iscsi.service" "iscsid.service" "iscsid.socket" "open-iscsi.service"
    "lvm2-lvmpolld.service" "lvm2-lvmpolld.socket"
    "multipathd.service"
    "nvmefc-boot-connections.service" "nvmf-autoconnect.service"
    "rbdmap.service"
    "remote-cryptsetup.target" "remote-fs-pre.target" "remote-fs.target"
    # SSSD
    "sssd.service" "sssd.socket"
    "sssd-autofs.socket" "sssd-kcm.socket" "sssd-nss.socket"
    "sssd-pac.socket" "sssd-pam.socket" "sssd-ssh.socket" "sssd-sudo.socket"
    # Auth services
    "krb5-admin-server.service" "krb5-kdc.service"
    "nscd.service" "nslcd.service"
    # SNMP
    "snmpd.service" "snmptrapd.service"
    # Desktop / misc
    "accounts-daemon.service"
    "rtkit-daemon.service"
    "apport.service"
    "avahi-daemon.service" "avahi-daemon.socket"
    "colord.service"
    "cups-browsed.service" "cups.path" "cups.service" "cups.socket"
    "debug-shell.service"
    "geoclue.service"
    "console-getty.service" "getty@ttyS0.service"
    "serial-getty@.service"
    "kerneloops.service"
    "packagekit.service"
    "power-profiles-daemon.service"
    "printer.target"
    "snapd.seeded.service" "snapd.service" "snapd.socket"
    "speech-dispatcher.service"
    "switcheroo-control.service"
    "tracker-extract-3.service" "tracker-miner-fs-3.service"
    "tracker-miner-rss-3.service" "tracker-writeback-3.service"
    "udisks2.service"
    "upower.service"
    "whoopsie.service"
    # Systemd hardening
    "ctrl-alt-del.target"
    "kexec.target" "systemd-kexec.service"
    "proc-sys-fs-binfmt_misc.automount" "proc-sys-fs-binfmt_misc.mount"
    "systemd-binfmt.service"
    "systemd-coredump.socket"
    "systemd-journal-gatewayd.socket" "systemd-journal-remote.socket"
    "systemd-journal-upload.service"
)

for svc in "${DISABLE[@]}"; do
    systemctl stop "$svc" 2>/dev/null || true
    systemctl mask "$svc" 2>/dev/null || true
done

# PACKAGE REMOVAL
REMOVE=(
    # GNOME desktop (replaced by LXQt)
    "gnome-session" "gnome-shell" "gnome-control-center" "gnome-tweaks"
    "gnome-system-monitor" "gnome-settings-daemon" "gnome-shell-extensions"
    "gnome-shell-extension-appindicator" "gnome-shell-extension-caffeine"
    "gnome-shell-extension-manager" "gnome-software" "gnome-remote-desktop"
    "mutter" "mutter-common" "network-manager-gnome"
    "xdg-desktop-portal-gnome" "dbus-x11" "gdm3"
    # Offensive / pentest tools
    "aircrack-ng" "autopsy" "beef-xss" "bettercap" "binwalk" "burpsuite"
    "crackmapexec" "dirb" "dsniff" "enum4linux" "ettercap*" "execstack"
    "exiftool" "foremost" "fping" "ghidra" "gobuster" "hashcat"
    "hping3" "hydra" "hydra-gtk" "impacket-scripts" "john"
    "macchanger" "maltego" "masscan" "medusa" "metagoofil"
    "metasploit-framework" "mitmproxy" "nbtscan" "nikto" "nmap"
    "openstego" "outguess" "radare2" "recon-ng" "responder"
    "scalpel" "scapy" "sleuthkit" "smbmap" "spiderfoot" "sqlmap"
    "steghide" "stegosuite" "theharvester" "tshark" "unicornscan"
    "wfuzz" "wireshark*" "yersinia" "zenmap" "zmap"
    # Remote access / network services
    "openssh-server" "openssh-client" "dropbear*" "tinyssh*" "telnet*"
    "rsh-client" "rsh-redone-client" "rlogin" "x11vnc" "xrdp*"
    "tigervnc*" "openvpn" "proftpd*" "vsftpd" "pure-ftpd"
    "apache2*" "nginx*" "lighttpd*" "postfix*" "sendmail*"
    "exim4*" "courier*" "xinetd" "webmin"
    # Dev toolchains
    "build-essential" "gcc*" "g++*" "gdb*" "binutils" "autoconf"
    "automake" "bison" "flex" "cmake*" "make" "m4" "libtool"
    "clang" "llvm" "lldb*" "nasm" "cargo*" "rustc" "golang*"
    "default-jdk" "default-jre" "nodejs*" "npm*" "ruby*" "perl"
    "php*" "lua*" "python-is-python3" "pip" "pip3" "cabal-install"
    "ghc*" "fpc" "erlang" "elixir" "julia" "mono-complete" "dotnet*"
    "octave" "r-base" "swig" "meson*" "ninja-build"
    # Containers / VMs
    "docker*" "podman*" "containerd*" "lxc*" "lxd*" "qemu*"
    "libvirt*" "vbox*" "snap*" "snapd" "flatpak*" "vagrant*"
    # Misc unwanted
    "anacron" "avahi*" "libavahi*" "bind9*" "cockpit*" "cron*"
    "cups*" "libcup*" "dhcpcd*" "emacs*" "espeak*" "fastfetch*"
    "fortune*" "cowsay*" "gimp*" "imagemagick*" "mosquitto*"
    "neofetch*" "nfs-common" "rpcbind" "rsync" "samba*" "smbd"
    "snmpd*" "socat" "strace" "tmux" "tor*" "traceroute"
    "unattended-upgrades" "valgrind*" "vim*" "wpa-supplicant"
    "bluetooth*" "bluez*" "modemmanager" "open-vm-tools"
    "patchelf" "prelink" "upx" "texlive-base" "texlive-latex-base"
    "fprint*" "libfprint*" "puppet*" "chef*" "ansible*" "salt-minion"
)

apt purge -y "${REMOVE[@]}" 2>/dev/null || true
apt-get autopurge -y
apt-get autoclean -y

# APT HARDENING

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
netfilter-persistent savesave

# PACKAGE INSTALLATION
apt install -y rsyslog labwc swaybg foot lxqt-core pcmanfm-qt lxqt-archiver network-manager nm-tray dbus-user-session xdg-desktop-portal xdg-desktop-portal-wlr xdg-utils layer-shell-qt wayland-protocols xwayland qt6-wayland qtwayland5 featherpad libpam-tmpdir pipewire pipewire-pulse wireplumber adwaita-icon-theme bibata-cursor-theme gdebi-core mesa-vulkan-drivers mesa-va-drivers firmware-amd-graphics qt6ct opensnitch python3-opensnitch-ui --no-install-recommends

mkdir -p ~/.local/bin
cat > ~/.local/bin/start-wayland << 'EOF'
#!/bin/bash
export XDG_SESSION_TYPE=wayland
export XDG_CURRENT_DESKTOP=LXQt
export XDG_SESSION_DESKTOP=LXQt
export QT_QPA_PLATFORM=wayland
export QT_QPA_PLATFORMTHEME=lxqt
export MOZ_ENABLE_WAYLAND=1

exec dbus-run-session -- labwc -s lxqt-session
EOF

chmod +x ~/.local/bin/start-wayland

apt install extrepo
extrepo enable librewolf
apt update
apt install -y librewolf --no-install-recommends

# ACCOUNTS/GROUPS
for grp in _ssh bluetooth fax floppy irc kvm voice games; do
    groupdel "$grp" --force 2>/dev/null || true
done

for usr in nobody games irc uucp proxy dhcpcd list news sync man mail lp www-data; do
    userdel "$usr" 2>/dev/null || true
done

for grp in render input video audio tty; do
    adduser dev "$grp" 2>/dev/null || true
done

# USER AUDIT
echo "Accounts with UID 0:" && awk -F: '($3 == 0) {print $1}' /etc/passwd
echo "Duplicate UIDs:" && cut -d: -f3 /etc/passwd | sort | uniq -d
echo "Missing 'x' placeholders:" && awk -F: '$2 != "x" {print $1}' /etc/passwd
awk -F: '($2 == "" ) {print "CRITICAL: Empty password for " $1}' /etc/shadow
awk -F: '($2 ~ /^\$/ && length($2) < 20) {print "WARNING: Weak hash for " $1}' /etc/shadow
find /home -name "authorized_keys" -print -delete 2>/dev/null || true

while IFS= read -r user; do
    usermod -s /usr/sbin/nologin "$user"
done < <(awk -F: -v current_user="dev" '($3 >= 1000 && $1 != current_user && $7 != "/usr/sbin/nologin" && $7 != "/bin/false") {print $1}' /etc/passwd)

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
+:root:LOCAL
-:root:ALL EXCEPT LOCAL
-:ALL:REMOTE
-:ALL:ALL
EOF
chmod 644 /etc/security/access.conf

# GRUB

sed -i 's|^GRUB_CMDLINE_LINUX_DEFAULT=.*|GRUB_CMDLINE_LINUX_DEFAULT="quiet splash mitigations=auto spectre_v2=on spec_store_bypass_disable=on amd_iommu=on iommu=pt init_on_alloc=1 init_on_free=1 page_alloc.shuffle=1 randomize_kstack_offset=on slab_nomerge vsyscall=none debugfs=off oops=panic ipv6.disable=1 processor.max_cstate=1 idle=nomwait amd_pstate=passive"|' /etc/default/grub
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
blacklist udf
install udf /bin/false
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
tmpfs    /tmp       tmpfs     size=8G,noatime,nodev,nosuid,noexec,mode=1777     0 0
tmpfs    /var/tmp   tmpfs     size=4G,noatime,nodev,nosuid,noexec,mode=1777     0 0
tmpfs    /dev/shm   tmpfs     size=2G,noatime,nodev,nosuid,noexec,mode=1777   0 0
tmpfs    /run       tmpfs     size=2G,noatime,nodev,nosuid,mode=0755          0 0
tmpfs    /home/dev/.cache    tmpfs    size=2G,noatime,nodev,nosuid,noexec,mode=700,uid=1000,gid=1000    0 0" >> /etc/fstab

groupadd -f proc
gpasswd -a root proc

# PERMISSIONS

chmod 700 /root
chown root:root /root
chmod 700 /home/dev
chown dev:dev /home/dev

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

mkdir -p /etc/opensnitchd/rules
chmod 750 /etc/opensnitchd
chmod 750 /etc/opensnitchd/rules
touch /var/log/opensnitchd.log
chmod 640 /var/log/opensnitchd.log

systemctl daemon-reload
systemctl enable opensnitchd.service
systemctl start opensnitchd.service

apt install git 
git clone --depth 1 https://github.com/DXC-0/Respect-My-Internet.git
cd Respect-My-Internet
chmod +x install.sh
./install.sh
systemctl restart opensnitchd
cd

# POLKIT

mkdir -p /etc/polkit-1/rules.d
cat > /etc/polkit-1/rules.d/50-gnome-allow.rules << 'EOF'
polkit.addRule(function(action, subject) {
if (subject.user == "dev") {
if (action.id == "org.freedesktop.login1.suspend" ||
action.id == "org.freedesktop.login1.hibernate" ||
action.id == "org.freedesktop.login1.reboot" ||
action.id == "org.freedesktop.login1.power-off" ||
action.id == "org.freedesktop.NetworkManager.network-control" ||
action.id == "org.freedesktop.NetworkManager.settings.modify.system" ||
action.id == "org.freedesktop.NetworkManager.enable-disable-network" ||
action.id == "org.freedesktop.NetworkManager.enable-disable-wifi" ||
action.id == "org.freedesktop.ModemManager1.Device.Control" ||
action.id == "org.freedesktop.timedate1.set-time" ||
action.id == "org.freedesktop.timedate1.set-timezone" ||
action.id == "org.freedesktop.locale1.set-locale" ||
action.id == "org.freedesktop.hostname1.set-static-hostname" ||
action.id == "org.freedesktop.hostname1.set-hostname" ||
action.id == "org.freedesktop.Accounts.UserAdministration" ||
action.id.indexOf("org.gnome.controlcenter") == 0 ||
action.id.indexOf("org.freedesktop.color") == 0) {
return polkit.Result.YES;
}
}
return polkit.Result.NO;
});
EOF

chmod 0644 /etc/polkit-1/rules.d/50-gnome-allow.rules

# PRIVILEGE ESCALATION HARDENING

echo "" > /etc/securetty
chmod 600 /etc/securetty

echo "dev" > /etc/cron.allow
echo "dev" > /etc/at.allow
chmod 600 /etc/cron.allow
chmod 600 /etc/at.allow
echo "" > /etc/cron.deny 2>/dev/null || true
echo "" > /etc/at.deny 2>/dev/null || true

rm -f /usr/bin/run0 2>/dev/null || true
rm -f /usr/bin/su 2>/dev/null || true

# LOCKDOWN

find / -xdev \( -perm -4000 -o -perm -2000 \) -type f -exec chmod a-s {} \; 2>/dev/null || true
chmod u+s /usr/bin/sudo

apt clean
apt autopurge -y
RC_PKGS=$(dpkg -l | grep '^rc' | awk '{print $2}' || true)
if [ -n "$RC_PKGS" ]; then
apt purge -y $RC_PKGS 2>/dev/null || true
fi

# IMMUTABLE FLAGS

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
chattr +i /etc/host.conf 2>/dev/null || true
chattr +i /etc/hosts 2>/dev/null || true
chattr +i /etc/hosts.allow 2>/dev/null || true
chattr +i /etc/hosts.deny 2>/dev/null || true
chattr -R +i /etc/default 2>/dev/null || true
chattr -R +i /etc/sudoers 2>/dev/null || true
chattr -R +i /etc/sudoers.d 2>/dev/null || true
chattr -R +i /etc/pam.d 2>/dev/null || true
chattr -R +i /etc/security 2>/dev/null || true
chattr +i /usr/lib/sysctl.d/sysctl.conf 2>/dev/null || true
chattr -R +i /usr/lib/sysctl.d 2>/dev/null || true
chattr -R +i /etc/sysctl.conf 2>/dev/null || true
chattr -R +i /etc/sysctl.d 2>/dev/null || true
chattr -R +i /etc/modprobe.d 2>/dev/null || true
chattr -R +i /etc/iptables 2>/dev/null || true
chattr -R +i /etc/profile 2>/dev/null || true
chattr -R +i /etc/profile.d 2>/dev/null || true
chattr +i /etc/bash.bashrc 2>/dev/null || true
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

echo "HARDENING COMPLETE"