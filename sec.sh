#!/bin/bash

#######-DEBIAN-HARDENING-#########

set -euo pipefail

# PRE-CONFIG

apt install -y extrepo iptables iptables-persistent netfilter-persistent --no-install-recommends
extrepo enable librewolf 
apt update
apt install -y librewolf --no-install-recommends


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

Cmnd_Alias FIREWALL = /usr/sbin/iptables -L, /usr/sbin/iptables -S, /usr/sbin/iptables-save
Cmnd_Alias PACKAGES = /usr/bin/apt update, /usr/bin/apt list --upgradable, /usr/bin/apt upgrade
Cmnd_Alias MAINT = /usr/bin/systemctl status *, /usr/bin/journalctl -xe

dev ALL=(root) FIREWALL, PACKAGES, MAINT
EOF

chmod 0440 /etc/sudoers
chmod -R 0000 /etc/sudoers.d

# STRIP CAPABILITIES
STRIP_CAPS=(
"/bin/dash" "/bin/rbash" "/bin/sh" "/usr/bin/7z" "/usr/bin/7za" "/usr/bin/apropos" "/usr/bin/apt" "/usr/bin/apt-cache" "/usr/bin/apt-get" "/usr/bin/ar" "/usr/bin/aria2c" "/usr/bin/arj" "/usr/bin/ash" "/usr/bin/at" "/usr/bin/awk" "/usr/bin/base32" "/usr/bin/base64" "/usr/bin/basenc" "/usr/bin/bash" "/usr/bin/batch" "/usr/bin/bunzip2" "/usr/bin/busctl" "/usr/bin/busybox" "/usr/bin/bzip2" "/usr/bin/cat" "/usr/bin/cmp" "/usr/bin/column" "/usr/bin/comm" "/usr/bin/composer" "/usr/bin/cp" "/usr/bin/cpan" "/usr/bin/cpio" "/usr/bin/crontab" "/usr/bin/csh" "/usr/bin/csplit" "/usr/bin/curl" "/usr/bin/cut" "/usr/bin/cvs" "/usr/bin/dash" "/usr/bin/dd" "/usr/bin/diff" "/usr/bin/dmesg" "/usr/bin/dpkg" "/usr/bin/ed" "/usr/bin/egrep" "/usr/bin/emacs" "/usr/bin/emacsclient" "/usr/bin/env" "/usr/bin/expand" "/usr/bin/fgrep" "/usr/bin/file" "/usr/bin/find" "/usr/bin/fish" "/usr/bin/fmt" "/usr/bin/fold" "/usr/bin/gawk" "/usr/bin/gem" "/usr/bin/git" "/usr/bin/grep" "/usr/bin/gunzip" "/usr/bin/gzip" "/usr/bin/hd" "/usr/bin/head" "/usr/bin/hexdump" "/usr/bin/hg" "/usr/bin/hostnamectl" "/usr/bin/info" "/usr/bin/install" "/usr/bin/ionice" "/usr/bin/joe" "/usr/bin/join" "/usr/bin/journalctl" "/usr/bin/jq" "/usr/bin/ksh" "/usr/bin/less" "/usr/bin/ln" "/usr/bin/loginctl" "/usr/bin/lua" "/usr/bin/lua5.1" "/usr/bin/lua5.3" "/usr/bin/lua5.4" "/usr/bin/man" "/usr/bin/mawk" "/usr/bin/mcedit" "/usr/bin/more" "/usr/bin/most" "/usr/bin/mv" "/usr/bin/mysql" "/usr/bin/nano" "/usr/bin/nawk" "/usr/bin/ne" "/usr/bin/nice" "/usr/bin/nl" "/usr/bin/node" "/usr/bin/nodejs" "/usr/bin/nohup" "/usr/bin/npm" "/usr/bin/od" "/usr/bin/openssl" "/usr/bin/parallel" "/usr/bin/paste" "/usr/bin/pax" "/usr/bin/perl" "/usr/bin/pg" "/usr/bin/php" "/usr/bin/pico" "/usr/bin/pip" "/usr/bin/pip3" "/usr/bin/pr" "/usr/bin/psql" "/usr/bin/python" "/usr/bin/python3" "/usr/bin/red" "/usr/bin/redis-cli" "/usr/bin/resolvectl" "/usr/bin/rev" "/usr/bin/rsync" "/usr/bin/ruby" "/usr/bin/rview" "/usr/bin/rvim" "/usr/bin/scp" "/usr/bin/screen" "/usr/bin/script" "/usr/bin/sed" "/usr/bin/sftp" "/usr/bin/shuf" "/usr/bin/sort" "/usr/bin/split" "/usr/bin/sqlite3" "/usr/bin/ssh" "/usr/bin/ssh-keygen" "/usr/bin/ssh-keyscan" "/usr/bin/strings" "/usr/bin/svn" "/usr/bin/systemctl" "/usr/bin/tac" "/usr/bin/tail" "/usr/bin/tar" "/usr/bin/taskset" "/usr/bin/tclsh" "/usr/bin/tcsh" "/usr/bin/tee" "/usr/bin/time" "/usr/bin/timedatectl" "/usr/bin/timeout" "/usr/bin/tmux" "/usr/bin/tr" "/usr/bin/unexpand" "/usr/bin/uniq" "/usr/bin/unxz" "/usr/bin/unzip" "/usr/bin/vi" "/usr/bin/view" "/usr/bin/vim" "/usr/bin/vim.basic" "/usr/bin/vim.tiny" "/usr/bin/vimdiff" "/usr/bin/watch" "/usr/bin/wc" "/usr/bin/wget" "/usr/bin/whatis" "/usr/bin/wish" "/usr/bin/xargs" "/usr/bin/xmllint" "/usr/bin/xxd" "/usr/bin/xz" "/usr/bin/yarn" "/usr/bin/yelp" "/usr/bin/yq" "/usr/bin/zip" "/usr/bin/zsh" "/usr/sbin/arp" "/usr/sbin/bridge" "/usr/sbin/capsh" "/usr/sbin/chroot" "/usr/sbin/cryptsetup" "/usr/sbin/debugfs" "/usr/sbin/dmsetup" "/usr/sbin/fdisk" "/usr/sbin/gdisk" "/usr/sbin/getcap" "/usr/sbin/ifconfig" "/usr/sbin/ip" "/usr/sbin/ip6tables" "/usr/sbin/iptables" "/usr/sbin/losetup" "/usr/sbin/lvm" "/usr/sbin/lvs" "/usr/sbin/mkfs" "/usr/sbin/mount" "/usr/sbin/netstat" "/usr/sbin/nft" "/usr/sbin/parted" "/usr/sbin/pvs" "/usr/sbin/route" "/usr/sbin/setcap" "/usr/sbin/ss" "/usr/sbin/tc" "/usr/sbin/umount" "/usr/sbin/vgs"
)

ALL_GTFOBINS=(
"7z" "aa-exec" "ab" "agetty" "alpine" "ansible-playbook" "ansible-test" "aoss" "apache2ctl" "apt" "apt-get" "ar" "aria2c" "arj" "arp" "as" "ascii-xfr" "ascii85" "ash" "aspell" "at" "atobm" "awk" "aws" "base32" "base58" "base64" "basenc" "basez" "bash" "batcat" "bc" "bconsole" "bpftrace" "bridge" "bundle" "bundler" "busctl" "busybox" "byebug" "bzip2" "c89" "c99" "cabal" "cancel" "capsh" "cat" "cdist" "certbot" "check_by_ssh" "check_cups" "check_log" "check_memory" "check_raid" "check_ssl_cert" "check_statusfile" "chmod" "choom" "chown" "chroot" "clamscan" "cmp" "cobc" "column" "comm" "composer" "cowsay" "cowthink" "cp" "cpan" "cpio" "cpulimit" "crash" "crontab" "csh" "csplit" "csvtool" "cupsfilter" "curl" "cut" "dash" "date" "dc" "dd" "debugfs" "dialog" "diff" "dig" "distcc" "dmesg" "dmidecode" "dmsetup" "dnf" "docker" "dos2unix" "dosbox" "dotnet" "dpkg" "dstat" "dvips" "easy_install" "eb" "ed" "efax" "elvish" "emacs" "enscript" "env" "eqn" "espeak" "ex" "exiftool" "expand" "expect" "facter" "file" "find" "finger" "fish" "flock" "fmt" "fold" "fping" "ftp" "gawk" "gcc" "gcloud" "gcore" "gdb" "gem" "genie" "genisoimage" "ghc" "ghci" "gimp" "ginsh" "git" "grc" "grep" "gtester" "gzip" "hd" "head" "hexdump" "highlight" "hping3" "iconv" "iftop" "install" "ionice" "ip" "irb" "ispell" "jjs" "joe" "join" "journalctl" "jq" "jrunscript" "jtag" "julia" "knife" "ksh" "ksshell" "ksu" "kubectl" "latex" "latexmk" "ld.so" "ldconfig" "less" "lftp" "links" "ln" "loginctl" "logsave" "look" "lp" "ltrace" "lua" "lualatex" "luatex" "lwp-download" "lwp-request" "mail" "make" "man" "mawk" "minicom" "more" "mosquitto" "mount" "msfconsole" "msgattrib" "msgcat" "msgconv" "msgfilter" "msgmerge" "msguniq" "mtr" "multitime" "mv" "mysql" "nano" "nasm" "nawk" "nc" "ncdu" "ncftp" "neofetch" "nft" "nice" "nl" "nm" "nmap" "node" "nohup" "npm" "nroff" "nsenter" "ntpdate" "octave" "od" "openssl" "openvpn" "openvt" "opkg" "pandoc" "paste" "pax" "pdb" "pdflatex" "pdftex" "perf" "perl" "perlbug" "pexec" "pg" "php" "pic" "pico" "pidstat" "pip" "pkexec" "pkg" "posh" "pr" "pry" "psftp" "psql" "ptx" "puppet" "pwsh" "python" "rake" "rc" "readelf" "red" "redcarpet" "redis" "restic" "rev" "rlogin" "rlwrap" "rpm" "rpmdb" "rpmquery" "rpmverify" "rsync" "rtorrent" "ruby" "run-mailcap" "run-parts" "runscript" "rview" "rvim" "sash" "scanmem" "scp" "screen" "script" "scrot" "sed" "service" "setarch" "setfacl" "setlock" "sftp" "sg" "shuf" "slsh" "smbclient" "snap" "socat" "socket" "soelim" "softlimit" "sort" "split" "sqlite3" "sqlmap" "ss" "ssh" "ssh-agent" "ssh-keygen" "ssh-keyscan" "sshpass" "start-stop-daemon" "stdbuf" "strace" "strings" "su" "sudo" "sysctl" "systemctl" "systemd-resolve" "tac" "tail" "tar" "task" "taskset" "tasksh" "tbl" "tclsh" "tcpdump" "tdbtool" "tee" "telnet" "terraform" "tex" "tftp" "tic" "time" "timedatectl" "timeout" "tmate" "tmux" "top" "torify" "torsocks" "troff" "tshark" "ul" "unexpand" "uniq" "unshare" "unsquashfs" "unzip" "update-alternatives" "uudecode" "uuencode" "vagrant" "valgrind" "varnishncsa" "vi" "view" "vigr" "vim" "vimdiff" "vipw" "virsh" "volatility" "w3m" "wall" "watch" "wc" "wget" "whiptail" "whois" "wireshark" "wish" "xargs" "xdg-user-dir" "xdotool" "xelatex" "xetex" "xmodmap" "xmore" "xpad" "xxd" "xz" "yarn" "yash" "yelp" "yum" "zathura" "zip" "zsh" "zsoelim" "zypper"
)

for interp in "${STRIP_CAPS[@]}"; do
    [[ -f "$interp" ]] && getcap "$interp" &>/dev/null && setcap -r "$interp" 2>/dev/null
done

cap_output=$(getcap -r /usr /bin /sbin 2>/dev/null | awk '{print $1}')
for binary in $cap_output; do
    basename=$(basename "$binary")
    for gtfo in "${ALL_GTFOBINS[@]}"; do
        if [[ "$basename" == "$gtfo" ]] || [[ "$basename" == "${gtfo}."* ]]; then
            setcap -r "$binary" 2>/dev/null
            break
        fi
    done
done

# CREATE PLACEHOLDER BLOCKERS
dangerous_paths=(
"/usr/bin/perl" "/usr/bin/perl5" "/usr/bin/python" "/usr/bin/python2" "/usr/bin/python3"
"/usr/bin/ruby" "/usr/bin/lua" "/usr/bin/lua5.1" "/usr/bin/lua5.3" "/usr/bin/lua5.4"
"/usr/bin/node" "/usr/bin/nodejs" "/usr/bin/php" "/usr/bin/php7" "/usr/bin/php8"
"/usr/bin/awk" "/usr/bin/gawk" "/usr/bin/mawk" "/usr/bin/nawk" "/usr/bin/sed"
"/usr/bin/ed" "/usr/bin/vi" "/usr/bin/vim" "/usr/bin/emacs" "/usr/bin/tar"
"/usr/bin/zip" "/usr/bin/unzip" "/usr/bin/gzip" "/usr/bin/bzip2" "/usr/bin/xz"
"/usr/bin/7z" "/usr/bin/7za" "/usr/bin/curl" "/usr/bin/wget" "/usr/bin/nc"
"/usr/bin/ncat" "/usr/bin/netcat" "/usr/bin/socat" "/usr/bin/telnet" "/usr/bin/ftp"
"/usr/bin/ssh" "/usr/bin/scp" "/usr/bin/sftp" "/usr/bin/rsync" "/usr/bin/dd"
"/usr/bin/xxd" "/usr/bin/od" "/usr/bin/hexdump" "/usr/bin/strings" "/usr/bin/objdump"
"/usr/bin/readelf" "/usr/bin/nm" "/usr/bin/as" "/usr/bin/ld" "/usr/bin/ar"
"/usr/sbin/tcpdump" "/usr/bin/nmap" "/usr/bin/tshark" "/usr/bin/wireshark"
"/usr/bin/msfconsole" "/usr/bin/msfvenom" "/usr/bin/hydra" "/usr/bin/medusa"
"/usr/bin/john" "/usr/bin/hashcat" "/usr/bin/sqlmap" "/usr/bin/nikto"
"/usr/bin/aircrack-ng" "/usr/bin/ettercap" "/usr/bin/bettercap" "/usr/bin/responder"
)

for binary_path in "${dangerous_paths[@]}"; do
    if [[ ! -e "$binary_path" ]]; then
        mkdir -p "$(dirname "$binary_path")"
        touch "$binary_path"
        chmod 000 "$binary_path"
        chattr +i "$binary_path" 2>/dev/null || true
    fi
done

# LOCKDOWN
find / -xdev \( -perm -4000 -o -perm -2000 \) -type f -exec chmod a-s {} \; 
chmod u+s /usr/bin/sudo

apt clean
apt autopurge -y
RC_PKGS=$(dpkg -l | grep '^rc' | awk '{print $2}' || true)
if [ -n "$RC_PKGS" ]; then
    echo "$RC_PKGS" | xargs apt purge -y 2>/dev/null || true
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
chattr +i /etc/cron.allow 2>/dev/null || true
chattr +i /etc/at.allow 2>/dev/null || true
chattr -R +i /etc/polkit-1 2>/dev/null || true
chattr +i /etc/nsswitch.conf 2>/dev/null || true
chattr +i /etc/ld.so.conf 2>/dev/null || true
chattr -R +i /etc/ld.so.conf.d 2>/dev/null || true
chattr -R +i /etc/X11 2>/dev/null || true
chattr -R +i /lib/modules 2>/dev/null || true
chattr -R +i /boot 2>/dev/null || true
chattr -R +i /usr 2>/dev/null || true

echo "HARDENING COMPLETE"