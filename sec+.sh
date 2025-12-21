#!/bin/bash

set -euo pipefail

# KERNEL & INITRAMFS INTEGRITY
# Create integrity database directory
install -d -m 700 /var/lib/kernel-integrity

# Generate SHA512 hashes of kernel and initramfs
sha512sum /boot/vmlinuz-* > /var/lib/kernel-integrity/kernel.sha512
sha512sum /boot/initrd.img-* >> /var/lib/kernel-integrity/kernel.sha512
sha512sum /boot/grub/grub.cfg >> /var/lib/kernel-integrity/kernel.sha512
sha512sum /boot/grub/grubenv >> /var/lib/kernel-integrity/kernel.sha512 2>/dev/null || true

chmod 400 /var/lib/kernel-integrity/kernel.sha512
chown root:root /var/lib/kernel-integrity/kernel.sha512

# Create boot-time integrity verification service
cat > /etc/systemd/system/kernel-integrity-check.service << 'EOF'
[Unit]
Description=Verify kernel and initramfs integrity at boot
DefaultDependencies=no
Before=sysinit.target
After=local-fs.target

[Service]
Type=oneshot
ExecStart=/usr/local/sbin/verify-kernel-integrity
RemainAfterExit=yes
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=sysinit.target
EOF

# Create the verification script
cat > /usr/local/sbin/verify-kernel-integrity << 'EOF'
#!/bin/bash
set -e

HASH_FILE="/var/lib/kernel-integrity/kernel.sha512"
LOG_TAG="kernel-integrity"

if [ ! -f "$HASH_FILE" ]; then
    logger -p auth.crit -t "$LOG_TAG" "CRITICAL: Hash database missing! System may be compromised."
    echo "CRITICAL: Kernel integrity database missing!" > /dev/console
    # Optionally halt the system:
    # systemctl poweroff
    exit 1
fi

if ! sha512sum -c "$HASH_FILE" --quiet 2>/dev/null; then
    logger -p auth.crit -t "$LOG_TAG" "CRITICAL: Kernel/initramfs integrity check FAILED! Possible tampering detected."
    echo "CRITICAL: Kernel integrity verification FAILED!" > /dev/console
    # Log which files failed
    sha512sum -c "$HASH_FILE" 2>&1 | grep -v OK | logger -p auth.crit -t "$LOG_TAG"
    # Optionally halt:
    # systemctl poweroff
    exit 1
fi

logger -p auth.info -t "$LOG_TAG" "Kernel and initramfs integrity verified successfully."
exit 0
EOF

chmod 700 /usr/local/sbin/verify-kernel-integrity
chown root:root /usr/local/sbin/verify-kernel-integrity

# Script to regenerate hashes after legitimate kernel update
cat > /usr/local/sbin/update-kernel-hashes << 'EOF'
#!/bin/bash
# Run this after kernel updates to regenerate integrity hashes
# Must unlock /var/lib/kernel-integrity first: chattr -i /var/lib/kernel-integrity/kernel.sha512

set -e

if lsattr /var/lib/kernel-integrity/kernel.sha512 2>/dev/null | grep -q 'i'; then
    echo "ERROR: Hash file is immutable. Run: chattr -i /var/lib/kernel-integrity/kernel.sha512"
    exit 1
fi

echo "Regenerating kernel integrity hashes..."
sha512sum /boot/vmlinuz-* > /var/lib/kernel-integrity/kernel.sha512
sha512sum /boot/initrd.img-* >> /var/lib/kernel-integrity/kernel.sha512
sha512sum /boot/grub/grub.cfg >> /var/lib/kernel-integrity/kernel.sha512
sha512sum /boot/grub/grubenv >> /var/lib/kernel-integrity/kernel.sha512 2>/dev/null || true

chmod 400 /var/lib/kernel-integrity/kernel.sha512
chattr +i /var/lib/kernel-integrity/kernel.sha512

echo "Kernel integrity hashes updated and locked."
EOF

chmod 700 /usr/local/sbin/update-kernel-hashes

systemctl daemon-reload
systemctl enable kernel-integrity-check.service

# Make kernel files immutable
chattr +i /boot/vmlinuz-* 2>/dev/null || true
chattr +i /boot/initrd.img-* 2>/dev/null || true
chattr +i /boot/grub/grub.cfg 2>/dev/null || true
chattr +i /var/lib/kernel-integrity/kernel.sha512 2>/dev/null || true

echo "[1/9] Kernel integrity verification configured."

# REBUILD CRITICAL BINARIES WITH HARDENING FLAGS 
# Create documentation of expected binary hardening
cat > /var/lib/kernel-integrity/binary-hardening-policy.txt << 'EOF'
# Required Binary Hardening Flags (verify with checksec)
# These should be present on all critical binaries:

RELRO:         Full RELRO (lazy binding disabled)
STACK CANARY:  Enabled (stack smashing protection)
NX:            Enabled (non-executable stack)
PIE:           Enabled (position independent executable)  
FORTIFY:       Enabled (buffer overflow detection)
RPATH/RUNPATH: None (no hardcoded library paths)

# Verify with: checksec --file=/usr/bin/sudo
# All Debian packages are built with these by default.
# Custom builds must use:
#   CFLAGS="-fstack-protector-strong -D_FORTIFY_SOURCE=2 -fPIE -Wl,-z,relro,-z,now"
#   LDFLAGS="-pie -Wl,-z,relro,-z,now"
EOF

chmod 400 /var/lib/kernel-integrity/binary-hardening-policy.txt

echo "[2/9] Binary hardening policy documented."

# CAPABILITIES HARDENING
# Install libcap if not present (needed for setcap/getcap)
apt install -y libcap2-bin 2>/dev/null || true

# Remove ALL capabilities from dangerous binaries
# These should never need special privileges
STRIP_CAPS_BINARIES=(
    /usr/bin/perl
    /usr/bin/perl5*
    /usr/bin/python*
    /usr/bin/ruby*
    /usr/bin/lua*
    /usr/bin/node
    /usr/bin/nodejs
    /usr/bin/php*
    /usr/bin/awk
    /usr/bin/gawk
    /usr/bin/mawk
    /usr/bin/nawk
    /usr/bin/sed
    /usr/bin/ed
    /usr/bin/vi
    /usr/bin/vim*
    /usr/bin/nano
    /usr/bin/emacs*
    /usr/bin/tar
    /usr/bin/zip
    /usr/bin/unzip
    /usr/bin/gzip
    /usr/bin/bzip2
    /usr/bin/xz
    /usr/bin/7z*
    /usr/bin/curl
    /usr/bin/wget
    /usr/bin/nc
    /usr/bin/ncat
    /usr/bin/netcat
    /usr/bin/socat
    /usr/bin/telnet
    /usr/bin/ftp
    /usr/bin/ssh
    /usr/bin/scp
    /usr/bin/sftp
    /usr/bin/rsync
    /usr/bin/dd
    /usr/bin/xxd
    /usr/bin/od
    /usr/bin/hexdump
    /usr/bin/strings
    /usr/bin/objdump
    /usr/bin/readelf
    /usr/bin/nm
    /usr/bin/as
    /usr/bin/ld
    /usr/bin/ar
    /usr/sbin/tcpdump
    /usr/sbin/nmap
    /usr/bin/tshark
    /usr/bin/wireshark
)

for bin in "${STRIP_CAPS_BINARIES[@]}"; do
    for f in $bin; do
        if [ -f "$f" ]; then
            setcap -r "$f" 2>/dev/null || true
        fi
    done
done

# Set MINIMAL required capabilities on specific binaries
# ping needs net_raw only
if [ -f /usr/bin/ping ]; then
    setcap cap_net_raw+ep /usr/bin/ping 2>/dev/null || true
fi

# Remove capabilities from network tools entirely
for bin in /usr/bin/traceroute /usr/bin/mtr /usr/sbin/arping; do
    if [ -f "$bin" ]; then
        setcap -r "$bin" 2>/dev/null || true
    fi
done

# Audit: List all binaries with capabilities
echo "Binaries with capabilities (should be minimal):" > /var/log/capabilities-audit.log
getcap -r / 2>/dev/null >> /var/log/capabilities-audit.log || true

echo "[3/9] Capabilities stripped from dangerous binaries."

# PREVENT LD_PRELOAD HIJACKING
# Method 1: Restrict /etc/ld.so.preload to root only
touch /etc/ld.so.preload
chown root:root /etc/ld.so.preload
chmod 644 /etc/ld.so.preload
# Empty it - no preloads allowed
echo "" > /etc/ld.so.preload
chattr +i /etc/ld.so.preload

# Method 2: Restrict ld.so.conf paths
cat > /etc/ld.so.conf << 'EOF'
# Hardened library paths - no user-writable directories
include /etc/ld.so.conf.d/*.conf
EOF

# Ensure ld.so.conf.d only has system paths
find /etc/ld.so.conf.d -type f -exec grep -l '/home\|/tmp\|/var/tmp' {} \; 2>/dev/null | while read f; do
    echo "WARNING: Removing insecure library path from $f"
    sed -i '/\/home\|\/tmp\|\/var\/tmp/d' "$f"
done

ldconfig

# Method 3: PAM environment restrictions - clear dangerous variables
cat >> /etc/security/pam_env.conf << 'EOF'
# Clear dangerous environment variables
LD_PRELOAD        DEFAULT="" OVERRIDE=""
LD_LIBRARY_PATH   DEFAULT="" OVERRIDE=""
LD_AUDIT          DEFAULT="" OVERRIDE=""
LD_DEBUG          DEFAULT="" OVERRIDE=""
LD_DEBUG_OUTPUT   DEFAULT="" OVERRIDE=""
LD_DYNAMIC_WEAK   DEFAULT="" OVERRIDE=""
LD_ORIGIN_PATH    DEFAULT="" OVERRIDE=""
LD_PROFILE        DEFAULT="" OVERRIDE=""
LD_SHOW_AUXV      DEFAULT="" OVERRIDE=""
LD_USE_LOAD_BIAS  DEFAULT="" OVERRIDE=""
GCONV_PATH        DEFAULT="" OVERRIDE=""
GETCONF_DIR       DEFAULT="" OVERRIDE=""
HOSTALIASES       DEFAULT="" OVERRIDE=""
LOCALDOMAIN       DEFAULT="" OVERRIDE=""
LOCPATH           DEFAULT="" OVERRIDE=""
MALLOC_TRACE      DEFAULT="" OVERRIDE=""
NIS_PATH          DEFAULT="" OVERRIDE=""
NLSPATH           DEFAULT="" OVERRIDE=""
RESOLV_HOST_CONF  DEFAULT="" OVERRIDE=""
RES_OPTIONS       DEFAULT="" OVERRIDE=""
TMPDIR            DEFAULT="/tmp" OVERRIDE="/tmp"
EOF

# Method 4: Profile script to unset dangerous variables
cat > /etc/profile.d/ld-protect.sh << 'EOF'
# Unset dangerous environment variables that could be used for injection
unset LD_PRELOAD
unset LD_LIBRARY_PATH
unset LD_AUDIT
unset LD_DEBUG
unset LD_DEBUG_OUTPUT
unset LD_DYNAMIC_WEAK
unset LD_ORIGIN_PATH
unset LD_PROFILE
unset LD_SHOW_AUXV
unset LD_USE_LOAD_BIAS
unset GCONV_PATH
unset GETCONF_DIR
unset HOSTALIASES
unset MALLOC_TRACE
unset NLSPATH

# Make these readonly to prevent setting
readonly LD_PRELOAD="" 2>/dev/null || true
readonly LD_LIBRARY_PATH="" 2>/dev/null || true
EOF

chmod 644 /etc/profile.d/ld-protect.sh

# Method 5: Audit rule for LD_PRELOAD abuse attempts
cat >> /etc/audit/rules.d/privilege-escalation.rules << 'EOF'
# Monitor LD_PRELOAD abuse attempts
-w /etc/ld.so.preload -p wa -k ld_preload
-w /etc/ld.so.conf -p wa -k ld_config
-w /etc/ld.so.conf.d -p wa -k ld_config
EOF

# RATE-LIMITING ON ALL AUTHENTICATION METHODS
# PAM tally2/faillock for login attempt limiting
apt install -y libpam-modules 2>/dev/null || true

# Configure faillock (modern replacement for tally2)
cat > /etc/security/faillock.conf << 'EOF'
# Faillock configuration - rate limit authentication attempts
# Deny after 3 failures
deny = 3
# Lock for 15 minutes (900 seconds)
unlock_time = 900
# Count failures in last 15 minutes
fail_interval = 900
# Also apply to root
even_deny_root
root_unlock_time = 900
# Audit failures
audit
# Silence successful unlocks
silent
EOF

chmod 644 /etc/security/faillock.conf

# Add faillock to PAM - must be before pam_u2f
cat > /etc/pam.d/common-auth << 'EOF'
#%PAM-1.0
# Rate limiting - deny after 3 failures for 15 minutes
auth      required    pam_faillock.so preauth
auth      sufficient  pam_u2f.so authfile=/etc/conf cue
auth      [default=die] pam_faillock.so authfail
auth      requisite   pam_deny.so
EOF

# Add faillock to login
cat > /etc/pam.d/login << 'EOF'
#%PAM-1.0
auth      required    pam_faillock.so preauth
auth      required    pam_securetty.so
auth      sufficient  pam_u2f.so authfile=/etc/conf cue
auth      [default=die] pam_faillock.so authfail
auth      requisite   pam_deny.so
auth      requisite   pam_nologin.so
auth      optional    pam_faildelay.so delay=4000000
account   required    pam_faillock.so
account   required    pam_access.so
account   include     common-account
password  include     common-password
session   include     common-session
EOF

# Add faillock to sudo
cat > /etc/pam.d/sudo << 'EOF'
#%PAM-1.0
auth      required    pam_faillock.so preauth
auth      sufficient  pam_u2f.so authfile=/etc/conf cue
auth      [default=die] pam_faillock.so authfail
auth      requisite   pam_deny.so
account   required    pam_faillock.so
account   include     common-account
password  include     common-password
session   include     common-session
EOF

# Add faillock to su
cat > /etc/pam.d/su << 'EOF'
#%PAM-1.0
auth      required    pam_faillock.so preauth
auth      sufficient  pam_u2f.so authfile=/etc/conf cue
auth      [default=die] pam_faillock.so authfail
auth      requisite   pam_deny.so
account   required    pam_faillock.so
account   include     common-account
password  include     common-password
session   include     common-session
EOF

cat > /etc/pam.d/su-l << 'EOF'
#%PAM-1.0
auth      required    pam_faillock.so preauth
auth      sufficient  pam_u2f.so authfile=/etc/conf cue
auth      [default=die] pam_faillock.so authfail
auth      requisite   pam_deny.so
account   required    pam_faillock.so
account   include     common-account
password  include     common-password
session   include     common-session
EOF

# Add to common-account for unlock
cat > /etc/pam.d/common-account << 'EOF'
#%PAM-1.0
account   required    pam_faillock.so
account   required    pam_unix.so
EOF

# Create faillock directory
install -d -m 755 /var/run/faillock

echo "[5/9] Authentication rate-limiting configured (3 attempts, 15 min lockout)."

# REMOVE COMPILERS AND CODE INJECTORS
# Compilers and build tools
COMPILER_PACKAGES=(
    gcc gcc-* g++ g++-* cpp cpp-*
    clang clang-* llvm llvm-*
    gfortran gfortran-*
    rustc cargo
    golang golang-*
    ghc ghc-*
    fpc
    nasm yasm
    as86 bin86
    make cmake ninja-build meson
    autoconf automake libtool
    bison flex byacc
    swig
    m4
)

# Interpreters that can execute arbitrary code
INTERPRETER_PACKAGES=(
    perl perl-base perl-modules
    python2* python3* python-is-python*
    ruby ruby-*
    lua* 
    tcl tcl-*
    php* php-*
    nodejs node npm
    openjdk-* default-jdk default-jre java-*
    mono-* libmono-*
    gawk mawk
    guile-*
    pike*
    racket*
    erlang*
    elixir*
    julia
    octave*
    r-base r-cran-*
    maxima*
    gap*
)

# Debuggers and injection tools
DEBUG_INJECT_PACKAGES=(
    gdb gdb-*
    lldb lldb-*
    strace ltrace
    valgrind
    binutils
    elfutils
    patchelf
    execstack
    prelink
    chrpath
    dwarfdump
    objdump
    readelf
    radare2 r2*
    ghidra
    ida-*
    hopper*
    nasm ndisasm
    xxd hexedit bvi
    binwalk
    upx upx-ucl
    msfvenom metasploit*
)

# Network injection/sniffing tools
NETWORK_INJECT_PACKAGES=(
    nmap zenmap
    masscan
    netcat netcat-* nc ncat socat
    hping3
    scapy
    ettercap*
    bettercap
    mitmproxy
    sslstrip
    tcpdump
    wireshark* tshark
    dsniff
    arpspoof
    macchanger
    aircrack-ng*
)

echo "Purging compilers..."
for pkg in "${COMPILER_PACKAGES[@]}"; do
    apt purge -y $pkg 2>/dev/null || true
done

echo "Purging interpreters..."
for pkg in "${INTERPRETER_PACKAGES[@]}"; do
    apt purge -y $pkg 2>/dev/null || true
done

echo "Purging debuggers and injection tools..."
for pkg in "${DEBUG_INJECT_PACKAGES[@]}"; do
    apt purge -y $pkg 2>/dev/null || true
done

echo "Purging network injection tools..."
for pkg in "${NETWORK_INJECT_PACKAGES[@]}"; do
    apt purge -y $pkg 2>/dev/null || true
done

apt autoremove -y 2>/dev/null || true

# Remove any remaining binaries that weren't package-managed
DANGEROUS_BINARIES=(
    /usr/bin/gcc /usr/bin/g++ /usr/bin/cc /usr/bin/c++
    /usr/bin/as /usr/bin/ld /usr/bin/ar /usr/bin/nm
    /usr/bin/make /usr/bin/cmake
    /usr/bin/perl /usr/bin/perl5*
    /usr/bin/python /usr/bin/python2* /usr/bin/python3*
    /usr/bin/ruby /usr/bin/irb /usr/bin/erb
    /usr/bin/lua /usr/bin/luac
    /usr/bin/node /usr/bin/nodejs /usr/bin/npm
    /usr/bin/php /usr/bin/php-cgi /usr/bin/php-fpm
    /usr/bin/gdb /usr/bin/lldb
    /usr/bin/strace /usr/bin/ltrace
    /usr/bin/nc /usr/bin/ncat /usr/bin/netcat
    /usr/bin/nmap /usr/bin/masscan
    /usr/bin/socat
    /usr/bin/xxd /usr/bin/hexdump
    /usr/bin/objdump /usr/bin/readelf
)

echo "Removing remaining dangerous binaries..."
for bin in "${DANGEROUS_BINARIES[@]}"; do
    for f in $bin; do
        if [ -f "$f" ] && [ ! -L "$f" ]; then
            echo "Removing: $f"
            rm -f "$f" 2>/dev/null || true
        fi
    done
done

echo "[6/9] Compilers and injection tools removed."

# PURGE SHELLS
# Shells to remove
SHELL_PACKAGES=(
    zsh zsh-*
    fish
    tcsh csh
    ksh ksh93 mksh pdksh
    dash
    ash busybox
    rc
    es
    sash
    yash
)

for pkg in "${SHELL_PACKAGES[@]}"; do
    apt purge -y $pkg 2>/dev/null || true
done

# Remove shell binaries
SHELL_BINARIES=(
    /bin/sh         # We'll relink this to bash
    /bin/dash
    /bin/zsh
    /bin/fish
    /bin/tcsh /bin/csh
    /bin/ksh /bin/ksh93 /bin/mksh /bin/pdksh
    /bin/ash
    /bin/rc
    /bin/es
    /bin/sash
    /bin/yash
    /usr/bin/zsh
    /usr/bin/fish
    /usr/bin/tcsh /usr/bin/csh
    /usr/bin/ksh*
)

for shell in "${SHELL_BINARIES[@]}"; do
    if [ -f "$shell" ] && [ "$shell" != "/bin/bash" ]; then
        # Check if it's not bash
        if ! [ "$shell" -ef "/bin/bash" ]; then
            rm -f "$shell" 2>/dev/null || true
        fi
    fi
done

# Ensure /bin/sh points to bash (not dash)
if [ -L /bin/sh ]; then
    rm /bin/sh
fi
ln -sf /bin/bash /bin/sh

# Update /etc/shells to only allow bash
cat > /etc/shells << 'EOF'
/bin/bash
/usr/bin/bash
EOF

chmod 644 /etc/shells
chattr +i /etc/shells

# Ensure all users have bash as shell (except system accounts with nologin)
while IFS=: read -r username _ uid _ _ _ shell; do
    if [ "$uid" -ge 1000 ] && [ "$shell" != "/usr/sbin/nologin" ] && [ "$shell" != "/bin/false" ]; then
        if [ "$shell" != "/bin/bash" ]; then
            echo "Changing shell for $username from $shell to /bin/bash"
            usermod -s /bin/bash "$username" 2>/dev/null || true
        fi
    fi
done < /etc/passwd

# 8. REMOVE PACKAGE MANAGERS FROM RUNTIME
# Create a maintenance script to re-enable package managers
cat > /usr/local/sbin/enable-package-manager << 'EOF'
#!/bin/bash
# Temporarily enable apt for maintenance
# Usage: enable-package-manager
# Then run your apt commands
# Then: disable-package-manager

set -e

if [ "$(id -u)" -ne 0 ]; then
    echo "Must be run as root"
    exit 1
fi

echo "Unlocking package manager..."
chattr -i /usr/bin/apt* 2>/dev/null || true
chattr -i /usr/bin/dpkg* 2>/dev/null || true
chattr -i /usr/bin/aptitude 2>/dev/null || true

chmod 755 /usr/bin/apt 2>/dev/null || true
chmod 755 /usr/bin/apt-get 2>/dev/null || true
chmod 755 /usr/bin/apt-cache 2>/dev/null || true
chmod 755 /usr/bin/apt-mark 2>/dev/null || true
chmod 755 /usr/bin/dpkg 2>/dev/null || true
chmod 755 /usr/bin/dpkg-deb 2>/dev/null || true
chmod 755 /usr/bin/dpkg-query 2>/dev/null || true

echo "Package manager enabled. Run 'disable-package-manager' when done."
EOF

cat > /usr/local/sbin/disable-package-manager << 'EOF'
#!/bin/bash
# Disable apt after maintenance
set -e

if [ "$(id -u)" -ne 0 ]; then
    echo "Must be run as root"
    exit 1
fi

echo "Locking package manager..."

# Make binaries non-executable
chmod 000 /usr/bin/apt 2>/dev/null || true
chmod 000 /usr/bin/apt-get 2>/dev/null || true
chmod 000 /usr/bin/apt-cache 2>/dev/null || true
chmod 000 /usr/bin/apt-mark 2>/dev/null || true
chmod 000 /usr/bin/apt-config 2>/dev/null || true
chmod 000 /usr/bin/apt-key 2>/dev/null || true
chmod 000 /usr/bin/aptitude 2>/dev/null || true
chmod 000 /usr/bin/dpkg 2>/dev/null || true
chmod 000 /usr/bin/dpkg-deb 2>/dev/null || true
chmod 000 /usr/bin/dpkg-query 2>/dev/null || true
chmod 000 /usr/bin/dpkg-divert 2>/dev/null || true
chmod 000 /usr/bin/dpkg-statoverride 2>/dev/null || true
chmod 000 /usr/bin/dpkg-trigger 2>/dev/null || true

# Make immutable
chattr +i /usr/bin/apt* 2>/dev/null || true
chattr +i /usr/bin/dpkg* 2>/dev/null || true
chattr +i /usr/bin/aptitude 2>/dev/null || true

echo "Package manager disabled and locked."
EOF

chmod 700 /usr/local/sbin/enable-package-manager
chmod 700 /usr/local/sbin/disable-package-manager

# Other package managers to disable
OTHER_PKG_MANAGERS=(
    /usr/bin/pip /usr/bin/pip2 /usr/bin/pip3
    /usr/bin/easy_install*
    /usr/bin/gem
    /usr/bin/npm /usr/bin/yarn /usr/bin/pnpm
    /usr/bin/cargo
    /usr/bin/go
    /usr/bin/cpan
    /usr/bin/pecl /usr/bin/pear
    /usr/bin/composer
    /usr/bin/snap
    /usr/bin/flatpak
    /usr/bin/brew
)

for pm in "${OTHER_PKG_MANAGERS[@]}"; do
    for f in $pm; do
        if [ -f "$f" ]; then
            chmod 000 "$f" 2>/dev/null || true
            chattr +i "$f" 2>/dev/null || true
        fi
    done
done

# Disable apt timers
systemctl disable --now apt-daily.timer apt-daily-upgrade.timer 2>/dev/null || true
systemctl mask apt-daily.timer apt-daily-upgrade.timer apt-daily.service apt-daily-upgrade.service 2>/dev/null || true

# Now lock apt/dpkg
/usr/local/sbin/disable-package-manager

# REMOVE UNNECESSARY LIBRARIES
# Development libraries
DEV_LIB_PACKAGES=(
    '*-dev'
    '*-dbg'
    '*-dbgsym'
    '*-doc'
)

# This is aggressive - only remove clearly dev packages
apt purge -y \
    libc6-dev \
    libstdc++-*-dev \
    linux-headers-* \
    linux-libc-dev \
    libssl-dev \
    libffi-dev \
    libpython*-dev \
    2>/dev/null || true

# Remove orphaned libraries
apt autoremove -y 2>/dev/null || true

# Find and report potentially unused libraries
echo "Checking for potentially unused shared libraries..."
cat > /var/log/unused-libs-check.log << 'EOFLOG'
# Potentially unused libraries report
# Review carefully before removing - some may be dynamically loaded
# Generated: $(date)
EOFLOG

# List libraries that might be orphaned (no reverse dependencies)
deborphan 2>/dev/null >> /var/log/unused-libs-check.log || echo "Install deborphan for orphaned package detection" >> /var/log/unused-libs-check.log

# Clean apt cache
apt clean

# Remove old kernels (keep current only)
CURRENT_KERNEL=$(uname -r)
dpkg -l 'linux-image-*' 2>/dev/null | grep '^ii' | awk '{print $2}' | while read pkg; do
    if [[ "$pkg" != *"$CURRENT_KERNEL"* ]] && [[ "$pkg" != "linux-image-amd64" ]] && [[ "$pkg" != "linux-image-generic" ]]; then
        echo "Removing old kernel: $pkg"
        # Unlock for removal
        chattr -i /usr/bin/apt* /usr/bin/dpkg* 2>/dev/null || true
        chmod 755 /usr/bin/apt-get /usr/bin/dpkg 2>/dev/null || true
        apt purge -y "$pkg" 2>/dev/null || true
    fi
done

# Re-lock package manager
/usr/local/sbin/disable-package-manager 2>/dev/null || true

# FINAL LOCKDOWN
# Lock down the new files we created
chattr +i /usr/local/sbin/verify-kernel-integrity 2>/dev/null || true
chattr +i /usr/local/sbin/update-kernel-hashes 2>/dev/null || true
chattr +i /usr/local/sbin/enable-package-manager 2>/dev/null || true
chattr +i /usr/local/sbin/disable-package-manager 2>/dev/null || true
chattr +i /etc/ld.so.preload 2>/dev/null || true
chattr +i /etc/ld.so.conf 2>/dev/null || true
chattr -R +i /etc/ld.so.conf.d 2>/dev/null || true
chattr +i /etc/security/faillock.conf 2>/dev/null || true
chattr +i /etc/profile.d/ld-protect.sh 2>/dev/null || true
chattr +i /var/lib/kernel-integrity/kernel.sha512 2>/dev/null || true

# Regenerate initramfs with current modules and lock
echo "Regenerating initramfs..."
chattr -i /boot/initrd.img-* 2>/dev/null || true
update-initramfs -u -k all
chattr +i /boot/initrd.img-* 2>/dev/null || true

# Update kernel hashes after initramfs regeneration
chattr -i /var/lib/kernel-integrity/kernel.sha512 2>/dev/null || true
sha512sum /boot/vmlinuz-* > /var/lib/kernel-integrity/kernel.sha512
sha512sum /boot/initrd.img-* >> /var/lib/kernel-integrity/kernel.sha512
sha512sum /boot/grub/grub.cfg >> /var/lib/kernel-integrity/kernel.sha512
chattr +i /var/lib/kernel-integrity/kernel.sha512 2>/dev/null || true

echo "ADVANCED HARDENING COMPLETE"
