#!/bin/bash
#===============================================================================
#
#          FILE: build-alphha-security.sh
#
#         USAGE: sudo ./build-alphha-security.sh [OPTIONS]
#
#   DESCRIPTION: Build script for Alphha Security OS - A Debian-based
#                all-in-one cybersecurity distribution.
#
#       OPTIONS: --variant <full|offensive|defensive|forensics|minimal>
#                --arch <amd64|arm64>
#                --output <directory>
#                --no-kali     Skip Kali repository
#                --help        Show this help
#
#        AUTHOR: Alphha Team
#     COPYRIGHT: Copyright (c) 2026 Alphha Team
#       LICENSE: BSD-3-Clause
#       VERSION: 1.0.0
#
#===============================================================================

set -euo pipefail

#-------------------------------------------------------------------------------
# Configuration
#-------------------------------------------------------------------------------
readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly SCRIPT_NAME="$(basename "${BASH_SOURCE[0]}")"
readonly VERSION="1.0.0"
readonly CODENAME="Sentinel"
readonly OS_NAME="Alphha Security OS"
readonly BUILD_DATE="$(date -u +%Y%m%d)"
readonly BUILD_TIMESTAMP="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

# Default options
VARIANT="full"
ARCH="amd64"
OUTPUT_DIR="${SCRIPT_DIR}/output"
WORK_DIR=""
INCLUDE_KALI=true

# Debian base
readonly DEBIAN_MIRROR="http://deb.debian.org/debian"
readonly DEBIAN_SUITE="bookworm"
readonly KALI_MIRROR="http://http.kali.org/kali"
readonly KALI_KEY_URL="https://archive.kali.org/archive-key.asc"

#-------------------------------------------------------------------------------
# Colors and Logging
#-------------------------------------------------------------------------------
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[0;33m'
readonly BLUE='\033[0;34m'
readonly CYAN='\033[0;36m'
readonly MAGENTA='\033[0;35m'
readonly NC='\033[0m'

log_info()    { echo -e "${GREEN}[INFO]${NC} $*"; }
log_warn()    { echo -e "${YELLOW}[WARN]${NC} $*"; }
log_error()   { echo -e "${RED}[ERROR]${NC} $*" >&2; }
log_debug()   { echo -e "${BLUE}[DEBUG]${NC} $*"; }
log_step()    { echo -e "${CYAN}[STEP]${NC} $*"; }
log_success() { echo -e "${GREEN}[SUCCESS]${NC} $*"; }

print_banner() {
    echo -e "${GREEN}"
    cat << 'EOF'
    _    _       _     _
   / \  | |_ __ | |__ | |__   __ _
  / _ \ | | '_ \| '_ \| '_ \ / _` |
 / ___ \| | |_) | | | | | | | (_| |
/_/   \_\_| .__/|_| |_|_| |_|\__,_|
          |_|  Security OS Builder
EOF
    echo -e "${NC}"
    echo -e "${CYAN}Version: ${VERSION} (${CODENAME})${NC}"
    echo -e "${CYAN}Build Date: ${BUILD_DATE}${NC}"
    echo ""
}

#-------------------------------------------------------------------------------
# Usage
#-------------------------------------------------------------------------------
usage() {
    cat << EOF
Usage: sudo $SCRIPT_NAME [OPTIONS]

Build Alphha Security OS ISO image.

OPTIONS:
    --variant <type>    Build variant (default: full)
                        - full:      All security tools (~6 GB)
                        - offensive: Penetration testing tools (~4 GB)
                        - defensive: Blue team & SIEM tools (~3 GB)
                        - forensics: Digital forensics tools (~3 GB)
                        - minimal:   CLI only, core tools (~1.5 GB)

    --arch <arch>       Target architecture (default: amd64)
                        - amd64
                        - arm64

    --output <dir>      Output directory (default: ./output)
    --no-kali           Don't include Kali Linux repositories
    --help              Show this help message

EXAMPLES:
    sudo $SCRIPT_NAME
    sudo $SCRIPT_NAME --variant offensive
    sudo $SCRIPT_NAME --variant forensics --output /tmp/build

COPYRIGHT:
    Copyright (c) 2026 Alphha Team
    Licensed under BSD-3-Clause

EOF
    exit 0
}

#-------------------------------------------------------------------------------
# Argument Parsing
#-------------------------------------------------------------------------------
parse_args() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --variant)
                VARIANT="$2"
                shift 2
                ;;
            --arch)
                ARCH="$2"
                shift 2
                ;;
            --output)
                OUTPUT_DIR="$2"
                shift 2
                ;;
            --no-kali)
                INCLUDE_KALI=false
                shift
                ;;
            --help|-h)
                usage
                ;;
            *)
                log_error "Unknown option: $1"
                usage
                ;;
        esac
    done

    # Validate variant
    case "$VARIANT" in
        full|offensive|defensive|forensics|minimal) ;;
        *)
            log_error "Invalid variant: $VARIANT"
            exit 1
            ;;
    esac

    # Validate architecture
    case "$ARCH" in
        amd64|arm64) ;;
        *)
            log_error "Invalid architecture: $ARCH"
            exit 1
            ;;
    esac
}

#-------------------------------------------------------------------------------
# Prerequisites Check
#-------------------------------------------------------------------------------
check_root() {
    if [[ $EUID -ne 0 ]]; then
        log_error "This script must be run as root"
        exit 1
    fi
}

check_dependencies() {
    log_step "Checking dependencies..."

    local deps=(
        debootstrap
        xorriso
        squashfs-tools
        grub-pc-bin
        grub-efi-amd64-bin
        mtools
        dosfstools
        isolinux
        syslinux-common
        curl
        wget
        gpg
    )

    local missing=()
    for dep in "${deps[@]}"; do
        if ! dpkg -l "$dep" &>/dev/null; then
            missing+=("$dep")
        fi
    done

    if [[ ${#missing[@]} -gt 0 ]]; then
        log_warn "Missing dependencies: ${missing[*]}"
        log_info "Installing missing dependencies..."
        apt-get update
        apt-get install -y "${missing[@]}"
    fi

    log_success "All dependencies satisfied"
}

#-------------------------------------------------------------------------------
# Cleanup Handler
#-------------------------------------------------------------------------------
cleanup() {
    local exit_code=$?
    log_info "Cleaning up..."

    # Unmount any mounted filesystems
    if [[ -n "${WORK_DIR:-}" && -d "$WORK_DIR" ]]; then
        umount -lf "$WORK_DIR/chroot/proc" 2>/dev/null || true
        umount -lf "$WORK_DIR/chroot/sys" 2>/dev/null || true
        umount -lf "$WORK_DIR/chroot/dev/pts" 2>/dev/null || true
        umount -lf "$WORK_DIR/chroot/dev" 2>/dev/null || true
        umount -lf "$WORK_DIR/chroot/run" 2>/dev/null || true

        # Remove work directory on failure
        if [[ $exit_code -ne 0 ]]; then
            log_warn "Build failed, cleaning up work directory..."
            rm -rf "$WORK_DIR"
        fi
    fi

    exit $exit_code
}

trap cleanup EXIT INT TERM

#-------------------------------------------------------------------------------
# Package Lists by Variant
#-------------------------------------------------------------------------------
get_core_packages() {
    cat << 'EOF'
linux-image-amd64
linux-headers-amd64
firmware-linux
firmware-linux-nonfree
intel-microcode
amd64-microcode
systemd
systemd-sysv
dbus
policykit-1
sudo
zsh
zsh-autosuggestions
zsh-syntax-highlighting
locales
console-setup
keyboard-configuration
grub-efi-amd64
grub-pc-bin
efibootmgr
os-prober
btrfs-progs
e2fsprogs
dosfstools
ntfs-3g
cryptsetup
lvm2
network-manager
iwd
wpasupplicant
wireless-tools
rfkill
dnsutils
whois
curl
wget
git
vim
nano
htop
tmux
tree
jq
unzip
zip
p7zip-full
file
rsync
openssh-client
openssh-server
openvpn
wireguard
socat
netcat-openbsd
ca-certificates
gnupg
apt-transport-https
EOF
}

get_desktop_packages() {
    if [[ "$VARIANT" == "minimal" ]]; then
        return
    fi

    cat << 'EOF'
xfce4
xfce4-goodies
xfce4-terminal
xfce4-whiskermenu-plugin
thunar
thunar-archive-plugin
thunar-volman
lightdm
lightdm-gtk-greeter
lightdm-gtk-greeter-settings
xorg
xserver-xorg-video-all
mesa-utils
fonts-noto
fonts-jetbrains-mono
papirus-icon-theme
arc-theme
plymouth
plymouth-themes
firefox-esr
EOF
}

get_offensive_packages() {
    cat << 'EOF'
nmap
masscan
netdiscover
arp-scan
dnsrecon
dnsenum
theharvester
recon-ng
enum4linux
nbtscan
nikto
wpscan
sqlmap
testssl.sh
sslscan
ffuf
gobuster
dirb
wfuzz
whatweb
wafw00f
hashcat
john
hydra
medusa
cewl
crunch
wordlists
aircrack-ng
wifite
reaver
kismet
hcxtools
metasploit-framework
exploitdb
crackmapexec
impacket-scripts
wireshark
tshark
tcpdump
ettercap-text-only
bettercap
mitmproxy
responder
tor
torsocks
proxychains4
macchanger
ghidra
radare2
gdb
ltrace
strace
binwalk
foremost
autopsy
sleuthkit
EOF
}

get_defensive_packages() {
    cat << 'EOF'
snort
suricata
zeek
fail2ban
rkhunter
chkrootkit
clamav
clamav-daemon
aide
auditd
lynis
tiger
apparmor
apparmor-profiles
apparmor-utils
firejail
ufw
nftables
rsyslog
logwatch
EOF
}

get_forensics_packages() {
    cat << 'EOF'
autopsy
sleuthkit
foremost
scalpel
testdisk
binwalk
bulk-extractor
dc3dd
dcfldd
ewf-tools
afflib-tools
guymager
yara
hashdeep
ssdeep
EOF
}

get_development_packages() {
    cat << 'EOF'
build-essential
gcc
g++
make
cmake
python3
python3-pip
python3-venv
python3-dev
ruby
ruby-dev
golang
nodejs
npm
default-jdk
EOF
}

get_packages_for_variant() {
    local packages=""

    # Core packages always included
    packages+=$(get_core_packages)
    packages+=$'\n'

    # Desktop packages (except minimal)
    packages+=$(get_desktop_packages)
    packages+=$'\n'

    # Development packages
    packages+=$(get_development_packages)
    packages+=$'\n'

    case "$VARIANT" in
        full)
            packages+=$(get_offensive_packages)
            packages+=$'\n'
            packages+=$(get_defensive_packages)
            packages+=$'\n'
            packages+=$(get_forensics_packages)
            ;;
        offensive)
            packages+=$(get_offensive_packages)
            ;;
        defensive)
            packages+=$(get_defensive_packages)
            packages+=$'\n'
            packages+=$(get_forensics_packages)
            ;;
        forensics)
            packages+=$(get_forensics_packages)
            ;;
        minimal)
            # Only core packages, already added
            ;;
    esac

    echo "$packages" | grep -v '^$' | sort -u
}

#-------------------------------------------------------------------------------
# Build Functions
#-------------------------------------------------------------------------------
setup_work_directory() {
    log_step "Setting up work directory..."

    WORK_DIR=$(mktemp -d -t alphha-build-XXXXXX)
    mkdir -p "$WORK_DIR"/{chroot,iso/{live,isolinux,boot/grub}}

    log_info "Work directory: $WORK_DIR"
}

run_debootstrap() {
    log_step "Running debootstrap..."

    local variant_flag="--variant=minbase"
    local include_pkgs="systemd,systemd-sysv,dbus,locales"

    debootstrap \
        $variant_flag \
        --arch="$ARCH" \
        --include="$include_pkgs" \
        "$DEBIAN_SUITE" \
        "$WORK_DIR/chroot" \
        "$DEBIAN_MIRROR"

    log_success "Debootstrap completed"
}

setup_chroot_mounts() {
    log_step "Setting up chroot mounts..."

    mount --bind /dev "$WORK_DIR/chroot/dev"
    mount --bind /dev/pts "$WORK_DIR/chroot/dev/pts"
    mount -t proc proc "$WORK_DIR/chroot/proc"
    mount -t sysfs sysfs "$WORK_DIR/chroot/sys"
    mount -t tmpfs tmpfs "$WORK_DIR/chroot/run"
}

configure_apt_sources() {
    log_step "Configuring APT sources..."

    cat > "$WORK_DIR/chroot/etc/apt/sources.list" << EOF
# Debian Bookworm - Main repositories
deb http://deb.debian.org/debian bookworm main contrib non-free non-free-firmware
deb http://deb.debian.org/debian bookworm-updates main contrib non-free non-free-firmware
deb http://security.debian.org/debian-security bookworm-security main contrib non-free non-free-firmware
EOF

    if [[ "$INCLUDE_KALI" == true ]]; then
        log_info "Adding Kali Linux repository..."

        # Download Kali GPG key from host (curl/gpg available on host, not in chroot yet)
        mkdir -p "$WORK_DIR/chroot/usr/share/keyrings"
        curl -fsSL "$KALI_KEY_URL" | gpg --dearmor -o "$WORK_DIR/chroot/usr/share/keyrings/kali-archive-keyring.gpg"

        # Add Kali repository with lower priority
        cat > "$WORK_DIR/chroot/etc/apt/sources.list.d/kali.list" << EOF
deb [signed-by=/usr/share/keyrings/kali-archive-keyring.gpg] http://http.kali.org/kali kali-rolling main contrib non-free non-free-firmware
EOF

        # Set Kali repo priority lower than Debian
        cat > "$WORK_DIR/chroot/etc/apt/preferences.d/kali.pref" << EOF
Package: *
Pin: release o=Kali
Pin-Priority: 100
EOF
    fi

    # Update package cache
    chroot "$WORK_DIR/chroot" apt-get update
}

install_packages() {
    log_step "Installing packages for variant: $VARIANT..."

    local packages
    # Get packages and convert newlines to spaces
    packages=$(get_packages_for_variant | tr '\n' ' ')

    # Write package list to a file in chroot to avoid argument issues
    echo "$packages" > "$WORK_DIR/chroot/tmp/packages.txt"

    # Install packages in chroot
    chroot "$WORK_DIR/chroot" bash -c '
        export DEBIAN_FRONTEND=noninteractive
        apt-get update
        xargs -a /tmp/packages.txt apt-get install -y --no-install-recommends 2>&1 || true
        rm -f /tmp/packages.txt
    '

    log_success "Package installation completed"
}

configure_system() {
    log_step "Configuring system..."

    # Set hostname
    echo "alphha-sec" > "$WORK_DIR/chroot/etc/hostname"

    # Configure hosts
    cat > "$WORK_DIR/chroot/etc/hosts" << EOF
127.0.0.1   localhost
127.0.1.1   alphha-sec
::1         localhost ip6-localhost ip6-loopback
ff02::1     ip6-allnodes
ff02::2     ip6-allrouters
EOF

    # Configure locale
    chroot "$WORK_DIR/chroot" bash -c "
        echo 'en_US.UTF-8 UTF-8' > /etc/locale.gen
        locale-gen
        update-locale LANG=en_US.UTF-8
    "

    # Configure timezone
    chroot "$WORK_DIR/chroot" ln -sf /usr/share/zoneinfo/UTC /etc/localtime

    # Create os-release
    cat > "$WORK_DIR/chroot/etc/os-release" << EOF
NAME="Alphha Security OS"
VERSION="$VERSION ($CODENAME)"
ID=alphha
ID_LIKE=debian
VERSION_ID="$VERSION"
VERSION_CODENAME="$CODENAME"
PRETTY_NAME="Alphha Security OS $VERSION ($CODENAME)"
HOME_URL="https://alphha.io"
SUPPORT_URL="https://alphha.io/support"
BUG_REPORT_URL="https://alphha.io/bugs"
EOF

    # Create alphha-release
    cat > "$WORK_DIR/chroot/etc/alphha-release" << EOF
Alphha Security OS $VERSION ($CODENAME)
Build: $BUILD_TIMESTAMP
Variant: $VARIANT
Architecture: $ARCH
Copyright (c) 2026 Alphha Team
EOF

    log_success "System configuration completed"
}

create_default_user() {
    log_step "Creating default user..."

    chroot "$WORK_DIR/chroot" bash -c '
        # Determine shell (prefer zsh if available, fallback to bash)
        if [ -x /bin/zsh ]; then
            USER_SHELL=/bin/zsh
        else
            USER_SHELL=/bin/bash
        fi

        # Create groups if they dont exist
        for grp in sudo adm cdrom audio video plugdev netdev; do
            getent group $grp >/dev/null 2>&1 || groupadd $grp 2>/dev/null || true
        done

        # Create sentinel user with available groups
        GROUPS="sudo,adm"
        for grp in cdrom audio video plugdev netdev; do
            getent group $grp >/dev/null 2>&1 && GROUPS="$GROUPS,$grp"
        done

        useradd -m -s "$USER_SHELL" -G "$GROUPS" sentinel 2>/dev/null || true

        # Set password
        echo "sentinel:alphha" | chpasswd

        # Allow passwordless sudo for live session
        mkdir -p /etc/sudoers.d
        echo "sentinel ALL=(ALL) NOPASSWD: ALL" > /etc/sudoers.d/sentinel
        chmod 440 /etc/sudoers.d/sentinel
    '

    log_success "Default user created: sentinel (password: alphha)"
}

configure_security_hardening() {
    log_step "Applying security hardening..."

    # Kernel hardening
    cat > "$WORK_DIR/chroot/etc/sysctl.d/99-alphha-security.conf" << 'EOF'
# Alphha Security OS - Kernel Hardening
# Copyright (c) 2026 Alphha Team

# Kernel
kernel.randomize_va_space = 2
kernel.kptr_restrict = 2
kernel.dmesg_restrict = 1
kernel.perf_event_paranoid = 3
kernel.yama.ptrace_scope = 1
kernel.unprivileged_bpf_disabled = 1
net.core.bpf_jit_harden = 2

# Network
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_rfc1337 = 1
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.secure_redirects = 0
net.ipv4.conf.default.secure_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0

# Filesystem
fs.protected_hardlinks = 1
fs.protected_symlinks = 1
fs.suid_dumpable = 0
EOF

    # SSH hardening (create directory if it doesn't exist)
    mkdir -p "$WORK_DIR/chroot/etc/ssh/sshd_config.d"
    cat > "$WORK_DIR/chroot/etc/ssh/sshd_config.d/alphha-hardening.conf" << 'EOF'
# Alphha Security OS - SSH Hardening
PermitRootLogin no
MaxAuthTries 3
PubkeyAuthentication yes
PasswordAuthentication yes
PermitEmptyPasswords no
X11Forwarding no
AllowAgentForwarding no
AllowTcpForwarding no
ClientAliveInterval 300
ClientAliveCountMax 2
Protocol 2
Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com
MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com
KexAlgorithms curve25519-sha256,curve25519-sha256@libssh.org
EOF

    log_success "Security hardening applied"
}

setup_branding() {
    log_step "Setting up branding..."

    # Create branding directories
    mkdir -p "$WORK_DIR/chroot/usr/share/backgrounds/alphha"
    mkdir -p "$WORK_DIR/chroot/usr/share/alphha-security"
    mkdir -p "$WORK_DIR/chroot/etc/skel"

    # Create MOTD
    cat > "$WORK_DIR/chroot/etc/motd" << 'EOF'

    _    _       _     _
   / \  | |_ __ | |__ | |__   __ _
  / _ \ | | '_ \| '_ \| '_ \ / _` |
 / ___ \| | |_) | | | | | | | (_| |
/_/   \_\_| .__/|_| |_|_| |_|\__,_|
          |_|  Security OS v1.0

Welcome to Alphha Security OS - All-in-One Cybersecurity Platform

Type 'alphha-menu' to launch the security tools menu.
Type 'alphha-help' for documentation.

Copyright (c) 2026 Alphha Team

EOF

    # Create issue banner
    cat > "$WORK_DIR/chroot/etc/issue" << 'EOF'
Alphha Security OS 1.0.0 (Sentinel)
Kernel \r on \m (\l)

EOF

    log_success "Branding setup completed"
}

install_custom_tools() {
    log_step "Installing Alphha custom tools..."

    mkdir -p "$WORK_DIR/chroot/opt/alphha-toolkit"
    mkdir -p "$WORK_DIR/chroot/usr/local/bin"

    # Copy custom tools from source
    if [[ -d "$SCRIPT_DIR/tools/alphha-toolkit" ]]; then
        cp -r "$SCRIPT_DIR/tools/alphha-toolkit/"* "$WORK_DIR/chroot/opt/alphha-toolkit/"
    fi

    if [[ -f "$SCRIPT_DIR/tools/alphha-menu" ]]; then
        cp "$SCRIPT_DIR/tools/alphha-menu" "$WORK_DIR/chroot/usr/local/bin/"
        chmod +x "$WORK_DIR/chroot/usr/local/bin/alphha-menu"
    fi

    if [[ -f "$SCRIPT_DIR/tools/alphha-update" ]]; then
        cp "$SCRIPT_DIR/tools/alphha-update" "$WORK_DIR/chroot/usr/local/bin/"
        chmod +x "$WORK_DIR/chroot/usr/local/bin/alphha-update"
    fi

    log_success "Custom tools installed"
}

configure_live_system() {
    log_step "Configuring live system..."

    # Install live-boot
    chroot "$WORK_DIR/chroot" apt-get install -y live-boot live-boot-initramfs-tools

    # Configure autologin for live session
    if [[ "$VARIANT" != "minimal" ]]; then
        mkdir -p "$WORK_DIR/chroot/etc/lightdm/lightdm.conf.d"
        cat > "$WORK_DIR/chroot/etc/lightdm/lightdm.conf.d/autologin.conf" << EOF
[Seat:*]
autologin-user=sentinel
autologin-user-timeout=0
EOF
    fi

    # Update initramfs
    chroot "$WORK_DIR/chroot" update-initramfs -u -k all

    log_success "Live system configured"
}

create_squashfs() {
    log_step "Creating squashfs filesystem..."

    # Clean up
    chroot "$WORK_DIR/chroot" apt-get clean
    rm -rf "$WORK_DIR/chroot/var/cache/apt/archives/"*.deb
    rm -rf "$WORK_DIR/chroot/tmp/"*
    rm -rf "$WORK_DIR/chroot/var/tmp/"*

    # Unmount before creating squashfs
    umount -lf "$WORK_DIR/chroot/proc" 2>/dev/null || true
    umount -lf "$WORK_DIR/chroot/sys" 2>/dev/null || true
    umount -lf "$WORK_DIR/chroot/dev/pts" 2>/dev/null || true
    umount -lf "$WORK_DIR/chroot/dev" 2>/dev/null || true
    umount -lf "$WORK_DIR/chroot/run" 2>/dev/null || true

    # Create squashfs
    mksquashfs "$WORK_DIR/chroot" "$WORK_DIR/iso/live/filesystem.squashfs" \
        -comp zstd \
        -Xcompression-level 19 \
        -b 1M \
        -no-duplicates \
        -no-recovery

    log_success "Squashfs created"
}

setup_bootloader() {
    log_step "Setting up bootloader..."

    # Copy kernel and initramfs
    cp "$WORK_DIR/chroot/boot/vmlinuz-"* "$WORK_DIR/iso/live/vmlinuz"
    cp "$WORK_DIR/chroot/boot/initrd.img-"* "$WORK_DIR/iso/live/initrd"

    # ISOLINUX configuration (BIOS boot)
    cp /usr/lib/ISOLINUX/isolinux.bin "$WORK_DIR/iso/isolinux/"
    cp /usr/lib/syslinux/modules/bios/* "$WORK_DIR/iso/isolinux/" 2>/dev/null || true

    cat > "$WORK_DIR/iso/isolinux/isolinux.cfg" << 'EOF'
UI vesamenu.c32
TIMEOUT 50
PROMPT 0
DEFAULT live

MENU TITLE Alphha Security OS 1.0.0 (Sentinel)
MENU COLOR border       30;44   #40ffffff #a0000000 std
MENU COLOR title        1;36;44 #ff00ff41 #a0000000 std
MENU COLOR sel          7;37;40 #e0ffffff #20ff0040 all
MENU COLOR unsel        37;44   #50ffffff #a0000000 std
MENU COLOR help         37;40   #c0ffffff #a0000000 std
MENU COLOR timeout_msg  37;40   #80ffffff #00000000 std
MENU COLOR timeout      1;37;40 #c0ffffff #00000000 std
MENU COLOR hotsel       1;7;37;40 #ffffffff #76a1d0ff *
MENU COLOR hotkey       37;40   #ff00ff41 #a0000000 std

LABEL live
    MENU LABEL ^Alphha Security OS (Live)
    KERNEL /live/vmlinuz
    APPEND initrd=/live/initrd boot=live quiet splash

LABEL forensic
    MENU LABEL ^Forensic Mode (Read-Only)
    KERNEL /live/vmlinuz
    APPEND initrd=/live/initrd boot=live noswap noautomount forensic

LABEL safe
    MENU LABEL ^Safe Mode
    KERNEL /live/vmlinuz
    APPEND initrd=/live/initrd boot=live single nomodeset

LABEL toram
    MENU LABEL ^Load to RAM
    KERNEL /live/vmlinuz
    APPEND initrd=/live/initrd boot=live toram quiet splash
EOF

    # GRUB configuration (UEFI boot)
    cat > "$WORK_DIR/iso/boot/grub/grub.cfg" << 'EOF'
set timeout=5
set default=0

insmod all_video
insmod gfxterm
insmod png

set gfxmode=auto
terminal_output gfxterm

set menu_color_normal=light-gray/black
set menu_color_highlight=green/black

menuentry "Alphha Security OS (Live)" {
    linux /live/vmlinuz boot=live quiet splash
    initrd /live/initrd
}

menuentry "Forensic Mode (Read-Only)" {
    linux /live/vmlinuz boot=live noswap noautomount forensic
    initrd /live/initrd
}

menuentry "Safe Mode" {
    linux /live/vmlinuz boot=live single nomodeset
    initrd /live/initrd
}

menuentry "Load to RAM" {
    linux /live/vmlinuz boot=live toram quiet splash
    initrd /live/initrd
}
EOF

    # Create EFI boot image
    mkdir -p "$WORK_DIR/iso/EFI/boot"
    grub-mkimage \
        -o "$WORK_DIR/iso/EFI/boot/bootx64.efi" \
        -p "/boot/grub" \
        -O x86_64-efi \
        fat iso9660 part_gpt part_msdos normal boot linux configfile loopback chain \
        efifwsetup efi_gop efi_uga ls search search_label search_fs_uuid search_fs_file \
        gfxterm gfxterm_background gfxterm_menu test all_video loadenv exfat ext2 ntfs btrfs \
        hfsplus udf

    # Create EFI FAT image
    dd if=/dev/zero of="$WORK_DIR/iso/boot/grub/efi.img" bs=1M count=10
    mkfs.vfat "$WORK_DIR/iso/boot/grub/efi.img"
    mmd -i "$WORK_DIR/iso/boot/grub/efi.img" ::/EFI
    mmd -i "$WORK_DIR/iso/boot/grub/efi.img" ::/EFI/boot
    mcopy -i "$WORK_DIR/iso/boot/grub/efi.img" "$WORK_DIR/iso/EFI/boot/bootx64.efi" ::/EFI/boot/

    log_success "Bootloader configured"
}

create_iso() {
    log_step "Creating ISO image..."

    mkdir -p "$OUTPUT_DIR"

    local iso_name="alphha-security-${VERSION}-${VARIANT}-${ARCH}.iso"
    local iso_path="$OUTPUT_DIR/$iso_name"

    xorriso -as mkisofs \
        -iso-level 3 \
        -full-iso9660-filenames \
        -volid "ALPHHA_SECURITY" \
        -eltorito-boot isolinux/isolinux.bin \
        -eltorito-catalog isolinux/boot.cat \
        -no-emul-boot \
        -boot-load-size 4 \
        -boot-info-table \
        -isohybrid-mbr /usr/lib/ISOLINUX/isohdpfx.bin \
        -eltorito-alt-boot \
        -e boot/grub/efi.img \
        -no-emul-boot \
        -isohybrid-gpt-basdat \
        -output "$iso_path" \
        "$WORK_DIR/iso"

    # Generate checksums
    log_info "Generating checksums..."
    cd "$OUTPUT_DIR"
    sha256sum "$iso_name" > "${iso_name}.sha256"
    md5sum "$iso_name" > "${iso_name}.md5"

    log_success "ISO created: $iso_path"
    log_info "SHA256: $(cat "${iso_name}.sha256")"
}

#-------------------------------------------------------------------------------
# Main
#-------------------------------------------------------------------------------
main() {
    print_banner
    parse_args "$@"
    check_root
    check_dependencies

    log_info "Building Alphha Security OS..."
    log_info "Variant: $VARIANT"
    log_info "Architecture: $ARCH"
    log_info "Output: $OUTPUT_DIR"
    log_info "Include Kali: $INCLUDE_KALI"
    echo ""

    setup_work_directory
    run_debootstrap
    setup_chroot_mounts
    configure_apt_sources
    install_packages
    configure_system
    create_default_user
    configure_security_hardening
    setup_branding
    install_custom_tools
    configure_live_system
    create_squashfs
    setup_bootloader
    create_iso

    # Cleanup work directory on success
    rm -rf "$WORK_DIR"

    echo ""
    log_success "Build completed successfully!"
    log_info "ISO: $OUTPUT_DIR/alphha-security-${VERSION}-${VARIANT}-${ARCH}.iso"
    echo ""
    echo -e "${CYAN}To test the ISO:${NC}"
    echo "  qemu-system-x86_64 -m 4G -cdrom $OUTPUT_DIR/alphha-security-${VERSION}-${VARIANT}-${ARCH}.iso -boot d"
    echo ""
}

main "$@"
