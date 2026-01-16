#!/bin/bash
#===============================================================================
#
#          FILE: build-alphha-security-vm.sh
#
#         USAGE: sudo ./build-alphha-security-vm.sh [OPTIONS]
#
#   DESCRIPTION: Build script for Alphha Security OS VM/Cloud images
#                Creates QCOW2 images optimized for virtual environments.
#
#       OPTIONS: --size <GB>     Disk size in GB (default: 20)
#                --output <dir>  Output directory
#                --cloud-init    Include cloud-init support
#                --help          Show help
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
readonly VERSION="1.0.0"
readonly CODENAME="Sentinel"
readonly OS_NAME="Alphha Security OS"
readonly BUILD_DATE="$(date -u +%Y%m%d)"

# Default options
DISK_SIZE=20
OUTPUT_DIR="${SCRIPT_DIR}/output"
CLOUD_INIT=true
WORK_DIR=""

# Debian base
readonly DEBIAN_MIRROR="http://deb.debian.org/debian"
readonly DEBIAN_SUITE="bookworm"

#-------------------------------------------------------------------------------
# Colors and Logging
#-------------------------------------------------------------------------------
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[0;33m'
readonly CYAN='\033[0;36m'
readonly NC='\033[0m'

log_info()    { echo -e "${GREEN}[INFO]${NC} $*"; }
log_warn()    { echo -e "${YELLOW}[WARN]${NC} $*"; }
log_error()   { echo -e "${RED}[ERROR]${NC} $*" >&2; }
log_step()    { echo -e "${CYAN}[STEP]${NC} $*"; }

print_banner() {
    echo -e "${GREEN}"
    cat << 'EOF'
    _    _       _     _
   / \  | |_ __ | |__ | |__   __ _
  / _ \ | | '_ \| '_ \| '_ \ / _` |
 / ___ \| | |_) | | | | | | | (_| |
/_/   \_\_| .__/|_| |_|_| |_|\__,_|
          |_|  VM Image Builder
EOF
    echo -e "${NC}"
    echo -e "${CYAN}Version: ${VERSION} (${CODENAME})${NC}"
    echo ""
}

usage() {
    cat << EOF
Usage: sudo $0 [OPTIONS]

Build Alphha Security OS VM image.

OPTIONS:
    --size <GB>     Disk size in GB (default: 20)
    --output <dir>  Output directory (default: ./output)
    --no-cloud      Disable cloud-init
    --help          Show this help

EXAMPLES:
    sudo $0
    sudo $0 --size 30 --output /tmp/images

COPYRIGHT:
    Copyright (c) 2026 Alphha Team

EOF
    exit 0
}

#-------------------------------------------------------------------------------
# Argument Parsing
#-------------------------------------------------------------------------------
parse_args() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --size)
                DISK_SIZE="$2"
                shift 2
                ;;
            --output)
                OUTPUT_DIR="$2"
                shift 2
                ;;
            --no-cloud)
                CLOUD_INIT=false
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
}

#-------------------------------------------------------------------------------
# Prerequisites
#-------------------------------------------------------------------------------
check_root() {
    if [[ $EUID -ne 0 ]]; then
        log_error "This script must be run as root"
        exit 1
    fi
}

check_dependencies() {
    log_step "Checking dependencies..."

    local deps=(debootstrap qemu-img qemu-nbd parted kpartx)
    local missing=()

    for dep in "${deps[@]}"; do
        if ! command -v "$dep" &>/dev/null; then
            missing+=("$dep")
        fi
    done

    if [[ ${#missing[@]} -gt 0 ]]; then
        log_warn "Missing: ${missing[*]}"
        apt-get update && apt-get install -y "${missing[@]}" qemu-utils
    fi
}

#-------------------------------------------------------------------------------
# Cleanup
#-------------------------------------------------------------------------------
cleanup() {
    log_info "Cleaning up..."

    # Unmount chroot
    if [[ -n "${WORK_DIR:-}" && -d "$WORK_DIR/mnt" ]]; then
        umount -lf "$WORK_DIR/mnt/proc" 2>/dev/null || true
        umount -lf "$WORK_DIR/mnt/sys" 2>/dev/null || true
        umount -lf "$WORK_DIR/mnt/dev/pts" 2>/dev/null || true
        umount -lf "$WORK_DIR/mnt/dev" 2>/dev/null || true
        umount -lf "$WORK_DIR/mnt/boot/efi" 2>/dev/null || true
        umount -lf "$WORK_DIR/mnt/boot" 2>/dev/null || true
        umount -lf "$WORK_DIR/mnt" 2>/dev/null || true
    fi

    # Disconnect NBD
    if [[ -e /dev/nbd0p1 ]]; then
        qemu-nbd --disconnect /dev/nbd0 2>/dev/null || true
    fi

    # Remove loop devices
    losetup -D 2>/dev/null || true
}

trap cleanup EXIT INT TERM

#-------------------------------------------------------------------------------
# Create Disk Image
#-------------------------------------------------------------------------------
create_disk_image() {
    log_step "Creating ${DISK_SIZE}GB QCOW2 disk image..."

    WORK_DIR=$(mktemp -d -t alphha-vm-XXXXXX)
    local image_path="$WORK_DIR/disk.qcow2"

    qemu-img create -f qcow2 "$image_path" "${DISK_SIZE}G"

    # Load NBD module
    modprobe nbd max_part=16

    # Connect image to NBD
    qemu-nbd --connect=/dev/nbd0 "$image_path"
    sleep 2

    log_info "Disk image created: $image_path"
}

#-------------------------------------------------------------------------------
# Partition Disk
#-------------------------------------------------------------------------------
partition_disk() {
    log_step "Partitioning disk..."

    parted -s /dev/nbd0 mklabel gpt
    parted -s /dev/nbd0 mkpart ESP fat32 1MiB 257MiB
    parted -s /dev/nbd0 set 1 esp on
    parted -s /dev/nbd0 mkpart primary ext4 257MiB 769MiB
    parted -s /dev/nbd0 mkpart primary ext4 769MiB 100%

    sleep 2
    partprobe /dev/nbd0

    # Format partitions
    mkfs.vfat -F32 /dev/nbd0p1
    mkfs.ext4 -F /dev/nbd0p2
    mkfs.ext4 -F /dev/nbd0p3

    log_info "Partitioning complete"
}

#-------------------------------------------------------------------------------
# Mount and Install Base
#-------------------------------------------------------------------------------
install_base_system() {
    log_step "Installing base system..."

    mkdir -p "$WORK_DIR/mnt"
    mount /dev/nbd0p3 "$WORK_DIR/mnt"
    mkdir -p "$WORK_DIR/mnt/boot"
    mount /dev/nbd0p2 "$WORK_DIR/mnt/boot"
    mkdir -p "$WORK_DIR/mnt/boot/efi"
    mount /dev/nbd0p1 "$WORK_DIR/mnt/boot/efi"

    # Run debootstrap
    debootstrap --arch=amd64 --variant=minbase \
        --include=systemd,systemd-sysv,dbus,locales \
        "$DEBIAN_SUITE" "$WORK_DIR/mnt" "$DEBIAN_MIRROR"

    log_info "Base system installed"
}

#-------------------------------------------------------------------------------
# Configure System
#-------------------------------------------------------------------------------
configure_system() {
    log_step "Configuring system..."

    local mnt="$WORK_DIR/mnt"

    # Mount virtual filesystems
    mount --bind /dev "$mnt/dev"
    mount --bind /dev/pts "$mnt/dev/pts"
    mount -t proc proc "$mnt/proc"
    mount -t sysfs sysfs "$mnt/sys"

    # Configure APT
    cat > "$mnt/etc/apt/sources.list" << EOF
deb http://deb.debian.org/debian bookworm main contrib non-free non-free-firmware
deb http://deb.debian.org/debian bookworm-updates main contrib non-free non-free-firmware
deb http://security.debian.org/debian-security bookworm-security main contrib non-free non-free-firmware
EOF

    # Install packages
    chroot "$mnt" bash -c "
        export DEBIAN_FRONTEND=noninteractive
        apt-get update
        apt-get install -y \
            linux-image-cloud-amd64 \
            grub-efi-amd64 \
            efibootmgr \
            sudo \
            openssh-server \
            curl \
            wget \
            vim \
            git \
            htop \
            tmux \
            nmap \
            netcat-openbsd \
            python3 \
            python3-pip \
            $([ '$CLOUD_INIT' == true ] && echo 'cloud-init cloud-guest-utils')
    "

    # Configure hostname
    echo "alphha-sec" > "$mnt/etc/hostname"
    cat > "$mnt/etc/hosts" << EOF
127.0.0.1   localhost
127.0.1.1   alphha-sec
::1         localhost ip6-localhost ip6-loopback
EOF

    # Create os-release
    cat > "$mnt/etc/os-release" << EOF
NAME="Alphha Security OS"
VERSION="$VERSION ($CODENAME)"
ID=alphha
ID_LIKE=debian
VERSION_ID="$VERSION"
VERSION_CODENAME="$CODENAME"
PRETTY_NAME="Alphha Security OS $VERSION ($CODENAME)"
HOME_URL="https://alphha.io"
EOF

    # Configure locale
    echo "en_US.UTF-8 UTF-8" > "$mnt/etc/locale.gen"
    chroot "$mnt" locale-gen

    # Configure timezone
    chroot "$mnt" ln -sf /usr/share/zoneinfo/UTC /etc/localtime

    # Create user
    chroot "$mnt" useradd -m -s /bin/bash -G sudo sentinel
    echo "sentinel:alphha" | chroot "$mnt" chpasswd
    echo "sentinel ALL=(ALL) NOPASSWD: ALL" > "$mnt/etc/sudoers.d/sentinel"

    # Configure SSH
    cat > "$mnt/etc/ssh/sshd_config.d/alphha.conf" << EOF
PermitRootLogin no
PasswordAuthentication yes
PubkeyAuthentication yes
MaxAuthTries 3
EOF

    # Configure networking
    cat > "$mnt/etc/network/interfaces" << EOF
auto lo
iface lo inet loopback

auto eth0
iface eth0 inet dhcp
EOF

    # Generate fstab
    cat > "$mnt/etc/fstab" << EOF
# Alphha Security OS fstab
UUID=$(blkid -s UUID -o value /dev/nbd0p3) /         ext4 defaults 0 1
UUID=$(blkid -s UUID -o value /dev/nbd0p2) /boot     ext4 defaults 0 2
UUID=$(blkid -s UUID -o value /dev/nbd0p1) /boot/efi vfat defaults 0 2
EOF

    log_info "System configured"
}

#-------------------------------------------------------------------------------
# Install Bootloader
#-------------------------------------------------------------------------------
install_bootloader() {
    log_step "Installing bootloader..."

    local mnt="$WORK_DIR/mnt"

    # Install GRUB
    chroot "$mnt" grub-install --target=x86_64-efi --efi-directory=/boot/efi --bootloader-id=alphha --removable

    # Configure GRUB
    cat > "$mnt/etc/default/grub" << EOF
GRUB_DEFAULT=0
GRUB_TIMEOUT=3
GRUB_DISTRIBUTOR="Alphha Security OS"
GRUB_CMDLINE_LINUX_DEFAULT="quiet"
GRUB_CMDLINE_LINUX="console=tty0 console=ttyS0,115200n8"
GRUB_TERMINAL="console serial"
GRUB_SERIAL_COMMAND="serial --speed=115200 --unit=0 --word=8 --parity=no --stop=1"
EOF

    chroot "$mnt" update-grub
    chroot "$mnt" update-initramfs -u

    log_info "Bootloader installed"
}

#-------------------------------------------------------------------------------
# Finalize Image
#-------------------------------------------------------------------------------
finalize_image() {
    log_step "Finalizing image..."

    local mnt="$WORK_DIR/mnt"

    # Cleanup
    chroot "$mnt" apt-get clean
    rm -rf "$mnt/var/cache/apt/archives/"*.deb
    rm -rf "$mnt/tmp/"*

    # Unmount
    umount "$mnt/proc"
    umount "$mnt/sys"
    umount "$mnt/dev/pts"
    umount "$mnt/dev"
    umount "$mnt/boot/efi"
    umount "$mnt/boot"
    umount "$mnt"

    # Disconnect NBD
    qemu-nbd --disconnect /dev/nbd0
    sleep 2

    # Move and compress
    mkdir -p "$OUTPUT_DIR"
    local output_name="alphha-security-${VERSION}-vm-amd64.qcow2"

    # Compress the image
    log_info "Compressing image..."
    qemu-img convert -c -f qcow2 -O qcow2 "$WORK_DIR/disk.qcow2" "$OUTPUT_DIR/$output_name"

    # Generate checksum
    cd "$OUTPUT_DIR"
    sha256sum "$output_name" > "${output_name}.sha256"

    log_info "Image created: $OUTPUT_DIR/$output_name"
    log_info "Size: $(du -h "$OUTPUT_DIR/$output_name" | cut -f1)"
}

#-------------------------------------------------------------------------------
# Main
#-------------------------------------------------------------------------------
main() {
    print_banner
    parse_args "$@"
    check_root
    check_dependencies

    log_info "Building Alphha Security OS VM image..."
    log_info "Disk size: ${DISK_SIZE}GB"
    log_info "Cloud-init: $CLOUD_INIT"
    log_info "Output: $OUTPUT_DIR"
    echo ""

    create_disk_image
    partition_disk
    install_base_system
    configure_system
    install_bootloader
    finalize_image

    # Cleanup work directory
    rm -rf "$WORK_DIR"

    echo ""
    log_info "Build complete!"
    echo ""
    echo -e "${CYAN}To test the image:${NC}"
    echo "  qemu-system-x86_64 -m 2G -hda $OUTPUT_DIR/alphha-security-${VERSION}-vm-amd64.qcow2 -enable-kvm"
    echo ""
}

main "$@"
