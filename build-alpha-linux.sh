#!/bin/bash
#===============================================================================
# Alpha Linux VM Builder
# Ultra-lightweight Debian-based Linux distribution
# Version: 1.0.0
#===============================================================================

set -euo pipefail

readonly VM_NAME="alpha-linux"
readonly VERSION="1.0.0"
readonly ARCH="amd64"
readonly DEBIAN_RELEASE="bookworm"
readonly DISK_SIZE="4G"
readonly BUILD_DIR="/tmp/alpha-build"
readonly OUTPUT_DIR="./output"

readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly NC='\033[0m'

log_info() { echo -e "${GREEN}[INFO]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; exit 1; }

check_prerequisites() {
    log_info "Checking prerequisites..."
    [[ $EUID -eq 0 ]] || log_error "This script must be run as root"
    local required_tools=("debootstrap" "qemu-img" "qemu-nbd" "parted" "mkfs.ext4" "mkfs.vfat")
    for tool in "${required_tools[@]}"; do
        command -v "$tool" &>/dev/null || log_error "Required tool not found: $tool"
    done
    log_info "All prerequisites satisfied"
}

create_disk_image() {
    log_info "Creating disk image..."
    mkdir -p "$BUILD_DIR" "$OUTPUT_DIR"
    qemu-img create -f qcow2 "${BUILD_DIR}/${VM_NAME}.qcow2" "$DISK_SIZE"
    log_info "Loading NBD module..."
    modprobe nbd max_part=8
    qemu-nbd --connect=/dev/nbd0 "${BUILD_DIR}/${VM_NAME}.qcow2"
    sleep 2
}

partition_disk() {
    log_info "Partitioning disk..."
    parted -s /dev/nbd0 mklabel gpt
    parted -s /dev/nbd0 mkpart efi fat32 1MiB 129MiB
    parted -s /dev/nbd0 set 1 esp on
    parted -s /dev/nbd0 mkpart boot ext4 129MiB 385MiB
    parted -s /dev/nbd0 mkpart root ext4 385MiB 100%
    sleep 1 && partprobe /dev/nbd0 && sleep 1
    log_info "Formatting partitions..."
    mkfs.vfat -F32 -n EFI /dev/nbd0p1
    mkfs.ext4 -L boot /dev/nbd0p2
    mkfs.ext4 -L root /dev/nbd0p3
}

mount_filesystems() {
    log_info "Mounting filesystems..."
    mkdir -p "${BUILD_DIR}/rootfs"
    mount /dev/nbd0p3 "${BUILD_DIR}/rootfs"
    mkdir -p "${BUILD_DIR}/rootfs/boot"
    mount /dev/nbd0p2 "${BUILD_DIR}/rootfs/boot"
    mkdir -p "${BUILD_DIR}/rootfs/boot/efi"
    mount /dev/nbd0p1 "${BUILD_DIR}/rootfs/boot/efi"
}

install_base_system() {
    log_info "Installing minimal base system..."
    debootstrap --variant=minbase --arch="$ARCH" --components=main \
        --include=systemd,systemd-sysv,dbus \
        "$DEBIAN_RELEASE" "${BUILD_DIR}/rootfs" http://deb.debian.org/debian
}

setup_chroot() {
    log_info "Setting up chroot environment..."
    mount --bind /dev "${BUILD_DIR}/rootfs/dev"
    mount --bind /dev/pts "${BUILD_DIR}/rootfs/dev/pts"
    mount -t proc proc "${BUILD_DIR}/rootfs/proc"
    mount -t sysfs sysfs "${BUILD_DIR}/rootfs/sys"
    mount --bind /run "${BUILD_DIR}/rootfs/run"
    cp /etc/resolv.conf "${BUILD_DIR}/rootfs/etc/resolv.conf"
}

install_packages() {
    log_info "Installing essential packages..."
    chroot "${BUILD_DIR}/rootfs" /bin/bash -c "
        export DEBIAN_FRONTEND=noninteractive
        cat > /etc/apt/apt.conf.d/99minimal << EOF
APT::Install-Recommends \"false\";
APT::Install-Suggests \"false\";
Acquire::Languages \"none\";
EOF
        apt-get update
        apt-get install -y --no-install-recommends \
            linux-image-cloud-amd64 systemd-boot openssh-server sudo curl \
            ca-certificates iproute2 iputils-ping procps less cloud-init cloud-guest-utils
    "
}

configure_system() {
    log_info "Configuring system..."
    local rootfs="${BUILD_DIR}/rootfs"
    echo "alpha" > "${rootfs}/etc/hostname"
    cat > "${rootfs}/etc/hosts" << EOF
127.0.0.1   localhost
127.0.1.1   alpha
::1         localhost ip6-localhost ip6-loopback
EOF
    echo "C.UTF-8 UTF-8" > "${rootfs}/etc/locale.gen"
    echo "LANG=C.UTF-8" > "${rootfs}/etc/default/locale"
    ln -sf /usr/share/zoneinfo/UTC "${rootfs}/etc/localtime"
    cat > "${rootfs}/etc/fstab" << EOF
LABEL=root  /           ext4    defaults,noatime,discard    0 1
LABEL=boot  /boot       ext4    defaults,noatime            0 2
LABEL=EFI   /boot/efi   vfat    defaults,umask=0077         0 1
EOF
}

configure_network() {
    log_info "Configuring network..."
    local rootfs="${BUILD_DIR}/rootfs"
    mkdir -p "${rootfs}/etc/systemd/network"
    cat > "${rootfs}/etc/systemd/network/10-eth0.network" << EOF
[Match]
Name=eth0

[Network]
DHCP=yes
IPv6AcceptRA=yes

[DHCPv4]
UseDNS=yes
UseNTP=yes
EOF
    chroot "${rootfs}" systemctl enable systemd-networkd systemd-resolved
}

configure_security() {
    log_info "Applying security hardening..."
    local rootfs="${BUILD_DIR}/rootfs"
    mkdir -p "${rootfs}/etc/ssh/sshd_config.d"
    cat > "${rootfs}/etc/ssh/sshd_config.d/hardening.conf" << EOF
PermitRootLogin no
PasswordAuthentication no
PubkeyAuthentication yes
PermitEmptyPasswords no
X11Forwarding no
AllowTcpForwarding no
MaxAuthTries 3
Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com
MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com
KexAlgorithms curve25519-sha256,curve25519-sha256@libssh.org
EOF
    cat > "${rootfs}/etc/sysctl.d/99-hardening.conf" << EOF
kernel.dmesg_restrict = 1
kernel.kptr_restrict = 2
kernel.randomize_va_space = 2
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.all.rp_filter = 1
net.ipv4.tcp_syncookies = 1
fs.protected_hardlinks = 1
fs.protected_symlinks = 1
vm.swappiness = 10
EOF
}

create_user() {
    log_info "Creating default user..."
    chroot "${BUILD_DIR}/rootfs" useradd -m -s /bin/bash -G sudo,adm alpha
    echo "alpha ALL=(ALL) NOPASSWD:ALL" > "${BUILD_DIR}/rootfs/etc/sudoers.d/alpha"
    chmod 440 "${BUILD_DIR}/rootfs/etc/sudoers.d/alpha"
    chroot "${BUILD_DIR}/rootfs" passwd -l root
    mkdir -p "${BUILD_DIR}/rootfs/home/alpha/.ssh"
    chmod 700 "${BUILD_DIR}/rootfs/home/alpha/.ssh"
    chroot "${BUILD_DIR}/rootfs" chown -R alpha:alpha /home/alpha/.ssh
}

configure_bootloader() {
    log_info "Configuring bootloader..."
    local rootfs="${BUILD_DIR}/rootfs"
    chroot "${rootfs}" bootctl install --esp-path=/boot/efi 2>/dev/null || true
    local kver=$(ls "${rootfs}/boot/vmlinuz-"* | head -1 | sed 's|.*/vmlinuz-||')
    mkdir -p "${rootfs}/boot/efi/loader/entries"
    cat > "${rootfs}/boot/efi/loader/entries/alpha.conf" << EOF
title   Alpha Linux
linux   /vmlinuz-${kver}
initrd  /initrd.img-${kver}
options root=LABEL=root rw quiet loglevel=3 net.ifnames=0
EOF
    cat > "${rootfs}/boot/efi/loader/loader.conf" << EOF
default alpha.conf
timeout 0
editor no
EOF
    cp "${rootfs}/boot/vmlinuz-${kver}" "${rootfs}/boot/efi/"
    cp "${rootfs}/boot/initrd.img-${kver}" "${rootfs}/boot/efi/"
}

cleanup() {
    log_info "Cleaning up..."
    chroot "${BUILD_DIR}/rootfs" /bin/bash -c "
        apt-get clean && apt-get autoremove --purge -y
        rm -rf /var/lib/apt/lists/* /var/cache/apt/* /usr/share/doc/* /usr/share/man/*
        find /var/log -type f -delete
        truncate -s 0 /etc/machine-id
    "
}

finalize() {
    log_info "Finalizing..."
    umount -R "${BUILD_DIR}/rootfs" 2>/dev/null || true
    qemu-nbd --disconnect /dev/nbd0 && sleep 2
    qemu-img convert -c -O qcow2 "${BUILD_DIR}/${VM_NAME}.qcow2" "${OUTPUT_DIR}/${VM_NAME}-${VERSION}.qcow2"
    sha256sum "${OUTPUT_DIR}/${VM_NAME}-${VERSION}.qcow2" > "${OUTPUT_DIR}/${VM_NAME}-${VERSION}.qcow2.sha256"
    rm -rf "${BUILD_DIR}"
    log_info "Build complete: ${OUTPUT_DIR}/${VM_NAME}-${VERSION}.qcow2"
}

trap 'umount -R "${BUILD_DIR}/rootfs" 2>/dev/null; qemu-nbd --disconnect /dev/nbd0 2>/dev/null; rm -rf "${BUILD_DIR}"' ERR

main() {
    check_prerequisites && create_disk_image && partition_disk && mount_filesystems
    install_base_system && setup_chroot && install_packages && configure_system
    configure_network && configure_security && create_user && configure_bootloader
    cleanup && finalize
}

main "$@"
