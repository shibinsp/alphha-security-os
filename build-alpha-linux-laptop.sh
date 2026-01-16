#!/bin/bash
#===============================================================================
# Alpha Linux Laptop ISO Builder
# Bare-metal installation ISO with multiple desktop variants
# Version: 2.0.0
#===============================================================================

set -euo pipefail

# Configuration
readonly VERSION="2.0.0"
readonly CODENAME="alpha"
readonly DEBIAN_RELEASE="bookworm"
readonly ARCH="amd64"
readonly BUILD_DIR="/tmp/alpha-laptop-build"
readonly OUTPUT_DIR="./output"
readonly WORK_DIR="${BUILD_DIR}/work"
readonly ROOTFS="${BUILD_DIR}/rootfs"

# Colors
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly BLUE='\033[0;34m'
readonly NC='\033[0m'

# Default variant
VARIANT="${1:-sway}"

log_info() { echo -e "${GREEN}[INFO]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; exit 1; }
log_step() { echo -e "${BLUE}[STEP]${NC} $1"; }

#===============================================================================
# Package Lists
#===============================================================================
PACKAGES_CORE=(
    # Base system
    systemd systemd-sysv dbus dbus-user-session
    linux-image-amd64 linux-headers-amd64
    initramfs-tools
    grub-efi-amd64 grub-pc-bin efibootmgr
    btrfs-progs e2fsprogs dosfstools xfsprogs
    cryptsetup lvm2 mdadm
    
    # Firmware
    firmware-linux-free firmware-linux-nonfree firmware-misc-nonfree
    amd64-microcode intel-microcode
    firmware-iwlwifi firmware-realtek firmware-atheros
    firmware-amd-graphics
    sof-firmware
    
    # Networking
    networkmanager iwd
    wpasupplicant wireless-tools iw rfkill
    iproute2 iputils-ping
    openssh-client openssh-server
    ca-certificates curl wget
    
    # Audio
    pipewire pipewire-alsa pipewire-pulse wireplumber
    alsa-utils
    
    # Power management
    tlp acpi acpid upower thermald
    
    # Core utilities
    sudo polkit rtkit udisks2
    gvfs gvfs-backends
    htop btop neofetch
    vim nano less
    git rsync
    unzip p7zip-full
    bash-completion man-db
    locales console-setup
    
    # Security
    apparmor apparmor-utils
    openssl gnupg
    
    # Fonts
    fonts-dejavu-core fonts-liberation2
    fonts-noto-core fonts-noto-color-emoji
    
    # Installer dependencies
    dialog parted arch-install-scripts
    debootstrap squashfs-tools xorriso
    isolinux syslinux-common
)

PACKAGES_SWAY=(
    sway swaylock swayidle swaybg
    waybar wofi foot
    mako-notifier kanshi
    wl-clipboard grim slurp
    xdg-desktop-portal-wlr xwayland
    thunar imv mpv
    firefox-esr
    papirus-icon-theme
    brightnessctl playerctl pamixer
)

PACKAGES_XFCE=(
    xfce4 xfce4-terminal xfce4-whiskermenu-plugin
    xfce4-pulseaudio-plugin xfce4-notifyd
    xfce4-power-manager xfce4-screenshooter xfce4-taskmanager
    lightdm lightdm-gtk-greeter
    thunar thunar-archive-plugin thunar-volman
    ristretto mousepad parole
    firefox-esr
    xorg xserver-xorg-input-libinput
    papirus-icon-theme
)

PACKAGES_GNOME=(
    gnome-shell gnome-session gnome-control-center
    gnome-terminal gnome-tweaks
    nautilus gdm3
    gnome-keyring gnome-disk-utility
    eog evince gedit
    firefox-esr
    xdg-desktop-portal-gnome
)

PACKAGES_MINIMAL=()

#===============================================================================
# Prerequisites Check
#===============================================================================
check_prerequisites() {
    log_step "Checking prerequisites..."
    
    [[ $EUID -eq 0 ]] || log_error "This script must be run as root"
    
    local required_tools=(
        debootstrap mksquashfs xorriso
        parted mkfs.ext4 mkfs.vfat mkfs.btrfs
    )
    
    for tool in "${required_tools[@]}"; do
        command -v "$tool" &>/dev/null || {
            log_warn "Installing missing tool: $tool"
            apt-get update && apt-get install -y squashfs-tools xorriso parted \
                dosfstools btrfs-progs debootstrap grub-efi-amd64-bin \
                grub-pc-bin isolinux syslinux-common
        }
    done
    
    log_info "All prerequisites satisfied"
}

#===============================================================================
# Select Variant
#===============================================================================
select_variant() {
    log_step "Selected variant: ${VARIANT}"
    
    case "$VARIANT" in
        minimal)
            DESKTOP_PACKAGES=("${PACKAGES_MINIMAL[@]}")
            ;;
        sway)
            DESKTOP_PACKAGES=("${PACKAGES_SWAY[@]}")
            ;;
        xfce)
            DESKTOP_PACKAGES=("${PACKAGES_XFCE[@]}")
            ;;
        gnome)
            DESKTOP_PACKAGES=("${PACKAGES_GNOME[@]}")
            ;;
        *)
            log_error "Unknown variant: $VARIANT (use: minimal, sway, xfce, gnome)"
            ;;
    esac
}

#===============================================================================
# Setup Build Environment
#===============================================================================
setup_build_env() {
    log_step "Setting up build environment..."
    
    rm -rf "$BUILD_DIR"
    mkdir -p "$BUILD_DIR"/{rootfs,iso/{live,boot/grub,isolinux,EFI/boot},work}
    
    log_info "Build directory created: $BUILD_DIR"
}

#===============================================================================
# Bootstrap Base System
#===============================================================================
bootstrap_system() {
    log_step "Bootstrapping Debian base system..."
    
    debootstrap \
        --variant=minbase \
        --arch="$ARCH" \
        --components=main,contrib,non-free,non-free-firmware \
        "$DEBIAN_RELEASE" \
        "$ROOTFS" \
        http://deb.debian.org/debian
    
    log_info "Base system bootstrapped"
}

#===============================================================================
# Configure APT Sources
#===============================================================================
configure_apt() {
    log_step "Configuring APT sources..."
    
    cat > "${ROOTFS}/etc/apt/sources.list" << EOF
deb http://deb.debian.org/debian ${DEBIAN_RELEASE} main contrib non-free non-free-firmware
deb http://deb.debian.org/debian ${DEBIAN_RELEASE}-updates main contrib non-free non-free-firmware
deb http://security.debian.org/debian-security ${DEBIAN_RELEASE}-security main contrib non-free non-free-firmware
EOF

    cat > "${ROOTFS}/etc/apt/apt.conf.d/99alpha" << EOF
APT::Install-Recommends "false";
APT::Install-Suggests "false";
APT::AutoRemove::RecommendsImportant "false";
Acquire::Languages "none";
EOF
}

#===============================================================================
# Mount Virtual Filesystems
#===============================================================================
mount_vfs() {
    log_step "Mounting virtual filesystems..."
    
    mount --bind /dev "${ROOTFS}/dev"
    mount --bind /dev/pts "${ROOTFS}/dev/pts"
    mount -t proc proc "${ROOTFS}/proc"
    mount -t sysfs sysfs "${ROOTFS}/sys"
    mount -t tmpfs tmpfs "${ROOTFS}/run"
    
    cp /etc/resolv.conf "${ROOTFS}/etc/resolv.conf"
}

#===============================================================================
# Unmount Virtual Filesystems
#===============================================================================
umount_vfs() {
    log_step "Unmounting virtual filesystems..."
    
    umount -l "${ROOTFS}/run" 2>/dev/null || true
    umount -l "${ROOTFS}/sys" 2>/dev/null || true
    umount -l "${ROOTFS}/proc" 2>/dev/null || true
    umount -l "${ROOTFS}/dev/pts" 2>/dev/null || true
    umount -l "${ROOTFS}/dev" 2>/dev/null || true
}

#===============================================================================
# Install Packages
#===============================================================================
install_packages() {
    log_step "Installing packages (this may take a while)..."
    
    # Combine all packages
    local all_packages=("${PACKAGES_CORE[@]}" "${DESKTOP_PACKAGES[@]}")
    
    chroot "$ROOTFS" /bin/bash -c "
        export DEBIAN_FRONTEND=noninteractive
        apt-get update
        apt-get install -y ${all_packages[*]}
    "
    
    log_info "Packages installed"
}

#===============================================================================
# Configure System
#===============================================================================
configure_system() {
    log_step "Configuring system..."
    
    # Hostname
    echo "alpha-live" > "${ROOTFS}/etc/hostname"
    cat > "${ROOTFS}/etc/hosts" << EOF
127.0.0.1   localhost
127.0.1.1   alpha-live alpha
::1         localhost ip6-localhost ip6-loopback
EOF

    # Locale
    echo "en_US.UTF-8 UTF-8" > "${ROOTFS}/etc/locale.gen"
    echo "C.UTF-8 UTF-8" >> "${ROOTFS}/etc/locale.gen"
    chroot "$ROOTFS" locale-gen
    echo "LANG=en_US.UTF-8" > "${ROOTFS}/etc/default/locale"
    
    # Timezone
    ln -sf /usr/share/zoneinfo/UTC "${ROOTFS}/etc/localtime"
    echo "UTC" > "${ROOTFS}/etc/timezone"
    
    # Keyboard
    cat > "${ROOTFS}/etc/default/keyboard" << EOF
XKBMODEL="pc105"
XKBLAYOUT="us"
XKBVARIANT=""
XKBOPTIONS="ctrl:nocaps"
EOF

    # Create live user
    chroot "$ROOTFS" useradd -m -s /bin/bash -G sudo,adm,cdrom,audio,video,plugdev,netdev,bluetooth alpha
    echo "alpha:alpha" | chroot "$ROOTFS" chpasswd
    echo "alpha ALL=(ALL) NOPASSWD:ALL" > "${ROOTFS}/etc/sudoers.d/alpha"
    chmod 440 "${ROOTFS}/etc/sudoers.d/alpha"
    
    # Enable autologin for live session
    mkdir -p "${ROOTFS}/etc/systemd/system/getty@tty1.service.d"
    cat > "${ROOTFS}/etc/systemd/system/getty@tty1.service.d/autologin.conf" << EOF
[Service]
ExecStart=
ExecStart=-/sbin/agetty --autologin alpha --noclear %I \$TERM
EOF
    
    log_info "System configured"
}

#===============================================================================
# Configure Desktop Environment
#===============================================================================
configure_desktop() {
    log_step "Configuring desktop environment: ${VARIANT}..."
    
    case "$VARIANT" in
        sway)
            configure_sway
            ;;
        xfce)
            configure_xfce
            ;;
        gnome)
            configure_gnome
            ;;
        minimal)
            log_info "No desktop to configure (minimal variant)"
            ;;
    esac
}

configure_sway() {
    mkdir -p "${ROOTFS}/home/alpha/.config/sway"
    cat > "${ROOTFS}/home/alpha/.config/sway/config" << 'EOF'
# Alpha Linux Sway Configuration

# Variables
set $mod Mod4
set $term foot
set $menu wofi --show drun

# Output
output * bg #1a1a2e solid_color

# Input
input type:touchpad {
    tap enabled
    natural_scroll enabled
    dwt enabled
}

# Key bindings
bindsym $mod+Return exec $term
bindsym $mod+d exec $menu
bindsym $mod+Shift+q kill
bindsym $mod+Shift+c reload
bindsym $mod+Shift+e exec swaynag -t warning -m 'Exit sway?' -B 'Yes' 'swaymsg exit'

# Focus
bindsym $mod+Left focus left
bindsym $mod+Down focus down
bindsym $mod+Up focus up
bindsym $mod+Right focus right

# Move
bindsym $mod+Shift+Left move left
bindsym $mod+Shift+Down move down
bindsym $mod+Shift+Up move up
bindsym $mod+Shift+Right move right

# Workspaces
bindsym $mod+1 workspace number 1
bindsym $mod+2 workspace number 2
bindsym $mod+3 workspace number 3
bindsym $mod+4 workspace number 4
bindsym $mod+5 workspace number 5

bindsym $mod+Shift+1 move container to workspace number 1
bindsym $mod+Shift+2 move container to workspace number 2
bindsym $mod+Shift+3 move container to workspace number 3
bindsym $mod+Shift+4 move container to workspace number 4
bindsym $mod+Shift+5 move container to workspace number 5

# Layout
bindsym $mod+b splith
bindsym $mod+v splitv
bindsym $mod+f fullscreen toggle
bindsym $mod+Shift+space floating toggle
bindsym $mod+space focus mode_toggle

# Resize
mode "resize" {
    bindsym Left resize shrink width 10px
    bindsym Down resize grow height 10px
    bindsym Up resize shrink height 10px
    bindsym Right resize grow width 10px
    bindsym Escape mode "default"
}
bindsym $mod+r mode "resize"

# Media keys
bindsym XF86AudioRaiseVolume exec pamixer -i 5
bindsym XF86AudioLowerVolume exec pamixer -d 5
bindsym XF86AudioMute exec pamixer -t
bindsym XF86MonBrightnessUp exec brightnessctl set +5%
bindsym XF86MonBrightnessDown exec brightnessctl set 5%-

# Appearance
default_border pixel 2
gaps inner 5
client.focused #6272a4 #6272a4 #f8f8f2 #6272a4 #6272a4

# Autostart
exec_always pkill waybar; waybar
exec mako
exec /usr/libexec/pipewire-launcher
EOF

    # Waybar config
    mkdir -p "${ROOTFS}/home/alpha/.config/waybar"
    cat > "${ROOTFS}/home/alpha/.config/waybar/config" << 'EOF'
{
    "layer": "top",
    "position": "top",
    "height": 30,
    "modules-left": ["sway/workspaces", "sway/mode"],
    "modules-center": ["clock"],
    "modules-right": ["pulseaudio", "network", "battery", "tray"],
    
    "clock": {
        "format": "{:%Y-%m-%d %H:%M}"
    },
    "battery": {
        "format": "{icon} {capacity}%",
        "format-icons": ["", "", "", "", ""]
    },
    "network": {
        "format-wifi": " {signalStrength}%",
        "format-ethernet": "",
        "format-disconnected": ""
    },
    "pulseaudio": {
        "format": "{icon} {volume}%",
        "format-muted": "",
        "format-icons": ["", "", ""]
    }
}
EOF

    # Auto-start sway on login
    cat >> "${ROOTFS}/home/alpha/.bash_profile" << 'EOF'
if [ -z "$DISPLAY" ] && [ "$XDG_VTNR" = 1 ]; then
    exec sway
fi
EOF

    chroot "$ROOTFS" chown -R alpha:alpha /home/alpha
}

configure_xfce() {
    # Enable lightdm
    chroot "$ROOTFS" systemctl enable lightdm
    
    # Autologin for live session
    mkdir -p "${ROOTFS}/etc/lightdm/lightdm.conf.d"
    cat > "${ROOTFS}/etc/lightdm/lightdm.conf.d/autologin.conf" << EOF
[Seat:*]
autologin-user=alpha
autologin-user-timeout=0
EOF
}

configure_gnome() {
    # Enable gdm
    chroot "$ROOTFS" systemctl enable gdm3
    
    # GDM autologin for live session
    mkdir -p "${ROOTFS}/etc/gdm3"
    cat > "${ROOTFS}/etc/gdm3/custom.conf" << EOF
[daemon]
AutomaticLoginEnable=true
AutomaticLogin=alpha

[security]

[xdmcp]

[chooser]

[debug]
EOF
}

#===============================================================================
# Configure Security
#===============================================================================
configure_security() {
    log_step "Configuring security..."
    
    # SSH hardening
    mkdir -p "${ROOTFS}/etc/ssh/sshd_config.d"
    cat > "${ROOTFS}/etc/ssh/sshd_config.d/hardening.conf" << EOF
PermitRootLogin no
PasswordAuthentication yes
PubkeyAuthentication yes
PermitEmptyPasswords no
X11Forwarding no
AllowTcpForwarding no
MaxAuthTries 3
ClientAliveInterval 300
ClientAliveCountMax 2
Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com
MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com
KexAlgorithms curve25519-sha256,curve25519-sha256@libssh.org
EOF

    # Sysctl hardening
    cat > "${ROOTFS}/etc/sysctl.d/99-alpha-hardening.conf" << EOF
# Kernel hardening
kernel.dmesg_restrict = 1
kernel.kptr_restrict = 1
kernel.yama.ptrace_scope = 1
kernel.randomize_va_space = 2
kernel.sysrq = 176

# Network hardening
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
net.ipv4.tcp_syncookies = 1
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0

# Filesystem hardening
fs.protected_hardlinks = 1
fs.protected_symlinks = 1
fs.protected_fifos = 2
fs.protected_regular = 2

# Performance
vm.swappiness = 10
vm.vfs_cache_pressure = 50
EOF
    
    # Enable AppArmor
    chroot "$ROOTFS" systemctl enable apparmor
}

#===============================================================================
# Configure Power Management
#===============================================================================
configure_power() {
    log_step "Configuring power management..."
    
    cat > "${ROOTFS}/etc/tlp.d/01-alpha.conf" << EOF
TLP_ENABLE=1
TLP_DEFAULT_MODE=BAT
CPU_SCALING_GOVERNOR_ON_AC=performance
CPU_SCALING_GOVERNOR_ON_BAT=powersave
CPU_ENERGY_PERF_POLICY_ON_AC=balance_performance
CPU_ENERGY_PERF_POLICY_ON_BAT=balance_power
CPU_BOOST_ON_AC=1
CPU_BOOST_ON_BAT=0
NMI_WATCHDOG=0
WIFI_PWR_ON_AC=off
WIFI_PWR_ON_BAT=on
RUNTIME_PM_ON_AC=on
RUNTIME_PM_ON_BAT=auto
USB_AUTOSUSPEND=1
EOF

    chroot "$ROOTFS" systemctl enable tlp
    chroot "$ROOTFS" systemctl enable thermald 2>/dev/null || true
}

#===============================================================================
# Create Installer Script
#===============================================================================
create_installer() {
    log_step "Creating installer script..."
    
    cat > "${ROOTFS}/usr/local/bin/alpha-install" << 'INSTALLER_EOF'
#!/bin/bash
#===============================================================================
# Alpha Linux Installer
# TUI-based installation wizard
#===============================================================================

set -euo pipefail

DIALOG=${DIALOG:-dialog}
TARGET="/mnt/target"

# Colors for dialog
export DIALOGRC=/tmp/dialogrc
cat > $DIALOGRC << EOF
use_colors = ON
screen_color = (WHITE,BLUE,ON)
dialog_color = (BLACK,WHITE,OFF)
title_color = (BLUE,WHITE,ON)
border_color = (WHITE,WHITE,ON)
button_active_color = (WHITE,BLUE,ON)
EOF

show_welcome() {
    $DIALOG --title "Alpha Linux Installer" --msgbox "\n
    Welcome to Alpha Linux ${VERSION}\n\n
    This installer will guide you through:\n
    - Disk partitioning\n
    - System installation\n
    - User configuration\n
    - Bootloader setup\n\n
    Press OK to continue." 16 50
}

select_disk() {
    local disks=$(lsblk -dpno NAME,SIZE,MODEL | grep -E '^/dev/(sd|nvme|vd)')
    local options=""
    
    while read -r line; do
        local disk=$(echo "$line" | awk '{print $1}')
        local size=$(echo "$line" | awk '{print $2}')
        local model=$(echo "$line" | awk '{$1=$2=""; print $0}' | xargs)
        options+="$disk \"$size $model\" "
    done <<< "$disks"
    
    DISK=$($DIALOG --title "Select Installation Disk" --menu \
        "\nSelect the disk to install Alpha Linux:\n\nWARNING: All data will be erased!" \
        20 60 10 $options 3>&1 1>&2 2>&3)
}

select_encryption() {
    $DIALOG --title "Disk Encryption" --yesno \
        "\nDo you want to encrypt your disk with LUKS2?\n\n(Recommended for laptops)" 10 50
    ENCRYPT=$?
}

partition_disk() {
    $DIALOG --title "Partitioning" --infobox "\nPartitioning disk..." 5 40
    
    # Detect boot mode
    if [ -d /sys/firmware/efi ]; then
        BOOT_MODE="uefi"
    else
        BOOT_MODE="bios"
    fi
    
    # Wipe disk
    wipefs -af "$DISK"
    
    if [ "$BOOT_MODE" = "uefi" ]; then
        parted -s "$DISK" mklabel gpt
        parted -s "$DISK" mkpart efi fat32 1MiB 513MiB
        parted -s "$DISK" set 1 esp on
        parted -s "$DISK" mkpart boot ext4 513MiB 1537MiB
        parted -s "$DISK" mkpart root btrfs 1537MiB 100%
        
        # Format
        if [[ "$DISK" == *"nvme"* ]]; then
            EFI_PART="${DISK}p1"
            BOOT_PART="${DISK}p2"
            ROOT_PART="${DISK}p3"
        else
            EFI_PART="${DISK}1"
            BOOT_PART="${DISK}2"
            ROOT_PART="${DISK}3"
        fi
        
        mkfs.vfat -F32 -n EFI "$EFI_PART"
    else
        parted -s "$DISK" mklabel msdos
        parted -s "$DISK" mkpart primary ext4 1MiB 1025MiB
        parted -s "$DISK" set 1 boot on
        parted -s "$DISK" mkpart primary btrfs 1025MiB 100%
        
        if [[ "$DISK" == *"nvme"* ]]; then
            BOOT_PART="${DISK}p1"
            ROOT_PART="${DISK}p2"
        else
            BOOT_PART="${DISK}1"
            ROOT_PART="${DISK}2"
        fi
    fi
    
    mkfs.ext4 -L boot "$BOOT_PART"
    
    # Encryption
    if [ "$ENCRYPT" -eq 0 ]; then
        LUKS_PASS=$($DIALOG --title "Encryption Password" --passwordbox \
            "\nEnter encryption password:" 10 50 3>&1 1>&2 2>&3)
        echo -n "$LUKS_PASS" | cryptsetup luksFormat --type luks2 "$ROOT_PART" -
        echo -n "$LUKS_PASS" | cryptsetup open "$ROOT_PART" cryptroot -
        ROOT_DEVICE="/dev/mapper/cryptroot"
    else
        ROOT_DEVICE="$ROOT_PART"
    fi
    
    mkfs.btrfs -f -L root "$ROOT_DEVICE"
    
    # Mount and create subvolumes
    mount "$ROOT_DEVICE" "$TARGET"
    btrfs subvolume create "${TARGET}/@"
    btrfs subvolume create "${TARGET}/@home"
    btrfs subvolume create "${TARGET}/@snapshots"
    umount "$TARGET"
    
    # Remount with subvolumes
    mount -o noatime,compress=zstd:1,subvol=@ "$ROOT_DEVICE" "$TARGET"
    mkdir -p "${TARGET}"/{boot,home,.snapshots}
    mount -o noatime,compress=zstd:1,subvol=@home "$ROOT_DEVICE" "${TARGET}/home"
    mount -o noatime,compress=zstd:1,subvol=@snapshots "$ROOT_DEVICE" "${TARGET}/.snapshots"
    mount "$BOOT_PART" "${TARGET}/boot"
    
    if [ "$BOOT_MODE" = "uefi" ]; then
        mkdir -p "${TARGET}/boot/efi"
        mount "$EFI_PART" "${TARGET}/boot/efi"
    fi
}

install_system() {
    $DIALOG --title "Installing" --gauge "\nCopying system files..." 8 50 0 < <(
        rsync -aAX --info=progress2 / "$TARGET" \
            --exclude={"/dev/*","/proc/*","/sys/*","/tmp/*","/run/*","/mnt/*","/media/*","/lost+found"} 2>&1 | \
        while read -r line; do
            if [[ "$line" =~ ([0-9]+)% ]]; then
                echo "${BASH_REMATCH[1]}"
            fi
        done
    )
}

configure_user() {
    USERNAME=$($DIALOG --title "User Setup" --inputbox \
        "\nEnter username:" 10 50 "alpha" 3>&1 1>&2 2>&3)
    
    PASSWORD=$($DIALOG --title "User Setup" --passwordbox \
        "\nEnter password for $USERNAME:" 10 50 3>&1 1>&2 2>&3)
    
    HOSTNAME=$($DIALOG --title "System Setup" --inputbox \
        "\nEnter hostname:" 10 50 "alpha" 3>&1 1>&2 2>&3)
}

configure_target() {
    $DIALOG --title "Configuring" --infobox "\nConfiguring system..." 5 40
    
    # Generate fstab
    genfstab -U "$TARGET" > "${TARGET}/etc/fstab"
    
    # Hostname
    echo "$HOSTNAME" > "${TARGET}/etc/hostname"
    cat > "${TARGET}/etc/hosts" << EOF
127.0.0.1   localhost
127.0.1.1   ${HOSTNAME}
::1         localhost ip6-localhost ip6-loopback
EOF

    # Chroot and configure
    arch-chroot "$TARGET" /bin/bash << CHROOT_EOF
# Remove live user and create new user
userdel -r alpha 2>/dev/null || true
useradd -m -s /bin/bash -G sudo,adm,cdrom,audio,video,plugdev,netdev,bluetooth ${USERNAME}
echo "${USERNAME}:${PASSWORD}" | chpasswd
rm -f /etc/sudoers.d/alpha
echo "${USERNAME} ALL=(ALL) ALL" > /etc/sudoers.d/${USERNAME}
chmod 440 /etc/sudoers.d/${USERNAME}

# Remove autologin
rm -f /etc/systemd/system/getty@tty1.service.d/autologin.conf
rm -f /etc/lightdm/lightdm.conf.d/autologin.conf 2>/dev/null || true
sed -i '/AutomaticLogin/d' /etc/gdm3/custom.conf 2>/dev/null || true

# Regenerate initramfs
update-initramfs -u -k all

# Install bootloader
if [ -d /sys/firmware/efi ]; then
    bootctl install --esp-path=/boot/efi
    
    KERNEL=\$(ls /boot/vmlinuz-* | head -1 | sed 's|/boot/vmlinuz-||')
    
    mkdir -p /boot/efi/loader/entries
    cat > /boot/efi/loader/entries/alpha.conf << BOOTEOF
title   Alpha Linux
linux   /vmlinuz-\${KERNEL}
initrd  /initrd.img-\${KERNEL}
options root=LABEL=root rootflags=subvol=@ rw quiet splash
BOOTEOF
    
    cat > /boot/efi/loader/loader.conf << LOADEREOF
default alpha.conf
timeout 3
editor no
LOADEREOF
    
    cp /boot/vmlinuz-\${KERNEL} /boot/efi/
    cp /boot/initrd.img-\${KERNEL} /boot/efi/
else
    grub-install --target=i386-pc $DISK
    update-grub
fi

# Enable services
systemctl enable NetworkManager
systemctl enable tlp
systemctl enable apparmor

# Clean machine-id for unique generation
truncate -s 0 /etc/machine-id
CHROOT_EOF
}

finish_install() {
    umount -R "$TARGET"
    
    if [ "$ENCRYPT" -eq 0 ]; then
        cryptsetup close cryptroot
    fi
    
    $DIALOG --title "Installation Complete" --msgbox "\n
    Alpha Linux has been installed successfully!\n\n
    Username: ${USERNAME}\n
    Hostname: ${HOSTNAME}\n\n
    Remove the installation media and reboot." 14 50
}

main() {
    mkdir -p "$TARGET"
    
    show_welcome
    select_disk
    select_encryption
    partition_disk
    install_system
    configure_user
    configure_target
    finish_install
}

main "$@"
INSTALLER_EOF

    chmod +x "${ROOTFS}/usr/local/bin/alpha-install"
    
    # Create desktop entry for installer
    mkdir -p "${ROOTFS}/usr/share/applications"
    cat > "${ROOTFS}/usr/share/applications/alpha-install.desktop" << EOF
[Desktop Entry]
Name=Install Alpha Linux
Comment=Install Alpha Linux to disk
Exec=sudo alpha-install
Icon=system-software-install
Terminal=true
Type=Application
Categories=System;
EOF
}

#===============================================================================
# Enable Services
#===============================================================================
enable_services() {
    log_step "Enabling services..."
    
    chroot "$ROOTFS" systemctl enable NetworkManager
    chroot "$ROOTFS" systemctl enable ssh
    chroot "$ROOTFS" systemctl enable tlp
    chroot "$ROOTFS" systemctl enable apparmor
}

#===============================================================================
# Cleanup System
#===============================================================================
cleanup_system() {
    log_step "Cleaning up..."
    
    chroot "$ROOTFS" /bin/bash -c "
        apt-get clean
        apt-get autoremove --purge -y
        rm -rf /var/lib/apt/lists/*
        rm -rf /var/cache/apt/*
        find /var/log -type f -delete
        rm -f /etc/resolv.conf
        truncate -s 0 /etc/machine-id
    "
}

#===============================================================================
# Create SquashFS
#===============================================================================
create_squashfs() {
    log_step "Creating squashfs image..."
    
    mksquashfs "$ROOTFS" "${BUILD_DIR}/iso/live/filesystem.squashfs" \
        -comp zstd -Xcompression-level 19 \
        -e boot
    
    log_info "SquashFS created"
}

#===============================================================================
# Configure Bootloader for ISO
#===============================================================================
configure_iso_boot() {
    log_step "Configuring ISO bootloader..."
    
    # Copy kernel and initrd
    cp "${ROOTFS}/boot/vmlinuz-"* "${BUILD_DIR}/iso/live/vmlinuz"
    cp "${ROOTFS}/boot/initrd.img-"* "${BUILD_DIR}/iso/live/initrd"
    
    # GRUB config for UEFI
    cat > "${BUILD_DIR}/iso/boot/grub/grub.cfg" << EOF
set timeout=5
set default=0

menuentry "Alpha Linux Live (${VARIANT})" {
    linux /live/vmlinuz boot=live toram quiet splash
    initrd /live/initrd
}

menuentry "Alpha Linux Live (Safe Mode)" {
    linux /live/vmlinuz boot=live toram nomodeset
    initrd /live/initrd
}

menuentry "Alpha Linux Installer" {
    linux /live/vmlinuz boot=live toram quiet splash installer
    initrd /live/initrd
}
EOF

    # ISOLINUX config for BIOS
    cat > "${BUILD_DIR}/iso/isolinux/isolinux.cfg" << EOF
UI vesamenu.c32
PROMPT 0
TIMEOUT 50
DEFAULT live

MENU TITLE Alpha Linux ${VERSION}
MENU COLOR border       30;44   #40ffffff #a0000000 std
MENU COLOR title        1;36;44 #9033ccff #a0000000 std
MENU COLOR sel          7;37;40 #e0ffffff #20ffffff all
MENU COLOR unsel        37;44   #50ffffff #a0000000 std

LABEL live
    MENU LABEL ^Alpha Linux Live (${VARIANT})
    KERNEL /live/vmlinuz
    APPEND initrd=/live/initrd boot=live toram quiet splash

LABEL safe
    MENU LABEL Alpha Linux (^Safe Mode)
    KERNEL /live/vmlinuz
    APPEND initrd=/live/initrd boot=live toram nomodeset

LABEL install
    MENU LABEL ^Install Alpha Linux
    KERNEL /live/vmlinuz
    APPEND initrd=/live/initrd boot=live toram quiet splash installer
EOF

    # Copy ISOLINUX files
    cp /usr/lib/ISOLINUX/isolinux.bin "${BUILD_DIR}/iso/isolinux/"
    cp /usr/lib/syslinux/modules/bios/{ldlinux,libcom32,libutil,vesamenu}.c32 "${BUILD_DIR}/iso/isolinux/"
    
    # Create EFI bootloader
    mkdir -p "${BUILD_DIR}/iso/EFI/boot"
    grub-mkstandalone \
        --format=x86_64-efi \
        --output="${BUILD_DIR}/iso/EFI/boot/bootx64.efi" \
        --locales="" \
        --fonts="" \
        "boot/grub/grub.cfg=${BUILD_DIR}/iso/boot/grub/grub.cfg"
    
    # Create EFI image
    dd if=/dev/zero of="${BUILD_DIR}/iso/boot/efi.img" bs=1M count=10
    mkfs.vfat "${BUILD_DIR}/iso/boot/efi.img"
    mmd -i "${BUILD_DIR}/iso/boot/efi.img" EFI EFI/boot
    mcopy -i "${BUILD_DIR}/iso/boot/efi.img" "${BUILD_DIR}/iso/EFI/boot/bootx64.efi" ::EFI/boot/
}

#===============================================================================
# Create ISO
#===============================================================================
create_iso() {
    log_step "Creating ISO image..."
    
    mkdir -p "$OUTPUT_DIR"
    
    local iso_name="alpha-linux-${VERSION}-${VARIANT}-${ARCH}.iso"
    
    xorriso -as mkisofs \
        -iso-level 3 \
        -full-iso9660-filenames \
        -volid "ALPHA_LINUX" \
        -eltorito-boot isolinux/isolinux.bin \
        -eltorito-catalog isolinux/boot.cat \
        -no-emul-boot \
        -boot-load-size 4 \
        -boot-info-table \
        -isohybrid-mbr /usr/lib/ISOLINUX/isohdpfx.bin \
        -eltorito-alt-boot \
        -e boot/efi.img \
        -no-emul-boot \
        -isohybrid-gpt-basdat \
        -output "${OUTPUT_DIR}/${iso_name}" \
        "${BUILD_DIR}/iso"
    
    # Generate checksums
    cd "$OUTPUT_DIR"
    sha256sum "$iso_name" > "${iso_name}.sha256"
    
    log_info "ISO created: ${OUTPUT_DIR}/${iso_name}"
    
    # Show info
    echo ""
    echo "=========================================="
    echo "Alpha Linux ISO Build Complete"
    echo "=========================================="
    echo "Variant: ${VARIANT}"
    echo "Size: $(du -h "${OUTPUT_DIR}/${iso_name}" | cut -f1)"
    echo "File: ${OUTPUT_DIR}/${iso_name}"
    echo ""
    echo "Live credentials:"
    echo "  Username: alpha"
    echo "  Password: alpha"
    echo "=========================================="
}

#===============================================================================
# Cleanup
#===============================================================================
cleanup() {
    log_step "Cleaning up build directory..."
    umount_vfs
    rm -rf "$BUILD_DIR"
}

trap 'umount_vfs 2>/dev/null; rm -rf "$BUILD_DIR"' ERR EXIT

#===============================================================================
# Main
#===============================================================================
main() {
    echo "=========================================="
    echo "Alpha Linux Laptop ISO Builder v${VERSION}"
    echo "Variant: ${VARIANT}"
    echo "=========================================="
    
    check_prerequisites
    select_variant
    setup_build_env
    bootstrap_system
    configure_apt
    mount_vfs
    install_packages
    configure_system
    configure_desktop
    configure_security
    configure_power
    create_installer
    enable_services
    cleanup_system
    umount_vfs
    create_squashfs
    configure_iso_boot
    create_iso
}

main "$@"
