<p align="center">
  <img src="branding/alphha-logo.svg" alt="Alphha Security OS Logo" width="200">
</p>

<h1 align="center">Alphha Security OS</h1>

<p align="center">
  <strong>All-in-One Debian-Based Cybersecurity Distribution</strong>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/version-1.0.0-green?style=flat-square" alt="Version">
  <img src="https://img.shields.io/badge/codename-Sentinel-blue?style=flat-square" alt="Codename">
  <img src="https://img.shields.io/badge/base-Debian%20Bookworm-red?style=flat-square" alt="Base">
  <img src="https://img.shields.io/badge/license-BSD--3--Clause-orange?style=flat-square" alt="License">
</p>

---

## Overview

**Alphha Security OS** is a comprehensive cybersecurity distribution built on Debian Bookworm, combining offensive and defensive security tools in a single platform. Designed for penetration testers, security researchers, forensic analysts, and blue team professionals.

### Key Features

- **500+ Security Tools** - Offensive, defensive, and forensic tools pre-installed
- **Custom Alphha Toolkit** - Original automation scripts for common security tasks
- **Hardened by Default** - 60+ kernel security settings, SSH hardening, nftables firewall
- **Multiple Editions** - Full, Offensive, Defensive, Forensics, and Minimal variants
- **XFCE Desktop** - Lightweight, fast, and customizable with dark cyber theme
- **Live Boot & Install** - Boot from USB or install to disk with encryption support

---

## System Requirements

| Component | Minimum | Recommended |
|-----------|---------|-------------|
| CPU | x86_64 with SSE4.2 | Quad-core 2.0 GHz+ |
| RAM | 2 GB | 4 GB+ |
| Storage | 20 GB | 40 GB+ |
| Display | 1024x768 | 1920x1080 |

---

## Installation

### Option 1: Download Pre-Built ISO

Download the latest ISO from the [Releases](https://github.com/shibinsp/alphha-security-os/releases) page.

### Option 2: Build from Source

#### Prerequisites (Debian/Ubuntu)

```bash
sudo apt update
sudo apt install -y debootstrap xorriso squashfs-tools grub-pc-bin \
    grub-efi-amd64-bin mtools dosfstools isolinux syslinux-common curl wget gpg
```

#### Build ISO

```bash
# Clone the repository
git clone https://github.com/shibinsp/alphha-security-os.git
cd alphha-security-os

# Build full edition (all tools, ~6 GB)
sudo ./build-alphha-security.sh

# Or choose a specific variant
sudo ./build-alphha-security.sh --variant offensive   # Penetration testing (~4 GB)
sudo ./build-alphha-security.sh --variant defensive   # Blue team tools (~3 GB)
sudo ./build-alphha-security.sh --variant forensics   # Digital forensics (~3 GB)
sudo ./build-alphha-security.sh --variant minimal     # CLI only (~1.5 GB)
```

#### Build VM Image

```bash
# Build QCOW2 image for virtual machines
sudo ./build-alphha-security-vm.sh --size 20
```

### Option 3: Boot from USB

```bash
# Write ISO to USB drive (replace /dev/sdX with your USB device)
sudo dd if=output/alphha-security-1.0.0-full-amd64.iso of=/dev/sdX bs=4M status=progress
sync
```

---

## Default Credentials

| User | Password | Notes |
|------|----------|-------|
| `sentinel` | `alphha` | Default user with sudo access |
| `root` | `alphha` | Root user (SSH disabled) |

**Important:** Change these passwords immediately after installation!

```bash
passwd           # Change current user password
sudo passwd root # Change root password
```

---

## Quick Start

### Launch Security Tools Menu

```bash
alphha-menu
```

### Update System & Tools

```bash
sudo alphha-update --all
```

### Run Reconnaissance

```bash
alphha-recon example.com -a -w -o ./recon-results
```

### Vulnerability Assessment

```bash
alphha-vuln 192.168.1.1 -t full -o ./vuln-scan
```

### Generate Report

```bash
alphha-report -i ./vuln-scan -f html -o report.html
```

---

## Alphha Toolkit

Custom tools developed exclusively for Alphha Security OS:

| Tool | Description |
|------|-------------|
| `alphha-menu` | Interactive security tools launcher |
| `alphha-update` | System and tools update utility |
| `alphha-recon` | Automated reconnaissance workflow |
| `alphha-vuln` | Vulnerability assessment wrapper |
| `alphha-report` | Professional security report generator |
| `alphha-backup` | Forensic evidence collection with chain of custody |
| `alphha-clean` | Secure cleanup and sanitization |

---

## Tool Categories

<details>
<summary><strong>01 - Information Gathering</strong></summary>

nmap, masscan, netdiscover, arp-scan, dnsrecon, dnsenum, theharvester, recon-ng, amass, enum4linux, nbtscan
</details>

<details>
<summary><strong>02 - Vulnerability Analysis</strong></summary>

nikto, wpscan, sqlmap, nuclei, testssl.sh, sslscan, lynis
</details>

<details>
<summary><strong>03 - Web Application Testing</strong></summary>

burpsuite, zaproxy, ffuf, gobuster, dirb, wfuzz, whatweb, wafw00f
</details>

<details>
<summary><strong>04 - Password Attacks</strong></summary>

hashcat, john, hydra, medusa, cewl, crunch, wordlists
</details>

<details>
<summary><strong>05 - Wireless Attacks</strong></summary>

aircrack-ng, wifite, reaver, kismet, hcxtools
</details>

<details>
<summary><strong>06 - Exploitation Frameworks</strong></summary>

metasploit-framework, exploitdb, searchsploit, crackmapexec
</details>

<details>
<summary><strong>07 - Post-Exploitation</strong></summary>

chisel, pwncat, evil-winrm, impacket-scripts, bloodhound
</details>

<details>
<summary><strong>08 - Forensics & Recovery</strong></summary>

autopsy, sleuthkit, volatility3, foremost, scalpel, binwalk, photorec, testdisk
</details>

<details>
<summary><strong>09 - Reverse Engineering</strong></summary>

ghidra, radare2, gdb, pwndbg, ltrace, strace, checksec
</details>

<details>
<summary><strong>10 - Network Analysis</strong></summary>

wireshark, tshark, tcpdump, ettercap, bettercap, mitmproxy, responder
</details>

<details>
<summary><strong>11 - Defensive Security (Blue Team)</strong></summary>

snort, suricata, zeek, fail2ban, rkhunter, chkrootkit, clamav, aide, auditd, osquery
</details>

<details>
<summary><strong>12 - Anonymity & Privacy</strong></summary>

tor, torsocks, proxychains4, macchanger, bleachbit
</details>

---

## Boot Modes

| Mode | Description |
|------|-------------|
| **Live** | Boot without installation, all changes are temporary |
| **Forensic** | Read-only mode, no disk mounting (for evidence preservation) |
| **Safe Mode** | Minimal boot for troubleshooting |
| **Load to RAM** | Copy entire system to RAM for faster performance |

---

## Security Hardening

Alphha Security OS includes comprehensive security hardening:

- **Kernel Hardening** - ASLR, ptrace restrictions, BPF JIT hardening
- **Network Security** - SYN cookies, anti-spoofing, ICMP restrictions
- **SSH Hardening** - Key-based auth, strong ciphers, rate limiting
- **Firewall** - nftables with drop-by-default policy
- **AppArmor** - Mandatory access control for critical applications

---

## Directory Structure

```
alphha-security-os/
├── build-alphha-security.sh      # ISO builder
├── build-alphha-security-vm.sh   # VM image builder
├── alphha-security-spec.json     # OS specification
├── branding/                     # Logo, themes, wallpapers
├── configs/                      # System configurations
│   ├── apt/                      # Repository configs
│   └── security/                 # Hardening configs
├── tools/                        # Custom Alphha tools
│   ├── alphha-menu
│   ├── alphha-update
│   └── alphha-toolkit/
├── installer/                    # TUI installer
└── docs/                         # Legal & documentation
    ├── LICENSE
    ├── COPYRIGHT
    └── CREDITS
```

---

## Contributing

Contributions are welcome! Please read our contributing guidelines before submitting pull requests.

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

---

## Legal Disclaimer

**Alphha Security OS is intended for authorized security testing, educational purposes, and defensive security only.**

- Always obtain proper authorization before testing systems you don't own
- The developers are not responsible for misuse of this software
- Use responsibly and ethically

---

## License

This project is licensed under the **BSD 3-Clause License** - see the [LICENSE](docs/LICENSE) file for details.

**Copyright (c) 2026 Alphha Team. All Rights Reserved.**

### Trademarks

"Alphha Security OS", "Alphha", and the Alphha logo are trademarks of the Alphha Team.

---

## Acknowledgments

Alphha Security OS is built upon the work of many open-source projects. See [CREDITS](docs/CREDITS) for full acknowledgments.

Special thanks to:
- Debian Project
- Kali Linux
- The open-source security community

---

<p align="center">
  <strong>Built with security in mind by the Alphha Team</strong>
</p>

<p align="center">
  <a href="https://github.com/shibinsp/alphha-security-os/issues">Report Bug</a>
  ·
  <a href="https://github.com/shibinsp/alphha-security-os/issues">Request Feature</a>
</p>
