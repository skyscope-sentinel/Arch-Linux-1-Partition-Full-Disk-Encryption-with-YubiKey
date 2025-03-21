# Arch Linux 1 Partition Full Disk Encryption with YubiKey

This repository provides a detailed guide and an automated Bash script for installing Arch Linux with full disk encryption (FDE) using a single encrypted partition, unlocked via a YubiKey with FIDO2 touch authentication. The setup leverages LUKS2, Btrfs, Argon2id PBKDF, and Serpent XTS cipher for maximum security, tailored for modern hardware with Ethernet-only connectivity.

## Features
- **Single Partition FDE**: Entire disk encrypted under one LUKS2 container, including `/boot`.
- **YubiKey Unlock**: Uses FIDO2 for touch-only decryption, no modification to existing YubiKey configuration.
- **High Security**: LUKS2 with Serpent XTS, Argon2id PBKDF (5000 ms iteration time), SHA-512 hash.
- **File System**: Btrfs for root and home, with LVM for flexibility.
- **Automation**: Bash script with interactive disk selection, progress bar, and live logging.
- **Hardware**: Tested on Gigabyte B760M H DDR4, Intel i7-12700, 32GB DDR4, NVIDIA GTX 970 + Intel graphics.

## Prerequisites
- Arch Linux netinstall ISO ([download](https://archlinux.org/download/)).
- A USB drive for booting.
- YubiKey with FIDO2 support.
- Ethernet connection (no WiFi/USB internet).
- Basic familiarity with Linux terminal commands.

## Installation Options

### Option 1: Automated Script
The `install-arch-fde-yubikey.sh` script automates the entire process with a modern CLI interface.

#### Usage
1. Boot into the Arch Linux live ISO.
2. Download the script:
      
   curl -O https://raw.githubusercontent.com/skyscope-sentinel/Arch-Linux-1-Partition-Full-Disk-Encryption-with-Yubikey/main/install-arch-fde-yubikey.sh

 3. Make it executable:chmod +x install-arch-fde-yubikey.sh

 4. Run as root:./install-arch-fde-yubikey.sh

### Script Features

### Dsk Selection
Scans available disks and presents a centered, numbered menu.

### Progress Bar
Displays percentage completion (e.g., [##########----------] 33%).

### Verbose Logging 
Logs tasks with timestamps to /tmp/arch_install_YYYYMMDD_HHMMSS.log.

### Tamper Protection
Checks script integrity with SHA-256 hash (basic protection; see notes).

