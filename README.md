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

       ```bash
       curl -O https://raw.githubusercontent.com/skyscopesentinel/Arch-Linux-1-Partition-Full-Disk-Encryption-with-Yubikey/main/install-arch-fde-yubikey.sh

4. Make it executable

       ```bash
       chmod +x install-arch-fde-yubikey.sh

### Run as root

     ```bash
     ./install-arch-fde-yubikey.sh

### Follow the interactive menu to select a disk, then watch the progress bar and live logs as the installation completes.

### Script Features

### Disk Selection
Scans available disks and presents a centered, numbered menu.
### Progress Bar
Displays percentage completion (e.g., [##########----------] 33%).
### Verbose Logging
Logs tasks with timestamps to /tmp/arch_install_YYYYMMDD_HHMMSS.log.
### Tamper Protection
Checks script integrity with SHA-256 hash (basic protection; see notes).

### Option 2 
** Manual Installation

### Step 1
** Boot the Arch Linux ISO
** Download the latest Arch Linux ISO from archlinux.org.
** Create a bootable USB

     ```bash
     dd if=archlinux.iso of=/dev/sdX bs=4M status=progress && sync

** Boot from the USB, ensuring Ethernet is connected (verify with ping archlinux.org).

### Step 2
** Partition the Disk
** Wipe the disk and create a single partition

     ```bash
     cfdisk /dev/sdaDelete all existing partitions.

** Create /dev/sda1, type 8300 (Linux filesystem), using the entire disk.
** Write changes and exit.

### Step 3
** Set Up LUKS2 Encryption
** Encrypt the partition

    ```bash 
    cryptsetup --type luks2 --cipher serpent-xts-plain64 --key-size 256 --hash sha512 --pbkdf argon2id --iter-time 5000 luks

### Format disk
** Enter a temporary passphrase
** Open the encrypted partition 

    ```bash 
    cryptsetup luksOpen /dev/sda1 cryptroot

### Step 4
** Configure LVM
** Create a physical volume

    ```bash
     pvcreate /dev/mapper/cryptroot

** Create a volume group

    ```bash 
    vgcreate vg0 /dev/mapper/cryptroot

** Create logical volumes 

    ```bash 
    lvcreate -n root -L 50G vg0
    lvcreate -n home -l 80%FREE vg0
    lvcreate -n swap -L 16G vg0

### Step 5
** Format File Systems
** Format root and home with Btrfs

    ```bash 
    mkfs.btrfs /dev/mapper/vg0-root
    mkfs.btrfs /dev/mapper/vg0-home

** Format swap 

     ```bash 
     mkswap /dev/mapper/vg0-swap

** Mount swap

    ```bash 
    swapon /dev/mapper/vg0-swap

### Step 6
** Mount File Systems
** Mount the root volume

    ```bash
    mount /dev/mapper/vg0-root /mnt

** Create and mount Btrfs subvolumes

    ```bash 
    btrfs subvolume create /mnt/boot
    btrfs subvolume create /mnt/home
    mount /dev/mapper/vg0-home /mnt/home

### Step 7
** Install Base System
** Install essential packages

     ```bash
     pacstrap /mnt base linux linux-firmware intel-ucode

### Step 8
** Generate fstab
** Generate and check fstab

     ```bash
     genfstab -U /mnt >> /mnt/etc/fstab

** Verify /boot and /home entries

     ```bash
     cat /mnt/etc/fstab

### Step 9
** Chroot and Basic Configuration
** Chroot into the system

     ```bash 
     arch-chroot /mntSet hostname:echo "archsecure" > /etc/hostname

** Configure /etc/hosts

     ```bash
     echo "127.0.0.1 localhost" >> /etc/hosts
     echo "::1       localhost" >> /etc/hosts
     echo "127.0.1.1 archsecure.localdomain archsecure" >> /etc/hosts

### Step 10
** Enroll YubiKey
** Install tools

     ```bash 
      pacman -S systemd yubikey-manager

** Enroll YubiKey with FIDO2

     ```bash
     systemd-cryptenroll /dev/sda1 --fido2-device=auto --fido2-with-client-pin=no

** Touch the YubiKey when prompted.

### Step 11
** Configure crypttab
** Add to /etc/crypttab

     ```bash
     echo "cryptroot UUID=$(blkid -s UUID -o value /dev/sda1) none luks,fido2-device=auto" >> /etc/crypttab

### Step 12
** Configure Initramfs
** Edit /etc/mkinitcpio.conf

     ```bash
     nano /etc/mkinitcpio.conf 

** Paste in the following if not already found find the line starting with HOOKS [The order of items is important]
 
     ```bash
    HOOKS=(base udev autodetect keyboard keymap consolefont modconf block lvm2 filesystems fsck)

** Regenerate initramfs

     ```bash
     mkinitcpio -P

### Step 13
** Install Bootloader (systemd-boot)
** Install systemd-boot:

     ```bash
     bootctl --path=/boot install

** Create /boot/loader/entries/arch.conf

    ```bash
    nano  /boot/loader/entries/arch.conf

** Paste in the following if not already found or contained in the file

title   Arch Linux
linux   /vmlinuz-linux
initrd  /intel-ucode.img
initrd  /initramfs-linux.img
options cryptdevice=UUID=$(blkid -s UUID -o value /dev/sda1):cryptroot root=/dev/mapper/vg0-root rwEdit /boot/loader/loader.conf:default arch.conf
timeout 3

### Step 14
** Set Root Password and Exit
** Set root password

     ```bash
     passwd

** Exit chroot

     ```bash
     exit

### Step 15
** Reboot
** Unmount and reboot

    ```bash 
    umount -R /mnt
    swapoff /dev/mapper/vg0-swap
    reboot

** Insert YubiKey and touch it at boot to unlock.

### Post-Installation
** Verify boot prompts for YubiKey touch.

### Install additional drivers (e.g., nvidia intel etcetera) 
** If needed run the following:

     ```bash
     pacman -S nvidia nvidia-utils

### Troubleshooting
** Boot Failure: Ensure lvm2 is in mkinitcpio.conf hooks.
** YubiKey Not Recognized: Verify FIDO2 support (ykman info) and re-enroll if needed.
** Btrfs Issues: Check subvolume mounts with btrfs subvolume list /
** Script Errors: Check the log file in /tmp/ for details.

### Notes on Script Security
** The script includes a basic tamper check using SHA-256 hashing. 
** For stronger protection, sign it with GPG (gpg --sign install-arch-fde-yubikey.sh) and verify the signature before running.

### License

This project is licensed under the MIT License - see below for details.MIT License

Copyright (c) 2025 Skyscope Sentinel Intelligence

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.


### Credits

** Developed by
Casey J Topojani

[Developer grants full rights to all Github developers to use freely and distribute all scripts and code and make modification/s
enhancements and refinements under the condition that it is freely distributed to the open source community.]

** Organization: 
Skyscope Sentinel Intelligence, ABN 11287984779

### Contributing
Feel free to fork this repository, submit issues, or create pull requests with improvements or additional configurations.
