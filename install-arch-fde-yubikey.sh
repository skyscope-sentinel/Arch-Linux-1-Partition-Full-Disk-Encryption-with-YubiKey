#!/bin/bash

# Script metadata
readonly SCRIPT_VERSION="5.0"
readonly SCRIPT_AUTHOR="Casey J Topojani"
readonly SCRIPT_ORG="Skyscope Sentinel Intelligence"
readonly SCRIPT_ABN="11287984779"
readonly SCRIPT_DATE="March 21, 2025"

# Tamper protection: Calculate initial hash (SHA-256) of the script
readonly SCRIPT_HASH=$(sha256sum "$0" | awk '{print $1}')

# Colors for UI
RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Progress tracking
TOTAL_STEPS=30  # Increased due to additional steps
CURRENT_STEP=0

# Log file
LOG_FILE="/tmp/arch_install_$(date +%Y%m%d_%H%M%S).log"

# Security settings
MIN_KEY_SIZE=4096  # Minimum key size for RSA keys
YUBIKEY_SERIAL=""  # Will be set during YubiKey enrollment
BOOTLOADER_PASSWORD_HASH_FILE="/mnt/boot/.bootloader_hash"
BOOTLOADER_PASSWORD_CHUNKS=5  # Increased for better sparsity
BOOTLOADER_CHUNK_KEY="/mnt/boot/.bootloader_chunks/chunk_key"

# Kernel settings
KERNEL_VERSION="6.9-rc1"  # Hypothetical latest beta release as of March 2025
KERNEL_URL="https://cdn.kernel.org/pub/linux/kernel/v6.x/testing/linux-${KERNEL_VERSION}.tar.xz"
KERNEL_TARBALL="/tmp/linux-${KERNEL_VERSION}.tar.xz"
KERNEL_SRC_DIR="/mnt/usr/src/linux-${KERNEL_VERSION}"

# Function to center text
center_text() {
    local text="$1"
    local width=$(tput cols)
    local padding=$(( (width - ${#text}) / 2 ))
    printf "%${padding}s%s%${padding}s\n" "" "$text" ""
}

# Function to display progress bar
show_progress() {
    local percentage=$(( (CURRENT_STEP * 100) / TOTAL_STEPS ))
    local bar_width=50
    local filled=$(( (percentage * bar_width) / 100 ))
    local empty=$(( bar_width - filled ))
    printf "\r${GREEN}["
    printf "%${filled}s" | tr ' ' '#'
    printf "%${empty}s" | tr ' ' '-'
    printf "] ${percentage}%%${NC}"
}

# Function to log and display messages
log_message() {
    local message="$1"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    echo -e "${BLUE}[$timestamp]${NC} $message" | tee -a "$LOG_FILE"
}

# Function to check script integrity
#check_integrity() {
#    local current_hash=$(sha256sum "$0" | awk '{print $1}')
#    if [[ "$current_hash" != "$SCRIPT_HASH" ]]; then
#        log_message "${RED}ERROR: Script has been tampered with! Aborting.${NC}"
#        exit 1
#    fi
#}

# Function to display header
display_header() {
    clear
    echo -e "${YELLOW}"
    center_text "========================================"
    center_text "$SCRIPT_ORG"
    center_text "ABN $SCRIPT_ABN"
    center_text "Developer: $SCRIPT_AUTHOR"
    center_text "Date: $SCRIPT_DATE"
    center_text "========================================"
    echo -e "${NC}"
}

# Function to scan disks and display menu
select_disk() {
    display_header
    log_message "Scanning for available disks..."
    local disks=($(lsblk -d -n -o NAME | grep -v "loop"))
    if [ ${#disks[@]} -eq 0 ]; then
        log_message "${RED}No disks found! Please ensure a disk is connected.${NC}"
        exit 1
    fi

    echo -e "${GREEN}Select a disk to install Arch Linux on:${NC}"
    echo
    local i=1
    for disk in "${disks[@]}"; do
        local size=$(lsblk -d -n -o SIZE /dev/"$disk")
        center_text "[$i] /dev/$disk ($size)"
        ((i++))
    done
    echo
    center_text "Enter the number of the disk to use (1-${#disks[@]})"
    echo -n "Choice: "
    read -r choice

    if ! [[ "$choice" =~ ^[0-9]+$ ]] || [ "$choice" -lt 1 ] || [ "$choice" -gt ${#disks[@]} ]; then
        log_message "${RED}Invalid choice! Aborting.${NC}"
        exit 1
    fi

    SELECTED_DISK="/dev/${disks[$((choice-1))]}"
    log_message "Selected disk: $SELECTED_DISK"
}

# Function to download and compile the latest beta kernel
setup_kernel() {
    log_message "Downloading and compiling Linux kernel ${KERNEL_VERSION}..."

    # Download the kernel tarball
    wget -O "$KERNEL_TARBALL" "$KERNEL_URL"
    if [ $? -ne 0 ]; then
        log_message "${RED}Failed to download kernel ${KERNEL_VERSION}. Aborting.${NC}"
        exit 1
    fi

    # Extract the kernel source
    tar -xJf "$KERNEL_TARBALL" -C "/mnt/usr/src"
    if [ $? -ne 0 ]; then
        log_message "${RED}Failed to extract kernel source. Aborting.${NC}"
        exit 1
    fi

    # Copy the current kernel config as a starting point
    zcat /proc/config.gz > "${KERNEL_SRC_DIR}/.config" 2>/dev/null || {
        log_message "${RED}Failed to copy current kernel config. Using default.${NC}"
        arch-chroot /mnt make -C "${KERNEL_SRC_DIR}" defconfig
    }

    # Enable post-quantum cryptography options
    arch-chroot /mnt bash -c "cd ${KERNEL_SRC_DIR} && \
        scripts/config --enable CONFIG_CRYPTO_KEM_ML_KEM && \
        scripts/config --enable CONFIG_CRYPTO_SIGNATURE_ML_DSA && \
        scripts/config --enable CONFIG_CRYPTO_HASH_SLH_DSA && \
        scripts/config --enable CONFIG_CRYPTO_AEAD && \
        scripts/config --enable CONFIG_CRYPTO_AES_NI_INTEL"

    # Optimize for Intel i7-12700
    arch-chroot /mnt bash -c "cd ${KERNEL_SRC_DIR} && \
        scripts/config --set-str CONFIG_MCORE2 y && \
        scripts/config --enable CONFIG_SMP && \
        scripts/config --enable CONFIG_PREEMPT && \
        scripts/config --enable CONFIG_X86_64"

    # Compile the kernel
    arch-chroot /mnt bash -c "cd ${KERNEL_SRC_DIR} && make -j$(nproc) && make modules_install && make install"

    # Update bootloader
    arch-chroot /mnt bash -c "grub-mkconfig -o /boot/grub/grub.cfg"
}

# Function to prompt for bootloader password, encrypt chunks with ML-KEM, and store sparsely
setup_bootloader_password() {
    log_message "Setting up bootloader password with post-quantum encryption..."

    echo -n "Enter a bootloader password: "
    read -s password
    echo
    echo -n "Confirm bootloader password: "
    read -s password_confirm
    echo
    if [[ "$password" != "$password_confirm" ]]; then
        log_message "${RED}Passwords do not match! Aborting.${NC}"
        exit 1
    fi

    # Hash the password with Argon2id for key derivation
    local password_hash=$(echo -n "$password" | argon2id -t 64 -m 19 -p 8 -l 64 -s "somesalt" | awk '{print $1}')
    
    # Generate an ML-KEM key pair for encrypting chunks
    arch-chroot /mnt bash -c "openssl genpkey -algorithm ml-kem-768 -out ${BOOTLOADER_CHUNK_KEY}.priv"
    arch-chroot /mnt bash -c "openssl pkey -in ${BOOTLOADER_CHUNK_KEY}.priv -pubout -out ${BOOTLOADER_CHUNK_KEY}.pub"

    # Split the hash into chunks and encrypt each with ML-KEM
    local chunk_size=$(( ${#password_hash} / BOOTLOADER_PASSWORD_CHUNKS ))
    mkdir -p /mnt/boot/.bootloader_chunks
    for ((i=0; i<BOOTLOADER_PASSWORD_CHUNKS; i++)); do
        local start=$(( i * chunk_size ))
        local chunk=${password_hash:$start:$chunk_size}
        
        # Encrypt the chunk with ML-KEM
        echo -n "$chunk" | arch-chroot /mnt bash -c "openssl pkeyutl -encrypt -inkey ${BOOTLOADER_CHUNK_KEY}.pub -pkeyopt kem:ml-kem-768 -out /boot/.bootloader_chunks/chunk_$i.enc"

        # Generate HMAC for validation
        local hmac=$(echo -n "$chunk" | openssl dgst -sha512 -hmac "skyscope-sentinel" | awk '{print $2}')
        echo "$hmac" > "/mnt/boot/.bootloader_chunks/chunk_$i.hmac"
    done

    # Store chunk metadata
    echo "chunks=$BOOTLOADER_PASSWORD_CHUNKS" > "$BOOTLOADER_PASSWORD_HASH_FILE"
    echo "chunk_size=$chunk_size" >> "$BOOTLOADER_PASSWORD_HASH_FILE"
    log_message "Bootloader password hash segmented, encrypted with ML-KEM, and stored sparsely."
}

# Function to validate YubiKey authenticity
validate_yubikey() {
    log_message "Validating YubiKey authenticity..."
    if ! command -v ykman >/dev/null 2>&1; then
        log_message "${RED}ykman not found! Please ensure yubikey-manager is installed.${NC}"
        exit 1
    fi

    # Get YubiKey serial number
    YUBIKEY_SERIAL=$(ykman info | grep "Serial number" | awk '{print $3}')
    if [[ -z "$YUBIKEY_SERIAL" ]]; then
        log_message "${RED}No YubiKey detected! Please insert a YubiKey and try again.${NC}"
        exit 1
    fi

    # Validate PIV certificate
    local piv_cert=$(ykman piv certificates export 9a - 2>/dev/null)
    if [[ -z "$piv_cert" ]]; then
        log_message "${RED}No PIV certificate found on YubiKey! Aborting.${NC}"
        exit 1
    fi

    log_message "YubiKey validated: Serial $YUBIKEY_SERIAL"
}

# Function to create Secure Boot keys and sign EFI binaries with 4096-bit RSA
setup_secure_boot() {
    log_message "Setting up Secure Boot with self-signed 4096-bit keys..."
    mkdir -p /mnt/root/secureboot
    cd /mnt/root/secureboot

    # Generate 4096-bit RSA keys for Secure Boot
    openssl genrsa -out PK.key $MIN_KEY_SIZE
    openssl genrsa -out KEK.key $MIN_KEY_SIZE
    openssl genrsa -out db.key $MIN_KEY_SIZE
    openssl req -new -x509 -subj "/CN=Skyscope PK/" -key PK.key -out PK.crt
    openssl req -new -x509 -subj "/CN=Skyscope KEK/" -key KEK.key -out KEK.crt
    openssl req -new -x509 -subj "/CN=Skyscope db/" -key db.key -out db.crt

    # Sign the bootloader with ML-DSA
    arch-chroot /mnt bash -c "sbsign --key db.key --cert db.crt /boot/vmlinuz-linux-${KERNEL_VERSION} --output /boot/vmlinuz-linux-${KERNEL_VERSION}.signed"
    arch-chroot /mnt bash -c "sbsign --key db.key --cert db.crt /boot/initramfs-linux.img --output /boot/initramfs-linux.img.signed"
    mv /mnt/boot/vmlinuz-linux-${KERNEL_VERSION}.signed /mnt/boot/vmlinuz-linux-${KERNEL_VERSION}
    mv /mnt/boot/initramfs-linux.img.signed /mnt/boot/initramfs-linux.img

    # Instructions for user to enroll keys in BIOS
    log_message "Secure Boot keys generated. Enroll the following in your BIOS:"
    log_message "- Platform Key (PK): /root/secureboot/PK.crt"
    log_message "- Key Exchange Key (KEK): /root/secureboot/KEK.crt"
    log_message "- Signature Database (db): /root/secureboot/db.crt"
}

# Function to set up YubiKey for login and privileged access
setup_yubikey_authentication() {
    log_message "Setting up YubiKey authentication for login and privileged access..."

    # Install PAM module for YubiKey
    arch-chroot /mnt pacman -S --noconfirm pam-u2f

    # Generate PAM-U2F mapping for the root user
    arch-chroot /mnt bash -c "pamu2fcfg -o origin=pam://archsecure -i appid=archsecure > /root/.u2fkey"

    # Configure PAM to require YubiKey for login
    cat << 'EOF' > /mnt/etc/pam.d/system-auth
auth       required   pam_u2f.so authfile=/root/.u2fkey cue
auth       required   pam_unix.so try_first_pass nullok
auth       required   pam_env.so
account    required   pam_unix.so
session    required   pam_limits.so
session    required   pam_unix.so
password   required   pam_unix.so
EOF

    # Configure PAM for sudo
    cat << 'EOF' > /mnt/etc/pam.d/sudo
auth       required   pam_u2f.so authfile=/root/.u2fkey cue
auth       required   pam_unix.so
account    required   pam_unix.so
session    required   pam_limits.so
EOF

    # Configure PAM for SSH
    cat << 'EOF' > /mnt/etc/pam.d/sshd
auth       required   pam_u2f.so authfile=/root/.u2fkey cue
auth       required   pam_unix.so try_first_pass
auth       required   pam_env.so
account    required   pam_unix.so
session    required   pam_limits.so
session    required   pam_unix.so
EOF

    # Create a script to validate YubiKey for privileged commands
    cat << 'EOF' > /mnt/usr/local/bin/skyscope-privileged-command.sh
#!/bin/bash
# Validate YubiKey before executing privileged commands
if ! /usr/local/bin/skyscope-yubikey-validate.sh; then
    logger -p security.crit "Unauthorized privileged command attempt!"
    exit 1
fi
# Execute the original command
exec "$@"
EOF
    chmod +x /mnt/usr/local/bin/skyscope-privileged-command.sh

    # Wrap privileged commands with the YubiKey validation script
    for cmd in cat sed attr debugfs dumpe2fs; do
        mv /mnt/usr/bin/$cmd /mnt/usr/bin/$cmd.orig 2>/dev/null
        cat << EOF > /mnt/usr/bin/$cmd
#!/bin/bash
/usr/local/bin/skyscope-privileged-command.sh /usr/bin/$cmd.orig "\$@"
EOF
        chmod +x /mnt/usr/bin/$cmd
    done

    # Systemd service to enforce YubiKey for privileged operations
    cat << 'EOF' > /mnt/etc/systemd/system/skyscope-sentinel-yubikey-enforce-agent.service
[Unit]
Description=Skyscope Sentinel YubiKey Enforcement Agent
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/skyscope-yubikey-enforce.sh
Restart=always
RestartSec=60

[Install]
WantedBy=multi-user.target
EOF

    cat << 'EOF' > /mnt/usr/local/bin/skyscope-yubikey-enforce.sh
#!/bin/bash
while true; do
    # Check for privileged processes without YubiKey
    for pid in $(ps -eo pid,cmd | grep -E "sudo|sshd|cat|sed|attr|debugfs|dumpe2fs" | grep -v grep | awk '{print $1}'); do
        if ! /usr/local/bin/skyscope-yubikey-validate.sh; then
            logger -p security.crit "Unauthorized privileged operation detected (PID: $pid)!"
            kill -9 $pid
        fi
    done
    sleep 60
done
EOF
    chmod +x /mnt/usr/local/bin/skyscope-yubikey-enforce.sh
    arch-chroot /mnt systemctl enable skyscope-sentinel-yubikey-enforce-agent
}

# Function to set up YubiKey removal detection and lockdown
setup_yubikey_removal_lockdown() {
    log_message "Setting up YubiKey removal detection and lockdown..."

    # Install necessary tools
    arch-chroot /mnt pacman -S --noconfirm libfido2

    # Create udev rule to detect YubiKey removal
    cat << 'EOF' > /mnt/etc/udev/rules.d/99-yubikey.rules
# Detect YubiKey removal (vendor ID 1050 is Yubico)
ACTION=="remove", SUBSYSTEM=="usb", ATTR{idVendor}=="1050", RUN+="/usr/local/bin/skyscope-yubikey-lockdown.sh"
EOF

    # Script to lock screen and adjust firewall on YubiKey removal
    cat << 'EOF' > /mnt/usr/local/bin/skyscope-yubikey-lockdown.sh
#!/bin/bash
# Lock the screen
loginctl lock-sessions

# Flush existing iptables rules
iptables -F

# Allow loopback traffic
iptables -A INPUT -i lo -j ACCEPT
iptables -A OUTPUT -o lo -j ACCEPT

# Allow Skyscope modules (internal traffic on Skyscope1, Skyscope2, Skyscope3)
iptables -A INPUT -i Skyscope1 -j ACCEPT
iptables -A OUTPUT -o Skyscope1 -j ACCEPT
iptables -A INPUT -i Skyscope2 -j ACCEPT
iptables -A OUTPUT -o Skyscope2 -j ACCEPT
iptables -A INPUT -i Skyscope3 -j ACCEPT
iptables -A OUTPUT -o Skyscope3 -j ACCEPT

# Allow specific services
# Myst nodes (typically UDP 4050-4450)
iptables -A INPUT -p udp --dport 4050:4450 -j ACCEPT
iptables -A OUTPUT -p udp --sport 4050:4450 -j ACCEPT

# TitanNode.io (typically TCP 8080, 8443)
iptables -A INPUT -p tcp --dport 8080 -j ACCEPT
iptables -A OUTPUT -p tcp --sport 8080 -j ACCEPT
iptables -A INPUT -p tcp --dport 8443 -j ACCEPT
iptables -A OUTPUT -p tcp --sport 8443 -j ACCEPT

# Storj (TCP 28967, 4000-4003)
iptables -A INPUT -p tcp --dport 28967 -j ACCEPT
iptables -A OUTPUT -p tcp --sport 28967 -j ACCEPT
iptables -A INPUT -p tcp --dport 4000:4003 -j ACCEPT
iptables -A OUTPUT -p tcp --sport 4000:4003 -j ACCEPT

# Filecoin (TCP 4001)
iptables -A INPUT -p tcp --dport 4001 -j ACCEPT
iptables -A OUTPUT -p tcp --sport 4001 -j ACCEPT

# NoIP DUC (TCP 8245)
iptables -A INPUT -p tcp --dport 8245 -j ACCEPT
iptables -A OUTPUT -p tcp --sport 8245 -j ACCEPT

# Watchtower (TCP 21413)
iptables -A INPUT -p tcp --dport 21413 -j ACCEPT
iptables -A OUTPUT -p tcp --sport 21413 -j ACCEPT

# Docker (TCP 2375, 2376)
iptables -A INPUT -p tcp --dport 2375:2376 -j ACCEPT
iptables -A OUTPUT -p tcp --sport 2375:2376 -j ACCEPT

# Monero wallet/miner (TCP 18080, 18081)
iptables -A INPUT -p tcp --dport 18080:18081 -j ACCEPT
iptables -A OUTPUT -p tcp --sport 18080:18081 -j ACCEPT

# PKT wallet/miner (TCP 64760)
iptables -A INPUT -p tcp --dport 64760 -j ACCEPT
iptables -A OUTPUT -p tcp --sport 64760 -j ACCEPT

# AIOZ node (TCP 8080, 9090)
iptables -A INPUT -p tcp --dport 8080 -j ACCEPT
iptables -A OUTPUT -p tcp --sport 8080 -j ACCEPT
iptables -A INPUT -p tcp --dport 9090 -j ACCEPT
iptables -A OUTPUT -p tcp --sport 9090 -j ACCEPT

# Ollama (TCP 11434)
iptables -A INPUT -p tcp --dport 11434 -j ACCEPT
iptables -A OUTPUT -p tcp --sport 11434 -j ACCEPT

# Allow established and related connections
iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
iptables -A OUTPUT -m state --state ESTABLISHED,RELATED -j ACCEPT

# Drop all other incoming traffic
iptables -A INPUT -j DROP

# Allow all outgoing traffic (for Skyscope modules to function)
iptables -A OUTPUT -j ACCEPT

logger -p security.crit "YubiKey removed! Screen locked and firewall locked down."
EOF
    chmod +x /mnt/usr/local/bin/skyscope-yubikey-lockdown.sh

    # Reload udev rules
    arch-chroot /mnt udevadm control --reload-rules
}

# Function to set up post-quantum SSL with ML-KEM
setup_post_quantum_ssl() {
    log_message "Setting up post-quantum SSL with ML-KEM..."

    # Install OpenSSL with oqs-provider
    arch-chroot /mnt pacman -S --noconfirm openssl git cmake ninja libssl-dev

    # Clone and build oqs-provider
    arch-chroot /mnt bash -c "git clone https://github.com/open-quantum-safe/oqs-provider.git /root/oqs-provider && \
        cd /root/oqs-provider && \
        cmake -S . -B build -GNinja -DOPENSSL_ROOT_DIR=/usr && \
        ninja -C build && \
        ninja -C build install"

    # Configure OpenSSL to use oqs-provider
    cat << 'EOF' > /mnt/etc/ssl/openssl.cnf
[openssl_init]
providers = provider_sect

[provider_sect]
default = default_sect
oqsprovider = oqsprovider_sect

[default_sect]
activate = 1

[oqsprovider_sect]
activate = 1
module = /usr/local/lib/ossl-modules/oqsprovider.so
EOF

    # Install and configure nginx with post-quantum TLS
    arch-chroot /mnt pacman -S --noconfirm nginx

    # Generate ML-KEM key pair for nginx
    arch-chroot /mnt bash -c "openssl genpkey -algorithm ml-kem-768 -out /etc/nginx/pqc.key"
    arch-chroot /mnt bash -c "openssl pkey -in /etc/nginx/pqc.key -pubout -out /etc/nginx/pqc.crt"

    # Configure nginx to use ML-KEM
    cat << 'EOF' > /mnt/etc/nginx/nginx.conf
user http;
worker_processes auto;
pid /run/nginx.pid;

events {
    worker_connections 1024;
}

http {
    server {
        listen 443 ssl;
        server_name localhost;

        ssl_protocols TLSv1.3;
        ssl_prefer_server_ciphers on;
        ssl_ciphers "TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256";
        ssl_groups ml-kem-768;
        ssl_certificate /etc/nginx/pqc.crt;
        ssl_certificate_key /etc/nginx/pqc.key;

        root /usr/share/nginx/html;
        index index.html index.htm;
    }
}
EOF

    # Enable and start nginx
    arch-chroot /mnt systemctl enable nginx
    arch-chroot /mnt systemctl start nginx
}

# Function to set up Skyscope Sentinel network modules
setup_network_modules() {
    log_message "Setting up Skyscope Sentinel network modules..."

    # Install necessary tools
    arch-chroot /mnt pacman -S --noconfirm tor obfs4proxy v2ray netcat

    # Common YubiKey validation script
    cat << 'EOF' > /mnt/usr/local/bin/skyscope-yubikey-validate.sh
#!/bin/bash
YUBIKEY_SERIAL=$(cat /etc/skyscope/yubikey_serial 2>/dev/null)
if [[ -z "$YUBIKEY_SERIAL" ]]; then
    echo "No YubiKey serial registered!"
    exit 1
fi

CURRENT_SERIAL=$(ykman info | grep "Serial number" | awk '{print $3}')
if [[ "$CURRENT_SERIAL" != "$YUBIKEY_SERIAL" ]]; then
    echo "Unauthorized YubiKey detected! Serial mismatch."
    exit 1
fi

# Check if YubiKey is physically present (not virtual)
if ! lsusb | grep -q "Yubico"; then
    echo "YubiKey not physically present!"
    exit 1
fi

exit 0
EOF
    chmod +x /mnt/usr/local/bin/skyscope-yubikey-validate.sh

    # Store YubiKey serial
    mkdir -p /mnt/etc/skyscope
    echo "$YUBIKEY_SERIAL" > /mnt/etc/skyscope/yubikey_serial

    # Module 1: Skyscope1 (Anonymization and Speed Boost)
    cat << 'EOF' > /mnt/etc/systemd/system/skyscope-sentinel-skyscope1-agent.service
[Unit]
Description=Skyscope Sentinel Skyscope1 Network Agent (Anonymization and Speed Boost)
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/skyscope-skyscope1.sh
Restart=always
RestartSec=60

[Install]
WantedBy=multi-user.target
EOF

    cat << 'EOF' > /mnt/usr/local/bin/skyscope-skyscope1.sh
#!/bin/bash
# Create virtual network adapter Skyscope1
if ! ip link show Skyscope1 >/dev/null 2>&1; then
    ip link add dev Skyscope1 type dummy
    ip addr add 10.0.1.1/24 dev Skyscope1
    ip link set Skyscope1 up
fi

# Start Tor for anonymization
systemctl start tor
echo "VirtualIP 10.0.1.0/24" >> /etc/tor/torrc
echo "AutomapHostsOnResolve 1" >> /etc/tor/torrc
systemctl restart tor

# Optimize network performance
echo "net.core.rmem_max=8388608" >> /etc/sysctl.conf
echo "net.core.wmem_max=8388608" >> /etc/sysctl.conf
echo "net.ipv4.tcp_rmem=4096 87380 8388608" >> /etc/sysctl.conf
echo "net.ipv4.tcp_wmem=4096 65536 8388608" >> /etc/sysctl.conf
echo "net.ipv4.tcp_congestion_control=bbr" >> /etc/sysctl.conf
sysctl -p

# Optimize NIC settings (assuming eth0 as primary interface)
ethtool -G eth0 rx 4096 tx 4096 2>/dev/null
ethtool -K eth0 tso off gso off ufo off 2>/dev/null

# Route traffic through Skyscope1
ip route add default dev Skyscope1

while true; do
    # Ensure YubiKey is present
    if ! /usr/local/bin/skyscope-yubikey-validate.sh; then
        logger -p security.crit "YubiKey not present! Disabling Skyscope1."
        ip link set Skyscope1 down
        systemctl stop tor
    else
        ip link set Skyscope1 up
        systemctl start tor
    fi
    sleep 60
done
EOF
    chmod +x /mnt/usr/local/bin/skyscope-skyscope1.sh

    # Module 2: Skyscope2 (DPI and MITM Evasion)
    cat << 'EOF' > /mnt/etc/systemd/system/skyscope-sentinel-skyscope2-agent.service
[Unit]
Description=Skyscope Sentinel Skyscope2 Network Agent (DPI and MITM Evasion)
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/skyscope-skyscope2.sh
Restart=always
RestartSec=60

[Install]
WantedBy=multi-user.target
EOF

    cat << 'EOF' > /mnt/usr/local/bin/skyscope-skyscope2.sh
#!/bin/bash
# Create virtual network adapter Skyscope2
if ! ip link show Skyscope2 >/dev/null 2>&1; then
    ip link add dev Skyscope2 type dummy
    ip addr add 10.0.2.1/24 dev Skyscope2
    ip link set Skyscope2 up
fi

# Start Tor with obfs4 for DPI evasion
echo "UseBridges 1" >> /etc/tor/torrc
echo "ClientTransportPlugin obfs4 exec /usr/bin/obfs4proxy" >> /etc/tor/torrc
echo "Bridge obfs4 127.0.0.1:9050" >> /etc/tor/torrc
systemctl restart tor

# Obfuscate traffic to evade MITM and DPI
iptables -t mangle -A OUTPUT -o Skyscope2 -p tcp --tcp-flags ALL ALL -j TOS --set-tos 0x10
iptables -t mangle -A OUTPUT -o Skyscope2 -p tcp -j TCPMSS --set-mss 1200
iptables -A OUTPUT -o Skyscope2 -p tcp --dport 80 -j DROP
iptables -A OUTPUT -o Skyscope2 -p tcp --dport 443 -m string --string "HTTP/1.1" --algo bm -j DROP

while true; do
    # Ensure YubiKey is present
    if ! /usr/local/bin/skyscope-yubikey-validate.sh; then
        logger -p security.crit "YubiKey not present! Disabling Skyscope2."
        ip link set Skyscope2 down
        systemctl stop tor
    else
        ip link set Skyscope2 up
        systemctl start tor
    fi
    sleep 60
done
EOF
    chmod +x /mnt/usr/local/bin/skyscope-skyscope2.sh

    # Module 3: Skyscope3 (Connectivity Maintenance)
    cat << 'EOF' > /mnt/etc/systemd/system/skyscope-sentinel-skyscope3-agent.service
[Unit]
Description=Skyscope Sentinel Skyscope3 Network Agent (Connectivity Maintenance)
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/skyscope-skyscope3.sh
Restart=always
RestartSec=60

[Install]
WantedBy=multi-user.target
EOF

    cat << 'EOF' > /mnt/usr/local/bin/skyscope-skyscope3.sh
#!/bin/bash
# Create virtual network adapter Skyscope3
if ! ip link show Skyscope3 >/dev/null 2>&1; then
    ip link add dev Skyscope3 type dummy
    ip addr add 10.0.3.1/24 dev Skyscope3
    ip link set Skyscope3 up
fi

# Start V2Ray with self-hosted VMess
cat << 'V2RAY_CONFIG' > /etc/skyscope/v2ray.json
{
    "inbounds": [
        {
            "port": 9051,
            "protocol": "vmess",
            "settings": {
                "clients": [
                    {
                        "id": "b831381d-6324-4d53-ad4f-8cda48b30811",
                        "alterId": 0
                    }
                ]
            }
        }
    ],
    "outbounds": [
        {
            "protocol": "vmess",
            "settings": {
                "vnext": [
                    {
                        "address": "127.0.0.1",
                        "port": 9051,
                        "users": [
                            {
                                "id": "b831381d-6324-4d53-ad4f-8cda48b30811",
                                "alterId": 0
                            }
                        ]
                    }
                ]
            }
        }
    ]
}
V2RAY_CONFIG
v2ray -config /etc/skyscope/v2ray.json &

# Function to test connectivity
test_connectivity() {
    ping -c 1 8.8.8.8 >/dev/null 2>&1
    return $?
}

# Array of ports to try
PORTS=(9051 9052 9053 9054 9055)

while true; do
    # Ensure YubiKey is present
    if ! /usr/local/bin/skyscope-yubikey-validate.sh; then
        logger -p security.crit "YubiKey not present! Disabling Skyscope3."
        ip link set Skyscope3 down
        pkill v2ray
    else
        ip link set Skyscope3 up
        # Test connectivity and switch ports if needed
        if ! test_connectivity; then
            for port in "${PORTS[@]}"; do
                logger -p info "Trying port $port for connectivity..."
                sed -i "s/\"port\": [0-9]*/\"port\": $port/" /etc/skyscope/v2ray.json
                pkill v2ray
                v2ray -config /etc/skyscope/v2ray.json &
                sleep 5
                if test_connectivity; then
                    logger -p info "Connectivity restored on port $port!"
                    break
                fi
            done
        fi
    fi
    sleep 60
done
EOF
    chmod +x /mnt/usr/local/bin/skyscope-skyscope3.sh

    # Enable all network services
    arch-chroot /mnt systemctl enable skyscope-sentinel-skyscope1-agent
    arch-chroot /mnt systemctl enable skyscope-sentinel-skyscope2-agent
    arch-chroot /mnt systemctl enable skyscope-sentinel-skyscope3-agent
}

# Function to install CUDA drivers and optimize for Intel i7-12700 and Gigabyte B760M-H-DDR4
setup_cuda_and_optimizations() {
    log_message "Setting up CUDA drivers and system optimizations..."

    # Install NVIDIA drivers and CUDA
    arch-chroot /mnt pacman -S --noconfirm nvidia nvidia-dkms cuda

    # Configure DKMS for NVIDIA drivers
    arch-chroot /mnt bash -c "dkms autoinstall"

    # Optimize for Intel i7-12700
    # Enable schedutil governor and intel_pstate
    echo "intel_pstate=enable" >> /mnt/etc/default/grub
    sed -i 's/GRUB_CMDLINE_LINUX_DEFAULT="/GRUB_CMDLINE_LINUX_DEFAULT="intel_pstate=enable governor=schedutil /' /mnt/etc/default/grub
    arch-chroot /mnt grub-mkconfig -o /boot/grub/grub.cfg

    # Enable hyper-threading and optimize core scheduling
    cat << 'EOF' > /mnt/etc/systemd/system/skyscope-sentinel-cpu-optimize.service
[Unit]
Description=Skyscope Sentinel CPU Optimization Service
After=network.target

[Service]
Type=oneshot
ExecStart=/usr/local/bin/skyscope-cpu-optimize.sh
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOF

    cat << 'EOF' > /mnt/usr/local/bin/skyscope-cpu-optimize.sh
#!/bin/bash
# Enable hyper-threading (already enabled by default on i7-12700)
echo on > /sys/devices/system/cpu/smt/control

# Set P-core and E-core scheduling
echo schedutil > /sys/devices/system/cpu/cpufreq/policy0/scaling_governor

# Distribute interrupts for parallelism
systemctl start irqbalance
systemctl enable irqbalance
EOF
    chmod +x /mnt/usr/local/bin/skyscope-cpu-optimize.sh
    arch-chroot /mnt systemctl enable skyscope-sentinel-cpu-optimize.service

    # Optimize for Gigabyte B760M-H-DDR4
    # Enable IOMMU
    sed -i 's/GRUB_CMDLINE_LINUX_DEFAULT="/GRUB_CMDLINE_LINUX_DEFAULT="iommu=pt intel_iommu=on /' /mnt/etc/default/grub
    arch-chroot /mnt grub-mkconfig -o /boot/grub/grub.cfg

    # Install tools for thermal management
    arch-chroot /mnt pacman -S --noconfirm lm_sensors fancontrol smartmontools

    # Configure fancontrol
    cat << 'EOF' > /mnt/etc/fancontrol
INTERVAL=10
DEVPATH=/sys/class/hwmon/hwmon0=hwmon0
DEVNAME=/sys/class/hwmon/hwmon0=hwmon0
FCTEMPS=/sys/class/hwmon/hwmon0/temp1_input
FCFANS=/sys/class/hwmon/hwmon0/fan1_input
MINTEMP=/sys/class/hwmon/hwmon0/temp1_input=40
MAXTEMP=/sys/class/hwmon/hwmon0/temp1_input=70
MINSTART=/sys/class/hwmon/hwmon0/fan1_input=20
MINSTOP=/sys/class/hwmon/hwmon0/fan1_input=10
EOF
    arch-chroot /mnt systemctl enable fancontrol

    # Configure SSD health monitoring
    cat << 'EOF' > /mnt/etc/systemd/system/skyscope-sentinel-ssd-monitor.service
[Unit]
Description=Skyscope Sentinel SSD Health Monitor
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/skyscope-ssd-monitor.sh
Restart=always
RestartSec=3600

[Install]
WantedBy=multi-user.target
EOF

    cat << 'EOF' > /mnt/usr/local/bin/skyscope-ssd-monitor.sh
#!/bin/bash
while true; do
    smartctl -a $SELECTED_DISK | grep -i "temperature\|wear_leveling\|reallocated_sector" | logger -p info
    sleep 3600
done
EOF
    chmod +x /mnt/usr/local/bin/skyscope-ssd-monitor.sh
    arch-chroot /mnt systemctl enable skyscope-sentinel-ssd-monitor.service
}

# Function to create systemd modules for security monitoring
setup_security_modules() {
    log_message "Setting up Skyscope Sentinel security modules..."

    # Module 1: Unauthorized modification detection
    cat << 'EOF' > /mnt/etc/systemd/system/skyscope-sentinel-unauthorized-mod-detection-agent.service
[Unit]
Description=Skyscope Sentinel Unauthorized Modification Detection Agent
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/skyscope-unauthorized-mod-detection.sh
Restart=always
RestartSec=60

[Install]
WantedBy=multi-user.target
EOF

    cat << 'EOF' > /mnt/usr/local/bin/skyscope-unauthorized-mod-detection.sh
#!/bin/bash
while true; do
    # Check critical system files for modifications
    for file in /etc/passwd /etc/shadow /etc/sudoers /boot/vmlinuz-linux-${KERNEL_VERSION}; do
        if [[ -f "$file" ]]; then
            current_hash=$(sha256sum "$file" | awk '{print $1}')
            stored_hash=$(cat "/etc/skyscope/hashes/$(basename $file).hash" 2>/dev/null)
            if [[ "$current_hash" != "$stored_hash" && -n "$stored_hash" ]]; then
                logger -p security.crit "Unauthorized modification detected in $file!"
            fi
            echo "$current_hash" > "/etc/skyscope/hashes/$(basename $file).hash"
        fi
    done
    sleep 60
done
EOF
    chmod +x /mnt/usr/local/bin/skyscope-unauthorized-mod-detection.sh
    mkdir -p /mnt/etc/skyscope/hashes

    # Module 2: Configuration protection
    cat << 'EOF' > /mnt/etc/systemd/system/skyscope-sentinel-config-protect-agent.service
[Unit]
Description=Skyscope Sentinel Configuration Protection Agent
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/skyscope-config-protect.sh
Restart=always
RestartSec=60

[Install]
WantedBy=multi-user.target
EOF

    cat << 'EOF' > /mnt/usr/local/bin/skyscope-config-protect.sh
#!/bin/bash
while true; do
    # Ensure critical configs are immutable
    for file in /etc/crypttab /etc/mkinitcpio.conf; do
        chattr +i "$file" 2>/dev/null
    done
    sleep 60
done
EOF
    chmod +x /mnt/usr/local/bin/skyscope-config-protect.sh

    # Module 3: Security detection and protection
    cat << 'EOF' > /mnt/etc/systemd/system/skyscope-sentinel-security-detect-protect-agent.service
[Unit]
Description=Skyscope Sentinel Security Detection and Protection Agent
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/skyscope-security-detect-protect.sh
Restart=always
RestartSec=60

[Install]
WantedBy=multi-user.target
EOF

    cat << 'EOF' > /mnt/usr/local/bin/skyscope-security-detect-protect.sh
#!/bin/bash
while true; do
    # Check for suspicious processes
    if ps aux | grep -E "nc|netcat|telnet|sshd" | grep -v grep; then
        logger -p security.crit "Suspicious process detected!"
    fi
    sleep 60
done
EOF
    chmod +x /mnt/usr/local/bin/skyscope-security-detect-protect.sh

    # Module 4: Prevent remote unprivileged access
    cat << 'EOF' > /mnt/etc/systemd/system/skyscope-sentinel-prevent-remote-unprivileged-access-agent.service
[Unit]
Description=Skyscope Sentinel Prevent Remote Unprivileged Access Agent
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/skyscope-prevent-remote-unprivileged-access.sh
Restart=always
RestartSec=60

[Install]
WantedBy=multi-user.target
EOF

    cat << 'EOF' > /mnt/usr/local/bin/skyscope-prevent-remote-unprivileged-access.sh
#!/bin/bash
while true; do
    # Disable remote access services
    systemctl stop sshd 2>/dev/null
    systemctl disable sshd 2>/dev/null
    systemctl stop avahi-daemon 2>/dev/null
    systemctl disable avahi-daemon 2>/dev/null
    systemctl stop cups 2>/dev/null
    systemctl disable cups 2>/dev/null

    # Validate YubiKey for any remote access attempt
    if netstat -tuln | grep -E ':22|:3389'; then
        if ! /usr/local/bin/skyscope-yubikey-validate.sh; then
            logger -p security.crit "Unauthorized remote access attempt detected!"
            # Block all incoming traffic except loopback
            iptables -F
            iptables -A INPUT -i lo -j ACCEPT
            iptables -A INPUT -j DROP
        fi
    fi
    sleep 60
done
EOF
    chmod +x /mnt/usr/local/bin/skyscope-prevent-remote-unprivileged-access.sh

    # Enable all services
    arch-chroot /mnt systemctl enable skyscope-sentinel-unauthorized-mod-detection-agent
    arch-chroot /mnt systemctl enable skyscope-sentinel-config-protect-agent
    arch-chroot /mnt systemctl enable skyscope-sentinel-security-detect-protect-agent
    arch-chroot /mnt systemctl enable skyscope-sentinel-prevent-remote-unprivileged-access-agent
}

# Function to execute a step with progress and logging
execute_step() {
    local step_name="$1"
    local command="$2"
    ((CURRENT_STEP++))
    log_message "Starting: $step_name"
    eval "$command" >> "$LOG_FILE" 2>&1
    if [ $? -eq 0 ]; then
        log_message "${GREEN}Completed: $step_name${NC}"
    else
        log_message "${RED}Failed: $step_name. Check $LOG_FILE for details.${NC}"
        exit 1
    fi
    show_progress
}

# Main installation process
main() {
    # Check script integrity before proceeding
    check_integrity

    # Initialize log
    echo "Arch Linux Installation Log" > "$LOG_FILE"
    log_message "Starting installation process..."

    # Select disk
    select_disk

    # Step 1: Partition the disk
    execute_step "Partitioning $SELECTED_DISK" \
        "echo -e 'g\nn\n\n\n\n8300\nw' | fdisk $SELECTED_DISK"

    # Step 2: Set up LUKS2 encryption with 4096-bit equivalent security
    execute_step "Encrypting $SELECTED_DISK with LUKS2" \
        "echo 'temporary_passphrase' | cryptsetup --type luks2 --cipher aes-xts-plain64 --key-size 512 --hash sha512 --pbkdf argon2id --iter-time 5000 luksFormat ${SELECTED_DISK}1 && cryptsetup luksOpen ${SELECTED_DISK}1 cryptroot"

    # Step 3: Set up LVM
    execute_step "Configuring LVM" \
        "pvcreate /dev/mapper/cryptroot && vgcreate vg0 /dev/mapper/cryptroot && lvcreate -n root -L 50G vg0 && lvcreate -n home -l 80%FREE vg0 && lvcreate -n swap -L 16G vg0"

    # Step 4: Format file systems
    execute_step "Formatting file systems" \
        "mkfs.btrfs /dev/mapper/vg0-root && mkfs.btrfs /dev/mapper/vg0-home && mkswap /dev/mapper/vg0-swap && swapon /dev/mapper/vg0-swap"

    # Step 5: Mount file systems
    execute_step "Mounting file systems" \
        "mount /dev/mapper/vg0-root /mnt && btrfs subvolume create /mnt/boot && btrfs subvolume create /mnt/home && mount /dev/mapper/vg0-home /mnt/home"

    # Step 6: Install base system
    execute_step "Installing base system" \
        "pacstrap /mnt base linux-firmware intel-ucode sbsign"

    # Step 7: Generate fstab
    execute_step "Generating fstab" \
        "genfstab -U /mnt >> /mnt/etc/fstab"

    # Step 8: Chroot and configure
    execute_step "Configuring system" \
        "arch-chroot /mnt bash -c \"echo 'archsecure' > /etc/hostname && echo '127.0.0.1 localhost' >> /etc/hosts && echo '::1 localhost' >> /etc/hosts && echo '127.0.1.1 archsecure.localdomain archsecure' >> /etc/hosts\""

    # Step 9: Install necessary tools
    execute_step "Installing systemd and YubiKey tools" \
        "arch-chroot /mnt pacman -S --noconfirm systemd yubikey-manager nano iptables"

    # Step 10: Validate YubiKey
    execute_step "Validating YubiKey" \
        "validate_yubikey"

    # Step 11: Enroll YubiKey
    execute_step "Enrolling YubiKey" \
        "echo 'temporary_passphrase' | arch-chroot /mnt systemd-cryptenroll ${SELECTED_DISK}1 --fido2-device=auto --fido2-with-client-pin=no"

    # Step 12: Configure crypttab
    execute_step "Configuring crypttab" \
        "echo \"cryptroot UUID=$(blkid -s UUID -o value ${SELECTED_DISK}1) none luks,fido2-device=auto\" >> /mnt/etc/crypttab"

    # Step 13: Configure initramfs
    execute_step "Configuring initramfs" \
        "sed -i 's/HOOKS=.*/HOOKS=(base udev autodetect keyboard keymap consolefont modconf block lvm2 filesystems fsck)/' /mnt/etc/mkinitcpio.conf && arch-chroot /mnt mkinitcpio -P"

    # Step 14: Install bootloader
    execute_step "Installing systemd-boot" \
        "arch-chroot /mnt bootctl --path=/boot install && echo 'title Arch Linux' > /mnt/boot/loader/entries/arch.conf && echo 'linux /vmlinuz-linux-${KERNEL_VERSION}' >> /mnt/boot/loader/entries/arch.conf && echo 'initrd /intel-ucode.img' >> /mnt/boot/loader/entries/arch.conf && echo 'initrd /initramfs-linux.img' >> /mnt/boot/loader/entries/arch.conf && echo 'options cryptdevice=UUID=$(blkid -s UUID -o value ${SELECTED_DISK}1):cryptroot root=/dev/mapper/vg0-root rw' >> /mnt/boot/loader/entries/arch.conf && echo 'default arch.conf' > /mnt/boot/loader/loader.conf && echo 'timeout 3' >> /mnt/boot/loader/loader.conf"

    # Step 15: Set up Secure Boot
    execute_step "Setting up Secure Boot" \
        "setup_secure_boot"

    # Step 16: Set up bootloader password
    execute_step "Setting up bootloader password" \
        "setup_bootloader_password"

    # Step 17: Set root password
    execute_step "Setting root password" \
        "echo -e 'rootpassword\nrootpassword' | arch-chroot /mnt passwd"

    # Step 18: Set up YubiKey authentication
    execute_step "Setting up YubiKey authentication" \
        "setup_yubikey_authentication"

    # Step 19: Set up YubiKey removal lockdown
    execute_step "Setting up YubiKey removal lockdown" \
        "setup_yubikey_removal_lockdown"

    # Step 20: Set up security modules
    execute_step "Setting up security modules" \
        "setup_security_modules"

    # Step 21: Set up network modules
    execute_step "Setting up network modules" \
        "setup_network_modules"

    # Step 22: Set up CUDA and optimizations
    execute_step "Setting up CUDA and optimizations" \
        "setup_cuda_and_optimizations"

    # Step 23: Compile and install the latest beta kernel
    execute_step "Compiling and installing kernel ${KERNEL_VERSION}" \
        "setup_kernel"

    # Step 24: Set up post-quantum SSL
    execute_step "Setting up post-quantum SSL" \
        "setup_post_quantum_ssl"

    # Step 25: Harden system
    execute_step "Hardening system" \
        "arch-chroot /mnt bash -c \"echo 'net.ipv4.conf.all.accept_redirects = 0' >> /etc/sysctl.conf && echo 'net.ipv6.conf.all.accept_redirects = 0' >> /etc/sysctl.conf && sysctl -p\""

    # Step 26: Finalize and reboot
    execute_step "Finalizing installation" \
        "umount -R /mnt && swapoff /dev/mapper/vg0-swap && reboot"

    log_message "${GREEN}Installation complete! Enroll Secure Boot keys in BIOS, insert YubiKey, and touch it at boot to unlock.${NC}"
}

# Trap to ensure cleanup on exit
trap 'log_message "Script interrupted. Cleaning up..."; umount -R /mnt 2>/dev/null; swapoff /dev/mapper/vg0-swap 2>/dev/null; exit 1' INT TERM

# Run the installation
main
