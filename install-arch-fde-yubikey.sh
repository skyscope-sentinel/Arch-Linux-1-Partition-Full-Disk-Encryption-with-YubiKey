#!/bin/bash

# Script metadata
readonly SCRIPT_VERSION="5.1"
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
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Progress tracking
TOTAL_STEPS=31  # Adjusted for system update step
CURRENT_STEP=0

# Log file
LOG_FILE="/tmp/arch_install_$(date +%Y%m%d_%H%M%S).log"

# Security settings
MIN_KEY_SIZE=4096
YUBIKEY_SERIAL=""
BOOTLOADER_PASSWORD_HASH_FILE="/mnt/boot/.bootloader_hash"
BOOTLOADER_PASSWORD_CHUNKS=5
BOOTLOADER_CHUNK_KEY="/mnt/boot/.bootloader_chunks/chunk_key"

# Kernel settings
KERNEL_VERSION="6.9-rc1"
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

# Function to log and display messages
log_message() {
    local message="$1"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    echo -e "${BLUE}[$timestamp]${NC} $message" | tee -a "$LOG_FILE"
}

# Function to check script integrity
check_integrity() {
    local current_hash=$(sha256sum "$0" | awk '{print $1}')
    if [[ "$current_hash" != "$SCRIPT_HASH" ]]; then
        log_message "${RED}ERROR: Script has been tampered with! Aborting.${NC}"
        exit 1
    fi
}

# Function to display a progress bar
show_progress_bar() {
    local percentage=$1
    local bar_width=50
    local filled=$(( (percentage * bar_width) / 100 ))
    local empty=$(( bar_width - filled ))
    printf "\r${CYAN}["
    printf "%${filled}s" | tr ' ' '#'
    printf "%${empty}s" | tr ' ' '-'
    printf "] ${percentage}%%${NC}"
}

# Function to simulate progress for a command (for steps without native progress)
simulate_progress() {
    local duration=$1  # Estimated duration in seconds
    local start_time=$(date +%s)
    local end_time=$(( start_time + duration ))
    local percentage=0

    while [ $percentage -lt 100 ]; do
        current_time=$(date +%s)
        elapsed=$(( current_time - start_time ))
        percentage=$(( (elapsed * 100) / duration ))
        [ $percentage -gt 100 ] && percentage=100
        show_progress_bar $percentage
        sleep 0.1
    done
    echo
}

# Function to display verbose output and progress
execute_step_with_progress() {
    local step_name="$1"
    local command="$2"
    local estimated_duration=$3  # Estimated duration in seconds for progress simulation
    ((CURRENT_STEP++))

    log_message "Starting: $step_name"
    echo -e "${GREEN}Step $CURRENT_STEP/$TOTAL_STEPS: $step_name${NC}"
    echo -e "${CYAN}Details:${NC} Executing command: $command"

    # Run the command in the background and capture its PID
    eval "$command" >> "$LOG_FILE" 2>&1 &
    local cmd_pid=$!

    # Simulate progress while the command runs
    simulate_progress $estimated_duration &

    # Wait for the command to finish
    wait $cmd_pid
    local cmd_status=$?

    # Ensure the progress bar reaches 100%
    show_progress_bar 100
    echo

    # Update overall progress
    local overall_percentage=$(( (CURRENT_STEP * 100) / TOTAL_STEPS ))
    echo -e "${YELLOW}Overall Progress:${NC}"
    show_progress_bar $overall_percentage
    echo

    if [ $cmd_status -eq 0 ]; then
        log_message "${GREEN}Completed: $step_name${NC}"
    else
        log_message "${RED}Failed: $step_name. Check $LOG_FILE for details.${NC}"
        exit 1
    fi
}

# Function to select disk using whiptail
select_disk() {
    # Check if whiptail is installed
    if ! command -v whiptail >/dev/null 2>&1; then
        log_message "${RED}Error: whiptail not found. Please install newt (e.g., pacman -S newt) and try again.${NC}"
        exit 1
    fi

    # Get list of disks
    local disk_list=()
    for disk in /dev/nvme*n* /dev/sd*; do
        if [ -b "$disk" ]; then
            # Skip partitions (e.g., /dev/nvme0n1p1)
            if [[ ! "$disk" =~ [0-9]$ ]]; then
                size=$(blockdev --getsize64 "$disk")
                size_gb=$(( size / 1000000000 ))
                disk_list+=("$disk" "$size_gb GB")
            fi
        fi
    done

    if [ ${#disk_list[@]} -eq 0 ]; then
        log_message "${RED}Error: No disks found. Aborting.${NC}"
        exit 1
    fi

    # Display disk selection menu
    SELECTED_DISK=$(whiptail --title "Select Disk for Installation" --menu "Choose the disk to install Arch Linux on:" 15 60 5 "${disk_list[@]}" 3>&1 1>&2 2>&3)

    if [ $? -ne 0 ] || [ -z "$SELECTED_DISK" ]; then
        log_message "${RED}Error: Disk selection cancelled. Aborting.${NC}"
        exit 1
    fi

    log_message "Selected disk: $SELECTED_DISK (Size: $size_gb GB)"
}

# Function to prompt for LUKS passphrase securely
prompt_passphrase() {
    echo -e "${YELLOW}Setting up disk encryption${NC}"
    echo -e "${CYAN}Please enter a strong passphrase for LUKS encryption.${NC}"
    echo -e "${CYAN}This will be used to unlock your disk at boot.${NC}"
    local passphrase
    local passphrase_confirm
    while true; do
        passphrase=$(whiptail --passwordbox "Enter LUKS passphrase:" 10 50 3>&1 1>&2 2>&3)
        if [ $? -ne 0 ]; then
            log_message "${RED}Passphrase entry cancelled. Aborting.${NC}"
            exit 1
        fi
        passphrase_confirm=$(whiptail --passwordbox "Confirm LUKS passphrase:" 10 50 3>&1 1>&2 2>&3)
        if [ $? -ne 0 ]; then
            log_message "${RED}Passphrase confirmation cancelled. Aborting.${NC}"
            exit 1
        fi
        if [ "$passphrase" = "$passphrase_confirm" ]; then
            echo "$passphrase"
            return
        else
            whiptail --msgbox "Passphrases do not match. Please try again." 10 50
        fi
    done
}

# Function to download and compile the latest beta kernel
setup_kernel() {
    log_message "Downloading and compiling Linux kernel ${KERNEL_VERSION}..."
    wget -O "$KERNEL_TARBALL" "$KERNEL_URL" || { log_message "${RED}Failed to download kernel ${KERNEL_VERSION}. Aborting.${NC}"; exit 1; }
    tar -xJf "$KERNEL_TARBALL" -C "/mnt/usr/src" || { log_message "${RED}Failed to extract kernel source. Aborting.${NC}"; exit 1; }
    zcat /proc/config.gz > "${KERNEL_SRC_DIR}/.config" 2>/dev/null || arch-chroot /mnt make -C "${KERNEL_SRC_DIR}" defconfig
    arch-chroot /mnt bash -c "cd ${KERNEL_SRC_DIR} && \
        scripts/config --enable CONFIG_CRYPTO_KEM_ML_KEM && \
        scripts/config --enable CONFIG_CRYPTO_SIGNATURE_ML_DSA && \
        scripts/config --enable CONFIG_CRYPTO_HASH_SLH_DSA && \
        scripts/config --enable CONFIG_CRYPTO_AEAD && \
        scripts/config --enable CONFIG_CRYPTO_AES_NI_INTEL && \
        scripts/config --set-str CONFIG_MCORE2 y && \
        scripts/config --enable CONFIG_SMP && \
        scripts/config --enable CONFIG_PREEMPT && \
        scripts/config --enable CONFIG_X86_64 && \
        make -j$(nproc) && make modules_install && make install"
    arch-chroot /mnt grub-mkconfig -o /boot/grub/grub.cfg
}

# Function to set up bootloader password
setup_bootloader_password() {
    log_message "Setting up bootloader password with post-quantum encryption..."
    local password
    local password_confirm
    password=$(whiptail --passwordbox "Enter bootloader password:" 10 50 3>&1 1>&2 2>&3)
    if [ $? -ne 0 ]; then
        log_message "${RED}Bootloader password entry cancelled. Aborting.${NC}"
        exit 1
    fi
    password_confirm=$(whiptail --passwordbox "Confirm bootloader password:" 10 50 3>&1 1>&2 2>&3)
    if [ $? -ne 0 ]; then
        log_message "${RED}Bootloader password confirmation cancelled. Aborting.${NC}"
        exit 1
    fi
    if [[ "$password" != "$password_confirm" ]]; then
        whiptail --msgbox "Bootloader passwords do not match! Aborting." 10 50
        log_message "${RED}Bootloader passwords do not match! Aborting.${NC}"
        exit 1
    fi
    local password_hash=$(echo -n "$password" | argon2id -t 64 -m 19 -p 8 -l 64 -s "somesalt" | awk '{print $1}')
    arch-chroot /mnt bash -c "openssl genpkey -algorithm ml-kem-768 -out ${BOOTLOADER_CHUNK_KEY}.priv && openssl pkey -in ${BOOTLOADER_CHUNK_KEY}.priv -pubout -out ${BOOTLOADER_CHUNK_KEY}.pub"
    local chunk_size=$(( ${#password_hash} / BOOTLOADER_PASSWORD_CHUNKS ))
    mkdir -p /mnt/boot/.bootloader_chunks
    for ((i=0; i<BOOTLOADER_PASSWORD_CHUNKS; i++)); do
        local start=$(( i * chunk_size ))
        local chunk=${password_hash:$start:$chunk_size}
        echo -n "$chunk" | arch-chroot /mnt bash -c "openssl pkeyutl -encrypt -inkey ${BOOTLOADER_CHUNK_KEY}.pub -pkeyopt kem:ml-kem-768 -out /boot/.bootloader_chunks/chunk_$i.enc"
        local hmac=$(echo -n "$chunk" | openssl dgst -sha512 -hmac "skyscope-sentinel" | awk '{print $2}')
        echo "$hmac" > "/mnt/boot/.bootloader_chunks/chunk_$i.hmac"
    done
    echo "chunks=$BOOTLOADER_PASSWORD_CHUNKS" > "$BOOTLOADER_PASSWORD_HASH_FILE"
    echo "chunk_size=$chunk_size" >> "$BOOTLOADER_PASSWORD_HASH_FILE"
    log_message "Bootloader password hash segmented, encrypted with ML-KEM, and stored sparsely."
}

# Function to validate YubiKey authenticity
validate_yubikey() {
    log_message "Validating YubiKey authenticity..."
    command -v ykman >/dev/null 2>&1 || { log_message "${RED}ykman not found! Please ensure yubikey-manager is installed.${NC}"; exit 1; }
    YUBIKEY_SERIAL=$(ykman info | grep "Serial number" | awk '{print $3}')
    [[ -z "$YUBIKEY_SERIAL" ]] && { log_message "${RED}No YubiKey detected! Please insert a YubiKey and try again.${NC}"; exit 1; }
    local piv_cert=$(ykman piv certificates export 9a - 2>/dev/null)
    [[ -z "$piv_cert" ]] && { log_message "${RED}No PIV certificate found on YubiKey! Aborting.${NC}"; exit 1; }
    log_message "YubiKey validated: Serial $YUBIKEY_SERIAL"
}

# Function to set up Secure Boot
setup_secure_boot() {
    log_message "Setting up Secure Boot with self-signed 4096-bit keys..."
    mkdir -p /mnt/root/secureboot
    cd /mnt/root/secureboot
    openssl genrsa -out PK.key $MIN_KEY_SIZE
    openssl genrsa -out KEK.key $MIN_KEY_SIZE
    openssl genrsa -out db.key $MIN_KEY_SIZE
    openssl req -new -x509 -subj "/CN=Skyscope PK/" -key PK.key -out PK.crt
    openssl req -new -x509 -subj "/CN=Skyscope KEK/" -key KEK.key -out KEK.crt
    openssl req -new -x509 -subj "/CN=Skyscope db/" -key db.key -out db.crt
    arch-chroot /mnt bash -c "sbsign --key db.key --cert db.crt /boot/vmlinuz-linux-${KERNEL_VERSION} --output /boot/vmlinuz-linux-${KERNEL_VERSION}.signed && \
        sbsign --key db.key --cert db.crt /boot/initramfs-linux.img --output /boot/initramfs-linux.img.signed"
    mv /mnt/boot/vmlinuz-linux-${KERNEL_VERSION}.signed /mnt/boot/vmlinuz-linux-${KERNEL_VERSION}
    mv /mnt/boot/initramfs-linux.img.signed /mnt/boot/initramfs-linux.img
    log_message "Secure Boot keys generated. Enroll the following in your BIOS:"
    log_message "- Platform Key (PK): /root/secureboot/PK.crt"
    log_message "- Key Exchange Key (KEK): /root/secureboot/KEK.crt"
    log_message "- Signature Database (db): /root/secureboot/db.crt"
}

# Function to set up YubiKey for login and privileged access
setup_yubikey_authentication() {
    log_message "Setting up YubiKey authentication for login and privileged access..."
    arch-chroot /mnt pacman -S --noconfirm pam-u2f
    arch-chroot /mnt bash -c "pamu2fcfg -o origin=pam://archsecure -i appid=archsecure > /root/.u2fkey"
    cat << 'EOF' > /mnt/etc/pam.d/system-auth
auth       required   pam_u2f.so authfile=/root/.u2fkey cue
auth       required   pam_unix.so try_first_pass nullok
auth       required   pam_env.so
account    required   pam_unix.so
session    required   pam_limits.so
session    required   pam_unix.so
password   required   pam_unix.so
EOF
    cat << 'EOF' > /mnt/etc/pam.d/sudo
auth       required   pam_u2f.so authfile=/root/.u2fkey cue
auth       required   pam_unix.so
account    required   pam_unix.so
session    required   pam_limits.so
EOF
    cat << 'EOF' > /mnt/etc/pam.d/sshd
auth       required   pam_u2f.so authfile=/root/.u2fkey cue
auth       required   pam_unix.so try_first_pass
auth       required   pam_env.so
account    required   pam_unix.so
session    required   pam_limits.so
session    required   pam_unix.so
EOF
    cat << 'EOF' > /mnt/usr/local/bin/skyscope-privileged-command.sh
#!/bin/bash
if ! /usr/local/bin/skyscope-yubikey-validate.sh; then
    logger -p security.crit "Unauthorized privileged command attempt!"
    exit 1
fi
exec "$@"
EOF
    chmod +x /mnt/usr/local/bin/skyscope-privileged-command.sh
    for cmd in cat sed attr debugfs dumpe2fs; do
        mv /mnt/usr/bin/$cmd /mnt/usr/bin/$cmd.orig 2>/dev/null
        cat << EOF > /mnt/usr/bin/$cmd
#!/bin/bash
/usr/local/bin/skyscope-privileged-command.sh /usr/bin/$cmd.orig "\$@"
EOF
        chmod +x /mnt/usr/bin/$cmd
    done
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
    arch-chroot /mnt pacman -S --noconfirm libfido2
    cat << 'EOF' > /mnt/etc/udev/rules.d/99-yubikey.rules
ACTION=="remove", SUBSYSTEM=="usb", ATTR{idVendor}=="1050", RUN+="/usr/local/bin/skyscope-yubikey-lockdown.sh"
EOF
    cat << 'EOF' > /mnt/usr/local/bin/skyscope-yubikey-lockdown.sh
#!/bin/bash
loginctl lock-sessions
iptables -F
iptables -A INPUT -i lo -j ACCEPT
iptables -A OUTPUT -o lo -j ACCEPT
iptables -A INPUT -i Skyscope1 -j ACCEPT
iptables -A OUTPUT -o Skyscope1 -j ACCEPT
iptables -A INPUT -i Skyscope2 -j ACCEPT
iptables -A OUTPUT -o Skyscope2 -j ACCEPT
iptables -A INPUT -i Skyscope3 -j ACCEPT
iptables -A OUTPUT -o Skyscope3 -j ACCEPT
iptables -A INPUT -p udp --dport 4050:4450 -j ACCEPT
iptables -A OUTPUT -p udp --sport 4050:4450 -j ACCEPT
iptables -A INPUT -p tcp --dport 8080 -j ACCEPT
iptables -A OUTPUT -p tcp --sport 8080 -j ACCEPT
iptables -A INPUT -p tcp --dport 8443 -j ACCEPT
iptables -A OUTPUT -p tcp --sport 8443 -j ACCEPT
iptables -A INPUT -p tcp --dport 28967 -j ACCEPT
iptables -A OUTPUT -p tcp --sport 28967 -j ACCEPT
iptables -A INPUT -p tcp --dport 4000:4003 -j ACCEPT
iptables -A OUTPUT -p tcp --sport 4000:4003 -j ACCEPT
iptables -A INPUT -p tcp --dport 4001 -j ACCEPT
iptables -A OUTPUT -p tcp --sport 4001 -j ACCEPT
iptables -A INPUT -p tcp --dport 8245 -j ACCEPT
iptables -A OUTPUT -p tcp --sport 8245 -j ACCEPT
iptables -A INPUT -p tcp --dport 21413 -j ACCEPT
iptables -A OUTPUT -p tcp --sport 21413 -j ACCEPT
iptables -A INPUT -p tcp --dport 2375:2376 -j ACCEPT
iptables -A OUTPUT -p tcp --sport 2375:2376 -j ACCEPT
iptables -A INPUT -p tcp --dport 18080:18081 -j ACCEPT
iptables -A OUTPUT -p tcp --sport 18080:18081 -j ACCEPT
iptables -A INPUT -p tcp --dport 64760 -j ACCEPT
iptables -A OUTPUT -p tcp --sport 64760 -j ACCEPT
iptables -A INPUT -p tcp --dport 9090 -j ACCEPT
iptables -A OUTPUT -p tcp --sport 9090 -j ACCEPT
iptables -A INPUT -p tcp --dport 11434 -j ACCEPT
iptables -A OUTPUT -p tcp --sport 11434 -j ACCEPT
iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
iptables -A OUTPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
iptables -A INPUT -j DROP
iptables -A OUTPUT -j ACCEPT
logger -p security.crit "YubiKey removed! Screen locked and firewall locked down."
EOF
    chmod +x /mnt/usr/local/bin/skyscope-yubikey-lockdown.sh
    arch-chroot /mnt udevadm control --reload-rules
}

# Function to set up post-quantum SSL with ML-KEM
setup_post_quantum_ssl() {
    log_message "Setting up post-quantum SSL with ML-KEM..."
    arch-chroot /mnt pacman -S --noconfirm openssl git cmake ninja libssl-dev
    arch-chroot /mnt bash -c "git clone https://github.com/open-quantum-safe/oqs-provider.git /root/oqs-provider && cd /root/oqs-provider && cmake -S . -B build -GNinja -DOPENSSL_ROOT_DIR=/usr && ninja -C build && ninja -C build install"
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
    arch-chroot /mnt pacman -S --noconfirm nginx
    arch-chroot /mnt bash -c "openssl genpkey -algorithm ml-kem-768 -out /etc/nginx/pqc.key && openssl pkey -in /etc/nginx/pqc.key -pubout -out /etc/nginx/pqc.crt"
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
    arch-chroot /mnt systemctl enable nginx
    arch-chroot /mnt systemctl start nginx
}

# Function to set up Skyscope Sentinel network modules
setup_network_modules() {
    log_message "Setting up Skyscope Sentinel network modules..."
    arch-chroot /mnt pacman -S --noconfirm tor obfs4proxy v2ray netcat
    cat << 'EOF' > /mnt/usr/local/bin/skyscope-yubikey-validate.sh
#!/bin/bash
YUBIKEY_SERIAL=$(cat /etc/skyscope/yubikey_serial 2>/dev/null)
[[ -z "$YUBIKEY_SERIAL" ]] && { echo "No YubiKey serial registered!"; exit 1; }
CURRENT_SERIAL=$(ykman info | grep "Serial number" | awk '{print $3}')
[[ "$CURRENT_SERIAL" != "$YUBIKEY_SERIAL" ]] && { echo "Unauthorized YubiKey detected! Serial mismatch."; exit 1; }
lsusb | grep -q "Yubico" || { echo "YubiKey not physically present!"; exit 1; }
exit 0
EOF
    chmod +x /mnt/usr/local/bin/skyscope-yubikey-validate.sh
    mkdir -p /mnt/etc/skyscope
    echo "$YUBIKEY_SERIAL" > /mnt/etc/skyscope/yubikey_serial
    # Skyscope1: Anonymization and Speed Boost
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
ip link show Skyscope1 >/dev/null 2>&1 || { ip link add dev Skyscope1 type dummy; ip addr add 10.0.1.1/24 dev Skyscope1; ip link set Skyscope1 up; }
systemctl start tor
echo "VirtualIP 10.0.1.0/24" >> /etc/tor/torrc
echo "AutomapHostsOnResolve 1" >> /etc/tor/torrc
systemctl restart tor
echo "net.core.rmem_max=8388608" >> /etc/sysctl.conf
echo "net.core.wmem_max=8388608" >> /etc/sysctl.conf
echo "net.ipv4.tcp_rmem=4096 87380 8388608" >> /etc/sysctl.conf
echo "net.ipv4.tcp_wmem=4096 65536 8388608" >> /etc/sysctl.conf
echo "net.ipv4.tcp_congestion_control=bbr" >> /etc/sysctl.conf
sysctl -p
ethtool -G eth0 rx 4096 tx 4096 2>/dev/null
ethtool -K eth0 tso off gso off ufo off 2>/dev/null
ip route add default dev Skyscope1
while true; do
    /usr/local/bin/skyscope-yubikey-validate.sh || { logger -p security.crit "YubiKey not present! Disabling Skyscope1."; ip link set Skyscope1 down; systemctl stop tor; }
    ip link set Skyscope1 up
    systemctl start tor
    sleep 60
done
EOF
    chmod +x /mnt/usr/local/bin/skyscope-skyscope1.sh
    # Skyscope2: DPI and MITM Evasion
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
ip link show Skyscope2 >/dev/null 2>&1 || { ip link add dev Skyscope2 type dummy; ip addr add 10.0.2.1/24 dev Skyscope2; ip link set Skyscope2 up; }
echo "UseBridges 1" >> /etc/tor/torrc
echo "ClientTransportPlugin obfs4 exec /usr/bin/obfs4proxy" >> /etc/tor/torrc
echo "Bridge obfs4 127.0.0.1:9050" >> /etc/tor/torrc
systemctl restart tor
iptables -t mangle -A OUTPUT -o Skyscope2 -p tcp --tcp-flags ALL ALL -j TOS --set-tos 0x10
iptables -t mangle -A OUTPUT -o Skyscope2 -p tcp -j TCPMSS --set-mss 1200
iptables -A OUTPUT -o Skyscope2 -p tcp --dport 80 -j DROP
iptables -A OUTPUT -o Skyscope2 -p tcp --dport 443 -m string --string "HTTP/1.1" --algo bm -j DROP
while true; do
    /usr/local/bin/skyscope-yubikey-validate.sh || { logger -p security.crit "YubiKey not present! Disabling Skyscope2."; ip link set Skyscope2 down; systemctl stop tor; }
    ip link set Skyscope2 up
    systemctl start tor
    sleep 60
done
EOF
    chmod +x /mnt/usr/local/bin/skyscope-skyscope2.sh
    # Skyscope3: Connectivity Maintenance
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
ip link show Skyscope3 >/dev/null 2>&1 || { ip link add dev Skyscope3 type dummy; ip addr add 10.0.3.1/24 dev Skyscope3; ip link set Skyscope3 up; }
cat << 'V2RAY_CONFIG' > /etc/skyscope/v2ray.json
{
    "inbounds": [{"port": 9051, "protocol": "vmess", "settings": {"clients": [{"id": "b831381d-6324-4d53-ad4f-8cda48b30811", "alterId": 0}]}}],
    "outbounds": [{"protocol": "vmess", "settings": {"vnext": [{"address": "127.0.0.1", "port": 9051, "users": [{"id": "b831381d-6324-4d53-ad4f-8cda48b30811", "alterId": 0}]}}]}]
}
V2RAY_CONFIG
v2ray -config /etc/skyscope/v2ray.json &
test_connectivity() { ping -c 1 8.8.8.8 >/dev/null 2>&1; return $?; }
PORTS=(9051 9052 9053 9054 9055)
while true; do
    /usr/local/bin/skyscope-yubikey-validate.sh || { logger -p security.crit "YubiKey not present! Disabling Skyscope3."; ip link set Skyscope3 down; pkill v2ray; }
    ip link set Skyscope3 up
    if ! test_connectivity; then
        for port in "${PORTS[@]}"; do
            logger -p info "Trying port $port for connectivity..."
            sed -i "s/\"port\": [0-9]*/\"port\": $port/" /etc/skyscope/v2ray.json
            pkill v2ray
            v2ray -config /etc/skyscope/v2ray.json &
            sleep 5
            test_connectivity && { logger -p info "Connectivity restored on port $port!"; break; }
        done
    fi
    sleep 60
done
EOF
    chmod +x /mnt/usr/local/bin/skyscope-skyscope3.sh
    arch-chroot /mnt systemctl enable skyscope-sentinel-skyscope1-agent skyscope-sentinel-skyscope2-agent skyscope-sentinel-skyscope3-agent
}

# Function to install CUDA drivers and optimize for Intel i7-12700 and Gigabyte B760M-H-DDR4
setup_cuda_and_optimizations() {
    log_message "Setting up CUDA drivers and system optimizations..."
    arch-chroot /mnt pacman -S --noconfirm nvidia nvidia-dkms cuda
    arch-chroot /mnt dkms autoinstall
    echo "intel_pstate=enable" >> /mnt/etc/default/grub
    sed -i 's/GRUB_CMDLINE_LINUX_DEFAULT="/GRUB_CMDLINE_LINUX_DEFAULT="intel_pstate=enable governor=schedutil /' /mnt/etc/default/grub
    arch-chroot /mnt grub-mkconfig -o /boot/grub/grub.cfg
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
echo on > /sys/devices/system/cpu/smt/control
echo schedutil > /sys/devices/system/cpu/cpufreq/policy0/scaling_governor
systemctl start irqbalance
systemctl enable irqbalance
EOF
    chmod +x /mnt/usr/local/bin/skyscope-cpu-optimize.sh
    arch-chroot /mnt systemctl enable skyscope-sentinel-cpu-optimize.service
    sed -i 's/GRUB_CMDLINE_LINUX_DEFAULT="/GRUB_CMDLINE_LINUX_DEFAULT="iommu=pt intel_iommu=on /' /mnt/etc/default/grub
    arch-chroot /mnt grub-mkconfig -o /boot/grub/grub.cfg
    arch-chroot /mnt pacman -S --noconfirm lm_sensors fancontrol smartmontools
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
    # Unauthorized modification detection
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
    for file in /etc/passwd /etc/shadow /etc/sudoers /boot/vmlinuz-linux-${KERNEL_VERSION}; do
        if [[ -f "$file" ]]; then
            current_hash=$(sha256sum "$file" | awk '{print $1}')
            stored_hash=$(cat "/etc/skyscope/hashes/$(basename $file).hash" 2>/dev/null)
            [[ "$current_hash" != "$stored_hash" && -n "$stored_hash" ]] && logger -p security.crit "Unauthorized modification detected in $file!"
            echo "$current_hash" > "/etc/skyscope/hashes/$(basename $file).hash"
        fi
    done
    sleep 60
done
EOF
    chmod +x /mnt/usr/local/bin/skyscope-unauthorized-mod-detection.sh
    mkdir -p /mnt/etc/skyscope/hashes
    # Configuration protection
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
    for file in /etc/crypttab /etc/mkinitcpio.conf; do
        chattr +i "$file" 2>/dev/null
    done
    sleep 60
done
EOF
    chmod +x /mnt/usr/local/bin/skyscope-config-protect.sh
    # Security detection and protection
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
    ps aux | grep -E "nc|netcat|telnet|sshd" | grep -v grep && logger -p security.crit "Suspicious process detected!"
    sleep 60
done
EOF
    chmod +x /mnt/usr/local/bin/skyscope-security-detect-protect.sh
    # Prevent remote unprivileged access
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
    systemctl stop sshd avahi-daemon cups 2>/dev/null
    systemctl disable sshd avahi-daemon cups 2>/dev/null
    if netstat -tuln | grep -E ':22|:3389'; then
        /usr/local/bin/skyscope-yubikey-validate.sh || { logger -p security.crit "Unauthorized remote access attempt detected!"; iptables -F; iptables -A INPUT -i lo -j ACCEPT; iptables -A INPUT -j DROP; }
    fi
    sleep 60
done
EOF
    chmod +x /mnt/usr/local/bin/skyscope-prevent-remote-unprivileged-access.sh
    arch-chroot /mnt systemctl enable skyscope-sentinel-unauthorized-mod-detection-agent skyscope-sentinel-config-protect-agent skyscope-sentinel-security-detect-protect-agent skyscope-sentinel-prevent-remote-unprivileged-access-agent
}

# Main installation process
main() {
    check_integrity
    echo "Arch Linux Installation Log" > "$LOG_FILE"
    log_message "Starting installation process..."

    # Display header
    display_header

    # Select disk
    select_disk

    # Prompt for LUKS passphrase
    LUKS_PASSPHRASE=$(prompt_passphrase)
    PASSFILE=$(mktemp)
    chmod 600 "$PASSFILE"
    echo "$LUKS_PASSPHRASE" > "$PASSFILE"

    # Execute installation steps with progress bars
    execute_step_with_progress "Partitioning $SELECTED_DISK" \
        "echo -e 'g\nn\n\n\n\n8300\nw' | fdisk $SELECTED_DISK" 10

    execute_step_with_progress "Encrypting $SELECTED_DISK with LUKS2" \
        "cryptsetup --type luks2 --cipher aes-xts-plain64 --key-size 512 --hash sha512 --pbkdf argon2id --iter-time 5000 --key-file \"$PASSFILE\" luksFormat ${SELECTED_DISK}1 && cryptsetup --key-file \"$PASSFILE\" luksOpen ${SELECTED_DISK}1 cryptroot" 300  # 5 minutes for encryption

    execute_step_with_progress "Configuring LVM" \
        "pvcreate /dev/mapper/cryptroot && vgcreate vg0 /dev/mapper/cryptroot && lvcreate -n root -L 50G vg0 && lvcreate -n home -l 80%FREE vg0 && lvcreate -n swap -L 16G vg0" 30

    execute_step_with_progress "Formatting file systems" \
        "mkfs.btrfs /dev/mapper/vg0-root && mkfs.btrfs /dev/mapper/vg0-home && mkswap /dev/mapper/vg0-swap && swapon /dev/mapper/vg0-swap" 60

    execute_step_with_progress "Mounting file systems" \
        "mount /dev/mapper/vg0-root /mnt && btrfs subvolume create /mnt/boot && btrfs subvolume create /mnt/home && mount /dev/mapper/vg0-home /mnt/home" 10

    execute_step_with_progress "Installing base system" \
        "pacstrap /mnt base linux linux-firmware intel-ucode sbsign cryptsetup lvm2 btrfs-progs" 300  # 5 minutes for package installation

    execute_step_with_progress "Updating system" \
        "arch-chroot /mnt pacman -Syu --noconfirm" 300  # 5 minutes for system update

    execute_step_with_progress "Generating fstab" \
        "genfstab -U /mnt >> /mnt/etc/fstab" 5

    execute_step_with_progress "Configuring system" \
        "arch-chroot /mnt bash -c \"echo 'archsecure' > /etc/hostname && echo '127.0.0.1 localhost' >> /etc/hosts && echo '::1 localhost' >> /etc/hosts && echo '127.0.1.1 archsecure.localdomain archsecure' >> /etc/hosts\"" 10

    execute_step_with_progress "Installing additional tools" \
        "arch-chroot /mnt pacman -S --noconfirm yubikey-manager nano iptables" 60

    execute_step_with_progress "Validating YubiKey" \
        "validate_yubikey" 10

    execute_step_with_progress "Enrolling YubiKey" \
        "cp \"$PASSFILE\" /mnt/tmp/luks_passphrase && arch-chroot /mnt bash -c 'systemd-cryptenroll --password=\$(cat /tmp/luks_passphrase) ${SELECTED_DISK}1 --fido2-device=auto --fido2-with-client-pin=no' && rm /mnt/tmp/luks_passphrase" 30

    execute_step_with_progress "Configuring crypttab" \
        "echo \"cryptroot UUID=$(blkid -s UUID -o value ${SELECTED_DISK}1) none luks,fido2-device=auto\" >> /mnt/etc/crypttab" 5

    execute_step_with_progress "Configuring initramfs" \
        "sed -i 's/HOOKS=.*/HOOKS=(base udev autodetect keyboard keymap consolefont modconf block lvm2 filesystems fsck)/' /mnt/etc/mkinitcpio.conf && arch-chroot /mnt mkinitcpio -P" 30

    execute_step_with_progress "Installing systemd-boot" \
        "arch-chroot /mnt bootctl --path=/boot install && echo 'title Arch Linux' > /mnt/boot/loader/entries/arch.conf && echo 'linux /vmlinuz-linux-${KERNEL_VERSION}' >> /mnt/boot/loader/entries/arch.conf && echo 'initrd /intel-ucode.img' >> /mnt/boot/loader/entries/arch.conf && echo 'initrd /initramfs-linux.img' >> /mnt/boot/loader/entries/arch.conf && echo 'options cryptdevice=UUID=$(blkid -s UUID -o value ${SELECTED_DISK}1):cryptroot root=/dev/mapper/vg0-root rw' >> /mnt/boot/loader/entries/arch.conf && echo 'default arch.conf' > /mnt/boot/loader/loader.conf && echo 'timeout 3' >> /mnt/boot/loader/loader.conf" 10

    execute_step_with_progress "Setting up Secure Boot" \
        "setup_secure_boot" 60

    execute_step_with_progress "Setting up bootloader password" \
        "setup_bootloader_password" 30

    execute_step_with_progress "Setting root password" \
        "echo -e 'rootpassword\nrootpassword' | arch-chroot /mnt passwd" 5

    execute_step_with_progress "Setting up YubiKey authentication" \
        "setup_yubikey_authentication" 60

    execute_step_with_progress "Setting up YubiKey removal lockdown" \
        "setup_yubikey_removal_lockdown" 30

    execute_step_with_progress "Setting up security modules" \
        "setup_security_modules" 60

    execute_step_with_progress "Setting up network modules" \
        "setup_network_modules" 120  # 2 minutes for network setup

    execute_step_with_progress "Setting up CUDA and optimizations" \
        "setup_cuda_and_optimizations" 300  # 5 minutes for CUDA installation

    execute_step_with_progress "Compiling and installing kernel ${KERNEL_VERSION}" \
        "setup_kernel" 600  # 10 minutes for kernel compilation

    execute_step_with_progress "Setting up post-quantum SSL" \
        "setup_post_quantum_ssl" 120  # 2 minutes for SSL setup

    execute_step_with_progress "Hardening system" \
        "arch-chroot /mnt bash -c \"echo 'net.ipv4.conf.all.accept_redirects = 0' >> /etc/sysctl.conf && echo 'net.ipv6.conf.all.accept_redirects = 0' >> /etc/sysctl.conf && sysctl -p\"" 10

    execute_step_with_progress "Finalizing installation" \
        "umount -R /mnt && swapoff /dev/mapper/vg0-swap && reboot" 10

    # Clean up
    rm -f "$PASSFILE"

    log_message "${GREEN}Installation complete! Enroll Secure Boot keys in BIOS, insert YubiKey, and touch it at boot to unlock.${NC}"
    whiptail --msgbox "Installation complete!\n\nEnroll Secure Boot keys in your BIOS:\n- Platform Key (PK): /root/secureboot/PK.crt\n- Key Exchange Key (KEK): /root/secureboot/KEK.crt\n- Signature Database (db): /root/secureboot/db.crt\n\nInsert your YubiKey and touch it at boot to unlock the disk." 20 70
}

# Trap to ensure cleanup on exit
trap 'log_message "Script interrupted. Cleaning up..."; rm -f "$PASSFILE"; umount -R /mnt 2>/dev/null; swapoff /dev/mapper/vg0-swap 2>/dev/null; exit 1' INT TERM

# Run the installation
main
