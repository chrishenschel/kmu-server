#!/bin/bash

# ==============================================================================
# KMU Server Setup Script
# ==============================================================================
# Description: Professional, idempotent setup script for Ubuntu/Debian servers.
# Features: Docker, Security Hardening (UFW), System Updates, Git.
# ==============================================================================

set -eou pipefail

# --- Configuration ---
SUDO_USER="${SUDO_USER:-$(whoami)}"
LOG_FILE="/var/log/server_setup.log"

# --- Formatting ---
GREEN='\033[0;32m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

log() {
    echo -e "${BLUE}[INFO]${NC} $1" | tee -a "$LOG_FILE"
}

success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1" | tee -a "$LOG_FILE"
}

error() {
    echo -e "\033[0;31m[ERROR]\033[0m $1" | tee -a "$LOG_FILE" >&2
}

# --- Pre-checks ---
if [[ $EUID -ne 0 ]]; then
   error "This script must be run as root (use sudo)"
   exit 1
fi

log "Starting server setup process..."

# --- Update System ---
log "Updating package lists and upgrading system..."
apt update && apt upgrade -y

# --- Install Essentials ---
log "Installing essential packages..."
apt install -y ca-certificates curl git ufw software-properties-common yq

# --- Install Docker (Idempotent) ---
if ! command -v docker &> /dev/null; then
    log "Docker not found. Installing Docker..."
    
    # Remove old versions if they exist
    apt remove -y docker.io docker-compose docker-compose-v2 docker-doc podman-docker containerd runc || true

    # Add Docker's official GPG key
    install -m 0755 -d /etc/apt/keyrings
    curl -fsSL https://download.docker.com/linux/ubuntu/gpg -o /etc/apt/keyrings/docker.asc
    chmod a+r /etc/apt/keyrings/docker.asc

    # Add the repository to Apt sources
    tee /etc/apt/sources.list.d/docker.sources <<EOF
Types: deb
URIs: https://download.docker.com/linux/ubuntu
Suites: $(. /etc/os-release && echo "${UBUNTU_CODENAME:-$VERSION_CODENAME}")
Components: stable
Signed-By: /etc/apt/keyrings/docker.asc
EOF

    apt update
    apt install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
    
    # Add current sudo user to docker group
    usermod -aG docker "$SUDO_USER"
    success "Docker installed successfully."
else
    log "Docker is already installed. Skipping installation."
fi

# --- Security: UFW (Uncomplicated Firewall) ---
log "Configuring Firewall (UFW)..."
ufw allow OpenSSH
ufw allow 80/tcp
ufw allow 443/tcp
# Enable UFW (implicitly handles existing connections so we don't lock ourselves out)
echo "y" | ufw enable
success "Firewall configured: SSH, HTTP, and HTTPS allowed."

# --- Security: SSH Hardening (Optional but recommended) ---
# Note: These are commented out as they require manual confirmation to avoid lockouts.
# sed -i 's/PermitRootLogin yes/PermitRootLogin no/' /etc/ssh/sshd_config
# sed -i 's/#PasswordAuthentication yes/PasswordAuthentication no/' /etc/ssh/sshd_config
# systemctl restart ssh


success "Server setup completed successfully!"
log "Please log out and log back in for docker group changes to take effect."