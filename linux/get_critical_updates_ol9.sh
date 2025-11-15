#!/bin/bash

# Critical Security Updates Script for Oracle Linux 9.2
# This script applies only the most critical security updates to minimize risk and bandwidth

# Valid switchs are:
# ./critical_updates_ol9.sh preview
# ./critical_updates_ol9.sh install

set -euo pipefail

# Configuration
LOG_FILE="/var/log/critical_security_updates.log"
DRY_RUN=${1:-"preview"}  # preview, install
DOWNLOAD_CACHE="/var/cache/dnf"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging function
log() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') - $1" | tee -a "$LOG_FILE"
}

# Error handling
error_exit() {
    echo -e "${RED}ERROR: $1${NC}" >&2
    log "ERROR: $1"
    exit 1
}

# Check if running as root
check_root() {
    if [[ $EUID -ne 0 ]]; then
        error_exit "This script must be run as root"
    fi
}

# Check system version
check_system() {
    if ! grep -q "Oracle Linux.*release 9" /etc/oracle-release 2>/dev/null; then
        if ! grep -q "Oracle Linux.*release 9" /etc/redhat-release 2>/dev/null; then
            error_exit "This script is designed for Oracle Linux 9.x"
        fi
    fi
    log "System check passed: $(cat /etc/oracle-release 2>/dev/null || cat /etc/redhat-release)"
}

# Define critical packages patterns
get_critical_packages() {
    cat << 'EOF'
# Critical security packages (high priority)
kernel*
sudo*
glibc*
openssl*
systemd*
openssh*
# Authentication and privilege escalation fixes
pam*
polkit*
# Network security
bind*
unbound*
# Container security (if applicable)
podman*
runc*
EOF
}

# Get list of available critical security updates
get_critical_security_updates() {
    log "Checking for critical security updates..."
    
    # Get all security advisories
    dnf updateinfo list security 2>/dev/null | grep -E "(Critical|Important)" | while read -r line; do
        advisory=$(echo "$line" | awk '{print $1}')
        severity=$(echo "$line" | awk '{print $2}')
        package=$(echo "$line" | awk '{print $3}')
        
        # Filter for critical packages
        if echo "$package" | grep -qE "^(kernel|sudo|glibc|openssl|systemd|openssh|pam|polkit|bind|unbound|podman|runc)"; then
            echo "$advisory $severity $package"
        fi
    done
}

# Preview critical updates
preview_updates() {
    echo -e "${BLUE}=== CRITICAL SECURITY UPDATES PREVIEW ===${NC}"
    log "Starting preview of critical security updates"
    
    local critical_updates
    critical_updates=$(get_critical_security_updates)
    
    if [[ -z "$critical_updates" ]]; then
        echo -e "${GREEN}No critical security updates available${NC}"
        log "No critical security updates found"
        return 0
    fi
    
    echo -e "${YELLOW}Critical security updates available:${NC}"
    echo "$critical_updates" | while read -r advisory severity package; do
        echo -e "  ${RED}$severity${NC}: $package ($advisory)"
    done
    
    # Estimate download size
    echo -e "\n${BLUE}Estimating download size...${NC}"
    local packages_list
    packages_list=$(echo "$critical_updates" | awk '{print $3}' | sort -u)
    
    if [[ -n "$packages_list" ]]; then
        # Use dnf to check download size
        echo "$packages_list" | xargs dnf update --downloadonly --assumeno 2>&1 | \
            grep -E "(Total download size|Nothing to do)" || true
    fi
    
    echo -e "\n${YELLOW}Next step:${NC}"
    echo "  Run with 'install' to download and install: $0 install"
}

# Install critical updates
install_updates() {
    echo -e "${BLUE}=== INSTALLING CRITICAL SECURITY UPDATES ===${NC}"
    log "Starting installation of critical security updates"
    
    local critical_updates
    critical_updates=$(get_critical_security_updates)
    
    if [[ -z "$critical_updates" ]]; then
        echo -e "${GREEN}No critical security updates to install${NC}"
        return 0
    fi
    
    # Create system backup info
    echo -e "${YELLOW}Creating backup information...${NC}"
    rpm -qa > "/tmp/rpm_backup_$(date +%Y%m%d_%H%M%S).txt"
    uname -r > "/tmp/kernel_backup_$(date +%Y%m%d_%H%M%S).txt"
    
    local packages_list
    packages_list=$(echo "$critical_updates" | awk '{print $3}' | sort -u)
    
    # Install packages
    echo -e "${YELLOW}Installing critical security updates...${NC}"
    echo "$packages_list" | xargs dnf update --assumeyes
    
    # Check if kernel was updated
    if echo "$packages_list" | grep -q "kernel"; then
        echo -e "${RED}KERNEL UPDATED - REBOOT REQUIRED${NC}"
        log "Kernel updated - system reboot required"
        echo -e "${YELLOW}Please reboot the system to use the new kernel${NC}"
        echo "Current kernel: $(uname -r)"
        echo "New kernel(s) installed:"
        rpm -qa kernel* | grep -v "$(uname -r)" | sort
    fi
    
    log "Critical security updates installation completed"
    echo -e "${GREEN}Critical security updates installed successfully${NC}"
}

# Cleanup function
cleanup() {
    # Clean dnf cache if requested
    if [[ "${CLEAN_CACHE:-}" == "yes" ]]; then
        dnf clean all
    fi
}

# Main function
main() {
    echo -e "${BLUE}Oracle Linux 9.2 Critical Security Updates${NC}"
    echo "=========================================="
    
    check_root
    check_system
    
    case "${DRY_RUN}" in
        "preview"|"")
            preview_updates
            ;;
        "install")
            install_updates
            ;;
        *)
            echo "Usage: $0 [preview|install]"
            echo "  preview  - Show what updates are available (default)"
            echo "  install  - Download and install critical updates"
            exit 1
            ;;
    esac
    
    cleanup
}

# Trap for cleanup
trap cleanup EXIT

# Run main function
main