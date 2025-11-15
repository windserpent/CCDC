#!/bin/bash

# Critical Security Updates Script for Fedora 42
# This script applies only the most critical security updates to minimize risk and bandwidth

# Valid switchs are:
# ./critical_updates_f42.sh preview
# ./critical_updates_f42.sh install

set -euo pipefail

# Configuration
LOG_FILE="/var/log/critical_security_updates_f42.log"
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
    if ! grep -q "Fedora.*release 42" /etc/fedora-release 2>/dev/null; then
        error_exit "This script is designed for Fedora 42"
    fi
    log "System check passed: $(cat /etc/fedora-release)"
}

# Define critical packages patterns for Fedora
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
# Container security (Fedora-specific)
podman*
buildah*
skopeo*
runc*
crun*
# Fedora-specific critical packages
dnf*
rpm*
selinux-policy*
firefox*
# Graphics and drivers (common attack vectors)
mesa*
xorg-x11*
wayland*
EOF
}

# Get list of available critical security updates
get_critical_security_updates() {
    log "Checking for critical security updates..."
    
    # Get all security advisories
    dnf updateinfo list security 2>/dev/null | grep -E "(Critical|Important)" | while read -r line; do
        # Parse Fedora advisory format: FEDORA-YYYY-xxxxxx
        advisory=$(echo "$line" | awk '{print $1}')
        severity=$(echo "$line" | awk '{print $2}')
        package=$(echo "$line" | awk '{print $3}')
        
        # Filter for critical packages - expanded for Fedora
        if echo "$package" | grep -qE "^(kernel|sudo|glibc|openssl|systemd|openssh|pam|polkit|bind|unbound|podman|buildah|skopeo|runc|crun|dnf|rpm|selinux-policy|firefox|mesa|xorg-x11|wayland)"; then
            echo "$advisory $severity $package"
        fi
    done
}

# Check for specific CVE-based updates (Fedora often references CVEs directly)
get_high_impact_cves() {
    log "Checking for high-impact CVE updates..."
    
    # Look for specific high-impact CVE patterns
    dnf updateinfo list security 2>/dev/null | grep -iE "(CVE-[0-9]{4}-[0-9]{4,})" | \
    grep -E "(Critical|Important)" | while read -r line; do
        advisory=$(echo "$line" | awk '{print $1}')
        severity=$(echo "$line" | awk '{print $2}')
        package=$(echo "$line" | awk '{print $3}')
        
        # Extract CVE if present in advisory name
        cve=$(echo "$advisory" | grep -oE "CVE-[0-9]{4}-[0-9]{4,}" || echo "")
        
        echo "$advisory $severity $package $cve"
    done
}

# Preview critical updates
preview_updates() {
    echo -e "${BLUE}=== FEDORA 42 CRITICAL SECURITY UPDATES PREVIEW ===${NC}"
    log "Starting preview of critical security updates"
    
    local critical_updates cve_updates
    critical_updates=$(get_critical_security_updates)
    cve_updates=$(get_high_impact_cves)
    
    if [[ -z "$critical_updates" ]] && [[ -z "$cve_updates" ]]; then
        echo -e "${GREEN}No critical security updates available${NC}"
        log "No critical security updates found"
        return 0
    fi
    
    # Display critical package updates
    if [[ -n "$critical_updates" ]]; then
        echo -e "${YELLOW}Critical security updates for essential packages:${NC}"
        echo "$critical_updates" | while read -r advisory severity package; do
            echo -e "  ${RED}$severity${NC}: $package ($advisory)"
        done
        echo
    fi
    
    # Display high-impact CVE updates
    if [[ -n "$cve_updates" ]]; then
        echo -e "${YELLOW}High-impact CVE security updates:${NC}"
        echo "$cve_updates" | while read -r advisory severity package cve; do
            if [[ -n "$cve" ]]; then
                echo -e "  ${RED}$severity${NC}: $package ($advisory - $cve)"
            else
                echo -e "  ${RED}$severity${NC}: $package ($advisory)"
            fi
        done
        echo
    fi
    
    # Estimate download size
    echo -e "${BLUE}Estimating download size...${NC}"
    local packages_list
    packages_list=$(
        {
            echo "$critical_updates" | awk '{print $3}'
            echo "$cve_updates" | awk '{print $3}'
        } | sort -u
    )
    
    if [[ -n "$packages_list" ]]; then
        # Use dnf to check download size
        echo "$packages_list" | xargs dnf update --downloadonly --assumeno 2>&1 | \
            grep -E "(Total download size|Install size|Nothing to do)" || true
    fi
    
    echo -e "\n${YELLOW}Next step:${NC}"
    echo "  Run with 'install' to download and install: $0 install"
    echo -e "${BLUE}Info:${NC}"
    echo "  Fedora updates are frequent - consider scheduling regular runs"
    echo "  Check release notes: https://docs.fedoraproject.org/en-US/fedora/f42/release-notes/"
}

# Install critical updates
install_updates() {
    echo -e "${BLUE}=== INSTALLING FEDORA 42 CRITICAL SECURITY UPDATES ===${NC}"
    log "Starting installation of critical security updates"
    
    local critical_updates cve_updates
    critical_updates=$(get_critical_security_updates)
    cve_updates=$(get_high_impact_cves)
    
    if [[ -z "$critical_updates" ]] && [[ -z "$cve_updates" ]]; then
        echo -e "${GREEN}No critical security updates to install${NC}"
        return 0
    fi
    
    # Create system backup info
    echo -e "${YELLOW}Creating backup information...${NC}"
    rpm -qa > "/tmp/rpm_backup_f42_$(date +%Y%m%d_%H%M%S).txt"
    uname -r > "/tmp/kernel_backup_f42_$(date +%Y%m%d_%H%M%S).txt"
    
    # Get unique package list
    local packages_list
    packages_list=$(
        {
            echo "$critical_updates" | awk '{print $3}'
            echo "$cve_updates" | awk '{print $3}'
        } | sort -u
    )
    
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
    
    # Check for systemd updates (may require service restarts)
    if echo "$packages_list" | grep -q "systemd"; then
        echo -e "${YELLOW}SystemD updated - consider restarting services or rebooting${NC}"
        log "SystemD updated - services may need restart"
    fi
    
    # Check for container runtime updates
    if echo "$packages_list" | grep -qE "(podman|buildah|skopeo|runc|crun)"; then
        echo -e "${YELLOW}Container runtimes updated - restart container services${NC}"
        log "Container runtimes updated"
    fi
    
    log "Critical security updates installation completed"
    echo -e "${GREEN}Critical security updates installed successfully${NC}"
}

# Check for available Fedora version upgrades
check_version_upgrade() {
    local current_version
    current_version=$(grep -oE "release [0-9]+" /etc/fedora-release | awk '{print $2}')
    
    if [[ "$current_version" -lt 42 ]]; then
        echo -e "${YELLOW}Note: Fedora $current_version detected. Consider upgrading to Fedora 42${NC}"
        echo "  Use: dnf system-upgrade download --releasever=42"
    fi
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
    echo -e "${BLUE}Fedora 42 Critical Security Updates${NC}"
    echo "=================================="
    
    check_root
    check_system
    check_version_upgrade
    
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
            echo ""
            echo "Environment variables:"
            echo "  CLEAN_CACHE=yes  - Clean dnf cache after operation"
            exit 1
            ;;
    esac
    
    cleanup
}

# Trap for cleanup
trap cleanup EXIT

# Run main function
main