#!/bin/bash

# Splunk Security Hardening Script
# Addresses critical security vulnerabilities identified in security assessment
# Designed for blue team exercise environments
#
# Usage: ./splunk_security_hardening.sh [OPERATION]
#
# Operations:
#   check           - Assess current security configuration (default)
#   backup          - Create backup of configuration files only
#   apply-critical  - Fix critical security issues only (default key, SSL password, HTTPS, Python SSL)
#   apply-all       - Apply all security hardening measures
#   verify          - Verify security hardening was successful
#   rollback        - Restore configuration from backup
#   --help          - Display this help message
#
# Examples:
#   ./splunk_security_hardening.sh check
#   ./splunk_security_hardening.sh backup
#   ./splunk_security_hardening.sh apply-critical
#   ./splunk_security_hardening.sh apply-all
#   ./splunk_security_hardening.sh verify
#   ./splunk_security_hardening.sh rollback /tmp/splunk_config_backup_20251115_143022

set -euo pipefail

# ============================================================================
# CONFIGURATION VARIABLES
# ============================================================================

# Network Configuration
SPLUNK_SERVER_IP="172.16.101.10"
SPLUNK_DOMAIN="ccdcteam.com"
SPLUNK_HOSTNAME="splunk"

# Firewall Access Control - Networks allowed to access Splunk
ALLOWED_NETWORKS=(
    "172.16.101.0/24"    # Local subnet
#    "172.16.0.0/12"      # Private network range
)

# System Configuration
SPLUNK_HOME="/opt/splunk"
SPLUNK_USER="splunk"
SPLUNK_GROUP="splunk"
LOG_FILE="/var/log/splunk_security_hardening.log"
COMPLIANCE_REPORT="/var/log/splunk_security_compliance_report.log"
BACKUP_BASE_DIR="/opt/splunk/backups"
BACKUP_DIR="$BACKUP_BASE_DIR/config_backup_$(date +%Y%m%d_%H%M%S)"
OPERATION=${1:-"check"}

# Certificate Subject Details
CERT_COUNTRY="US"
CERT_STATE="MN"
CERT_ORGANIZATION="Acme"
CERT_ORG_UNIT="Security Team"

# ============================================================================
# GLOBAL VARIABLES
# ============================================================================

# Colors for output (no emoji/unicode)
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Security assessment tracking
CRITICAL_ISSUES_FOUND=0
HIGH_ISSUES_FOUND=0
MEDIUM_ISSUES_FOUND=0
ISSUES_FIXED=0
BACKUP_CREATED=false
ROLLBACK_AVAILABLE=false

# ============================================================================
# LOGGING AND OUTPUT FUNCTIONS
# ============================================================================

# Initialize log files
init_logging() {
    touch "$LOG_FILE"
    touch "$COMPLIANCE_REPORT"
    chmod 640 "$LOG_FILE" "$COMPLIANCE_REPORT"
    
    # Log script start
    log "=== Splunk Security Hardening Script Started ==="
    log "Operation: $OPERATION"
    log "Timestamp: $(date)"
    log "User: $(whoami)"
}

# Logging function
log() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') - $1" | tee -a "$LOG_FILE"
}

# Error handling with automatic rollback
error_exit() {
    echo -e "${RED}ERROR: $1${NC}" >&2
    log "ERROR: $1"
    
    # Trigger rollback if backup exists and we made changes
    if [[ "$BACKUP_CREATED" == true ]] && [[ "$ISSUES_FIXED" -gt 0 ]]; then
        warning "Attempting automatic rollback due to error..."
        restore_from_backup "$BACKUP_DIR" || true
    fi
    
    generate_compliance_report "FAILED"
    exit 1
}

# Success message
success() {
    echo -e "${GREEN}SUCCESS: $1${NC}"
    log "SUCCESS: $1"
}

# Warning message  
warning() {
    echo -e "${YELLOW}WARNING: $1${NC}"
    log "WARNING: $1"
}

# Info message
info() {
    echo -e "${CYAN}INFO: $1${NC}"
    log "INFO: $1"
}

# Cleanup function
cleanup() {
    local exit_code=$?
    
    if [[ $exit_code -ne 0 ]] && [[ "$OPERATION" != "check" ]] && [[ "$OPERATION" != "verify" ]]; then
        log "Script exited with error code $exit_code"
        generate_compliance_report "FAILED"
    fi
}

# Set trap for cleanup
trap cleanup EXIT

# ============================================================================
# VALIDATION FUNCTIONS
# ============================================================================

# Check if running as root
check_root() {
    if [[ $EUID -ne 0 ]]; then
        error_exit "This script must be run as root"
    fi
}

# Check if Splunk is installed
check_splunk_installed() {
    if [[ ! -d "$SPLUNK_HOME" ]]; then
        error_exit "Splunk not found at $SPLUNK_HOME"
    fi
    
    if [[ ! -f "$SPLUNK_HOME/bin/splunk" ]]; then
        error_exit "Splunk binary not found at $SPLUNK_HOME/bin/splunk"
    fi
    
    success "Splunk installation verified at $SPLUNK_HOME"
}

# Check Splunk status
check_splunk_status() {
    local status
    if systemctl is-active --quiet splunk 2>/dev/null; then
        status="running"
    elif pgrep -f splunkd >/dev/null; then
        status="running"
    else
        status="stopped"
    fi
    
    info "Splunk service status: $status"
    echo "$status"
}

# Validate Splunk configuration syntax
validate_splunk_config() {
    local config_dir="$1"
    
    info "Validating Splunk configuration syntax..."
    
    # Test configuration using Splunk's built-in validation
    if sudo -u "$SPLUNK_USER" "$SPLUNK_HOME/bin/splunk" btool check --dir="$config_dir" >/dev/null 2>&1; then
        success "Configuration syntax validation passed"
        return 0
    else
        error_exit "Configuration syntax validation failed - check $LOG_FILE for details"
        return 1
    fi
}

# Check if SELinux is enabled
check_selinux() {
    if command -v sestatus >/dev/null 2>&1; then
        local selinux_status=$(sestatus 2>/dev/null | grep "SELinux status:" | awk '{print $3}')
        if [[ "$selinux_status" == "enabled" ]]; then
            return 0
        fi
    fi
    return 1
}

# ============================================================================
# UTILITY FUNCTIONS
# ============================================================================

# Generate secure random string
generate_secure_key() {
    local length=$1
    openssl rand -base64 $((length * 3 / 4)) | tr -d '\n' | head -c "$length"
}

# Generate secure password
generate_secure_password() {
    local length=${1:-32}
    openssl rand -base64 $((length * 3 / 4)) | tr -d '\n' | head -c "$length"
}

# Create directory with proper ownership
create_splunk_directory() {
    local dir_path="$1"
    local permissions=${2:-755}
    
    mkdir -p "$dir_path"
    chown "$SPLUNK_USER:$SPLUNK_GROUP" "$dir_path"
    chmod "$permissions" "$dir_path"
    
    log "Created directory: $dir_path (permissions: $permissions)"
}

# Set file ownership and permissions
set_splunk_file_permissions() {
    local file_path="$1"
    local permissions=${2:-640}
    
    if [[ -f "$file_path" ]]; then
        chown "$SPLUNK_USER:$SPLUNK_GROUP" "$file_path"
        chmod "$permissions" "$file_path"
        log "Set permissions on $file_path ($permissions)"
    fi
}

# ============================================================================
# BACKUP AND RESTORE FUNCTIONS
# ============================================================================

# Create backup of configuration files
create_backup() {
    info "Creating backup of Splunk configuration files to: $BACKUP_DIR"
    
    # Create backup directory structure with proper permissions
    create_splunk_directory "$BACKUP_BASE_DIR" 700
    mkdir -p "$BACKUP_DIR"
    chown "$SPLUNK_USER:$SPLUNK_GROUP" "$BACKUP_DIR"
    chmod 700 "$BACKUP_DIR"
    
    local config_files=(
        "etc/system/local/server.conf"
        "etc/system/local/web.conf" 
        "etc/system/local/authorize.conf"
        "etc/splunk-launch.conf"
        "etc/auth/server.pem"
        "etc/auth/cacert.pem"
        "var/lib/splunk/kvstore/mongo/splunk.key"
    )
    
    for config_file in "${config_files[@]}"; do
        local full_path="$SPLUNK_HOME/$config_file"
        if [[ -f "$full_path" ]]; then
            local backup_path="$BACKUP_DIR/$(dirname "$config_file")"
            mkdir -p "$backup_path"
            cp "$full_path" "$backup_path/"
            log "Backed up: $config_file"
        else
            log "Config file not found (will be created): $full_path"
        fi
    done
    
    # Create restoration script
    create_restore_script "$BACKUP_DIR"
    
    BACKUP_CREATED=true
    ROLLBACK_AVAILABLE=true
    success "Backup created at: $BACKUP_DIR"
    info "Restoration script: $BACKUP_DIR/restore.sh"
}

# Create restoration script
create_restore_script() {
    local backup_dir="$1"
    
    cat > "$backup_dir/restore.sh" << EOF
#!/bin/bash
# Splunk Configuration Restoration Script
# Created: $(date)

SPLUNK_HOME="$SPLUNK_HOME"
BACKUP_DIR="$backup_dir"

echo "Stopping Splunk services..."
systemctl stop splunk 2>/dev/null || "$SPLUNK_HOME/bin/splunk" stop

echo "Restoring configuration files..."
EOF

    local config_files=(
        "etc/system/local/server.conf"
        "etc/system/local/web.conf" 
        "etc/system/local/authorize.conf"
        "etc/splunk-launch.conf"
        "etc/auth/server.pem"
        "etc/auth/cacert.pem"
        "var/lib/splunk/kvstore/mongo/splunk.key"
    )

    for config_file in "${config_files[@]}"; do
        local backup_file="$backup_dir/$config_file"
        if [[ -f "$backup_file" ]]; then
            echo "cp \"$backup_file\" \"$SPLUNK_HOME/$config_file\"" >> "$backup_dir/restore.sh"
        fi
    done
    
    cat >> "$backup_dir/restore.sh" << 'EOF'

echo "Setting file ownership..."
chown -R splunk:splunk /opt/splunk/etc/
chown -R splunk:splunk /opt/splunk/var/ 2>/dev/null || true

echo "Starting Splunk services..."
systemctl start splunk 2>/dev/null || /opt/splunk/bin/splunk start

echo "Configuration restored from backup."
EOF
    
    chmod +x "$backup_dir/restore.sh"
}

# Restore from backup
restore_from_backup() {
    local backup_dir="${1:-$BACKUP_DIR}"
    
    if [[ ! -d "$backup_dir" ]]; then
        error_exit "Backup directory not found: $backup_dir"
    fi
    
    if [[ ! -f "$backup_dir/restore.sh" ]]; then
        error_exit "Restore script not found: $backup_dir/restore.sh"
    fi
    
    warning "Restoring Splunk configuration from backup: $backup_dir"
    
    # Execute the restore script
    bash "$backup_dir/restore.sh"
    
    success "Configuration restored from backup"
}

# ============================================================================
# SECURITY ASSESSMENT FUNCTIONS
# ============================================================================

# Check current security configuration
check_current_security() {
    echo -e "${CYAN}=== SPLUNK SECURITY ASSESSMENT ===${NC}"
    log "Starting security assessment"
    
    # Reset counters
    CRITICAL_ISSUES_FOUND=0
    HIGH_ISSUES_FOUND=0
    MEDIUM_ISSUES_FOUND=0
    
    check_symmetric_key
    check_ssl_password
    check_web_https
    check_python_ssl_verification
    check_mongodb_binding
    check_ssl_verification_settings
    check_service_user
    check_file_permissions
    
    echo ""
    echo -e "${CYAN}=== SECURITY ASSESSMENT SUMMARY ===${NC}"
    echo -e "Critical Issues: ${RED}$CRITICAL_ISSUES_FOUND${NC}"
    echo -e "High Risk Issues: ${YELLOW}$HIGH_ISSUES_FOUND${NC}"
    echo -e "Medium Risk Issues: $MEDIUM_ISSUES_FOUND"
    
    local total_issues=$((CRITICAL_ISSUES_FOUND + HIGH_ISSUES_FOUND + MEDIUM_ISSUES_FOUND))
    if [[ $total_issues -eq 0 ]]; then
        success "No security issues detected"
    else
        warning "Total security issues found: $total_issues"
    fi
}

# Check symmetric key
check_symmetric_key() {
    local server_conf="$SPLUNK_HOME/etc/system/local/server.conf"
    
    if [[ -f "$server_conf" ]]; then
        if grep -q "pass4SymmKey = changeme" "$server_conf" 2>/dev/null; then
            echo -e "${RED}CRITICAL: Default symmetric key detected${NC}"
            ((CRITICAL_ISSUES_FOUND++)) || true
        else
            echo -e "${GREEN}PASS: Symmetric key appears to be changed${NC}"
        fi
    else
        echo -e "${YELLOW}WARNING: server.conf not found in local${NC}"
        ((MEDIUM_ISSUES_FOUND++)) || true
    fi
}

# Check SSL password
check_ssl_password() {
    local server_conf="$SPLUNK_HOME/etc/system/local/server.conf"
    
    if [[ -f "$server_conf" ]]; then
        if grep -q "sslPassword = password" "$server_conf" 2>/dev/null; then
            echo -e "${RED}CRITICAL: Default SSL password detected${NC}"
            ((CRITICAL_ISSUES_FOUND++)) || true
        else
            echo -e "${GREEN}PASS: SSL password appears to be changed${NC}"
        fi
    else
        echo -e "${YELLOW}WARNING: server.conf not found in local${NC}"
        ((MEDIUM_ISSUES_FOUND++)) || true
    fi
}

# Check web HTTPS
check_web_https() {
    local web_conf="$SPLUNK_HOME/etc/system/local/web.conf"
    
    if [[ -f "$web_conf" ]]; then
        if grep -q "enableSplunkWebSSL = false" "$web_conf" 2>/dev/null; then
            echo -e "${RED}CRITICAL: HTTPS disabled for web interface${NC}"
            ((CRITICAL_ISSUES_FOUND++)) || true
        elif grep -q "enableSplunkWebSSL = true" "$web_conf" 2>/dev/null; then
            echo -e "${GREEN}PASS: HTTPS enabled for web interface${NC}"
        else
            echo -e "${YELLOW}HIGH: HTTPS setting not configured (defaults to disabled)${NC}"
            ((HIGH_ISSUES_FOUND++)) || true
        fi
    else
        echo -e "${YELLOW}HIGH: web.conf not found in local${NC}"
        ((HIGH_ISSUES_FOUND++)) || true
    fi
}

# Check Python SSL verification
check_python_ssl_verification() {
    local launch_conf="$SPLUNK_HOME/etc/splunk-launch.conf"
    
    if [[ -f "$launch_conf" ]]; then
        if grep -q "^PYTHONHTTPSVERIFY=0" "$launch_conf" 2>/dev/null; then
            echo -e "${RED}CRITICAL: Python HTTPS verification disabled${NC}"
            ((CRITICAL_ISSUES_FOUND++)) || true
        else
            echo -e "${GREEN}PASS: Python HTTPS verification enabled or default${NC}"
        fi
    else
        echo -e "${YELLOW}WARNING: splunk-launch.conf not found${NC}"
        ((MEDIUM_ISSUES_FOUND++)) || true
    fi
}

# Check MongoDB binding
check_mongodb_binding() {
    local server_conf="$SPLUNK_HOME/etc/system/local/server.conf"
    
    # First check if configured for localhost binding
    if [[ -f "$server_conf" ]] && grep -q "bind_ip = 127.0.0.1" "$server_conf"; then
        echo -e "${GREEN}PASS: MongoDB configured to bind to localhost only${NC}"
        return 0
    fi
    
    # If not configured for localhost, check if protected by firewall
    if firewall-cmd --list-rich-rules 2>/dev/null | grep -q "source address=\"127.0.0.1\".*port=\"8191\""; then
        echo -e "${GREEN}PASS: MongoDB secured via firewall (localhost-only access)${NC}"
        return 0
    fi
    
    # Check actual network binding as fallback
    if netstat -tlnp 2>/dev/null | grep -q "0.0.0.0:8191" || ss -tlnp 2>/dev/null | grep -q "0.0.0.0:8191"; then
        echo -e "${RED}HIGH: MongoDB bound to all interfaces without firewall protection${NC}"
        ((HIGH_ISSUES_FOUND++)) || true
    else
        echo -e "${GREEN}PASS: MongoDB binding appears secure${NC}"
    fi
}

# Check SSL verification settings
check_ssl_verification_settings() {
    local server_conf="$SPLUNK_HOME/etc/system/local/server.conf"
    local issues=0
    
    if [[ -f "$server_conf" ]]; then
        if grep -q "sslVerifyServerName = false" "$server_conf" 2>/dev/null; then
            ((issues++)) || true
        fi
        if grep -q "cliVerifyServerName = false" "$server_conf" 2>/dev/null; then
            ((issues++)) || true
        fi
        if grep -q "sslVerifyServerCert = false" "$server_conf" 2>/dev/null; then
            ((issues++)) || true
        fi
        
        if [[ $issues -gt 0 ]]; then
            echo -e "${YELLOW}HIGH: SSL verification settings disabled ($issues settings)${NC}"
            ((HIGH_ISSUES_FOUND++)) || true
        else
            echo -e "${GREEN}PASS: SSL verification settings appear secure${NC}"
        fi
    fi
}

# Check service user
check_service_user() {
    local mongodb_running_as_root=false
    
    if pgrep -f mongod >/dev/null; then
        local mongo_user=$(ps -eo pid,user,comm | grep mongod | grep -v grep | awk '{print $2}' | head -1)
        if [[ "$mongo_user" == "root" ]]; then
            mongodb_running_as_root=true
        fi
    fi
    
    if [[ "$mongodb_running_as_root" == true ]]; then
        echo -e "${YELLOW}HIGH: MongoDB running as root user${NC}"
        ((HIGH_ISSUES_FOUND++)) || true
    else
        echo -e "${GREEN}PASS: MongoDB not running as root${NC}"
    fi
}

# Check file permissions
check_file_permissions() {
    local issues=0
    local files_to_check=(
        "$SPLUNK_HOME/etc/system/local/server.conf"
        "$SPLUNK_HOME/etc/system/local/web.conf"
        "$SPLUNK_HOME/etc/auth/server.pem"
        "$SPLUNK_HOME/var/lib/splunk/kvstore/mongo/splunk.key"
    )
    
    for file in "${files_to_check[@]}"; do
        if [[ -f "$file" ]]; then
            local owner=$(stat -c '%U' "$file" 2>/dev/null)
            if [[ "$owner" != "$SPLUNK_USER" ]]; then
                ((issues++)) || true
            fi
        fi
    done
    
    if [[ $issues -gt 0 ]]; then
        echo -e "${YELLOW}MEDIUM: File ownership issues detected ($issues files)${NC}"
        ((MEDIUM_ISSUES_FOUND++)) || true
    else
        echo -e "${GREEN}PASS: File permissions appear correct${NC}"
    fi
}

# ============================================================================
# HARDENING IMPLEMENTATION FUNCTIONS
# ============================================================================

# Fix symmetric key
fix_symmetric_key() {
    local server_conf="$SPLUNK_HOME/etc/system/local/server.conf"
    local new_key=$(generate_secure_key 64)
    
    info "Generating new symmetric key..."
    
    # Create local directory if it doesn't exist
    local local_dir="$(dirname "$server_conf")"
    create_splunk_directory "$local_dir"
    
    # Update or create server.conf
    if [[ -f "$server_conf" ]]; then
        # Replace existing key
        sed -i.bak "s|pass4SymmKey = .*|pass4SymmKey = $new_key|" "$server_conf"
    else
        # Create new configuration
        cat > "$server_conf" << EOF
[general]
pass4SymmKey = $new_key
EOF
    fi
    
    set_splunk_file_permissions "$server_conf" 600
    success "Symmetric key updated"
    ((ISSUES_FIXED++)) || true
}

# Fix SSL password and generate certificates
fix_ssl_configuration() {
    local server_conf="$SPLUNK_HOME/etc/system/local/server.conf"
    local auth_dir="$SPLUNK_HOME/etc/auth"
    local new_password=$(generate_secure_password)
    
    info "Generating new SSL certificates and password..."
    
    # Create auth directory if needed
    create_splunk_directory "$auth_dir" 755
    
    # Generate new certificates
    generate_certificates "$new_password"
    
    # Update server.conf with new SSL password
    local local_dir="$(dirname "$server_conf")"
    create_splunk_directory "$local_dir"
    
    if [[ -f "$server_conf" ]]; then
        sed -i.bak "s|sslPassword = .*|sslPassword = $new_password|" "$server_conf"
    else
        cat > "$server_conf" << EOF
[sslConfig]
sslPassword = $new_password
EOF
    fi
    
    set_splunk_file_permissions "$server_conf" 600
    success "SSL configuration updated"
    ((ISSUES_FIXED++)) || true
}

# Generate certificates with proper SANs
generate_certificates() {
    local ssl_password="$1"
    local auth_dir="$SPLUNK_HOME/etc/auth"
    local openssl_conf="/tmp/splunk_openssl.conf"
    
    info "Generating certificates with Subject Alternative Names..."
    
    # Create custom openssl configuration
    cat > "$openssl_conf" << EOF
[req]
default_bits = 4096
default_md = sha256
prompt = no
distinguished_name = req_distinguished_name
req_extensions = v3_req

[req_distinguished_name]
C = $CERT_COUNTRY
ST = $CERT_STATE
O = $CERT_ORGANIZATION
OU = $CERT_ORG_UNIT
CN = $SPLUNK_HOSTNAME.$SPLUNK_DOMAIN

[v3_req]
basicConstraints = CA:FALSE
keyUsage = nonRepudiation, digitalSignature, keyEncipherment
subjectAltName = @alt_names

[alt_names]
IP.1 = $SPLUNK_SERVER_IP
IP.2 = 127.0.0.1
DNS.1 = $SPLUNK_HOSTNAME
DNS.2 = localhost
DNS.3 = $SPLUNK_HOSTNAME.$SPLUNK_DOMAIN
DNS.4 = $SPLUNK_HOSTNAME.localdomain
EOF
    
    # Generate private key and certificate
    openssl req -new -x509 -days 365 -nodes \
        -config "$openssl_conf" \
        -keyout "$auth_dir/server.key" \
        -out "$auth_dir/server.pem" \
        -passout "pass:$ssl_password" 2>/dev/null
    
    # Create combined certificate file
    cat "$auth_dir/server.key" "$auth_dir/server.pem" > "$auth_dir/server.pem.new"
    mv "$auth_dir/server.pem.new" "$auth_dir/server.pem"
    
    # Create CA certificate (self-signed)
    cp "$auth_dir/server.pem" "$auth_dir/cacert.pem"
    
    # Set permissions
    set_splunk_file_permissions "$auth_dir/server.pem" 600
    set_splunk_file_permissions "$auth_dir/cacert.pem" 644
    
    # Cleanup
    rm -f "$openssl_conf" "$auth_dir/server.key"
    
    success "Certificates generated with proper SANs"
}

# Enable HTTPS for web interface
enable_web_https() {
    local web_conf="$SPLUNK_HOME/etc/system/local/web.conf"
    
    info "Enabling HTTPS for web interface..."
    
    # Create local directory if it doesn't exist
    local local_dir="$(dirname "$web_conf")"
    create_splunk_directory "$local_dir"
    
    # Update or create web.conf
    if [[ -f "$web_conf" ]]; then
        # Update existing file
        if grep -q "enableSplunkWebSSL" "$web_conf"; then
            sed -i.bak 's|enableSplunkWebSSL = false|enableSplunkWebSSL = true|' "$web_conf"
        else
            echo "" >> "$web_conf"
            echo "[settings]" >> "$web_conf"
            echo "enableSplunkWebSSL = true" >> "$web_conf"
        fi
    else
        # Create new configuration
        cat > "$web_conf" << EOF
[settings]
enableSplunkWebSSL = true
EOF
    fi
    
    set_splunk_file_permissions "$web_conf" 640
    success "HTTPS enabled for web interface"
    ((ISSUES_FIXED++)) || true
}

# Fix Python HTTPS verification
fix_python_ssl_verification() {
    local launch_conf="$SPLUNK_HOME/etc/splunk-launch.conf"
    
    info "Enabling Python HTTPS verification..."
    
    if [[ -f "$launch_conf" ]]; then
        # Remove or comment out the problematic line
        sed -i.bak 's|^PYTHONHTTPSVERIFY=0|#PYTHONHTTPSVERIFY=0|' "$launch_conf"
        
        # Add the correct setting if not present
        if ! grep -q "PYTHONHTTPSVERIFY=1" "$launch_conf"; then
            echo "PYTHONHTTPSVERIFY=1" >> "$launch_conf"
        fi
    else
        # Create launch configuration
        cat > "$launch_conf" << EOF
SPLUNK_HOME=$SPLUNK_HOME
SPLUNK_SERVER_NAME=Splunkd
PYTHONHTTPSVERIFY=1
PYTHONUTF8=1
EOF
    fi
    
    set_splunk_file_permissions "$launch_conf" 644
    success "Python HTTPS verification enabled"
    ((ISSUES_FIXED++)) || true
}

# Create MongoDB keyfile if missing
check_and_create_mongodb_keyfile() {
    local keyfile_path="$SPLUNK_HOME/var/lib/splunk/kvstore/mongo/splunk.key"
    local keyfile_dir="$(dirname "$keyfile_path")"
    
    if [[ -f "$keyfile_path" ]]; then
        info "MongoDB keyfile already exists: $keyfile_path"
        set_splunk_file_permissions "$keyfile_path" 600
    else
        warning "MongoDB keyfile missing, creating: $keyfile_path"
        
        # Create directory structure
        create_splunk_directory "$keyfile_dir" 700
        
        # Generate secure keyfile (1024 bytes of random data)
        openssl rand -base64 756 > "$keyfile_path"
        
        # Set proper permissions
        set_splunk_file_permissions "$keyfile_path" 600
        
        success "MongoDB keyfile created"
        ((ISSUES_FIXED++)) || true
    fi
}

# Fix MongoDB binding to localhost only
fix_mongodb_binding() {
    local server_conf="$SPLUNK_HOME/etc/system/local/server.conf"
    
    info "Configuring MongoDB to bind to localhost only..."
    
    # Ensure we have a server.conf to work with
    local local_dir="$(dirname "$server_conf")"
    create_splunk_directory "$local_dir"
    
    if [[ ! -f "$server_conf" ]]; then
        echo "[kvstore]" > "$server_conf"
    fi
    
    # Check if kvstore stanza exists
    if ! grep -q "^\[kvstore\]" "$server_conf"; then
        echo "" >> "$server_conf"
        echo "[kvstore]" >> "$server_conf"
    fi
    
    # Add or update bind_ip setting
    if grep -q "^bind_ip" "$server_conf"; then
        sed -i "s|^bind_ip.*|bind_ip = 127.0.0.1|" "$server_conf"
    else
        # Add bind_ip after [kvstore] stanza
        sed -i "/^\[kvstore\]/a bind_ip = 127.0.0.1" "$server_conf"
    fi
    
    set_splunk_file_permissions "$server_conf" 600
    success "MongoDB configured to bind to localhost only"
    ((ISSUES_FIXED++)) || true
}

# Fix SSL verification settings
fix_ssl_verification_settings() {
    local server_conf="$SPLUNK_HOME/etc/system/local/server.conf"
    
    info "Enabling SSL verification settings..."
    
    local ssl_settings=(
        "sslVerifyServerName = true"
        "cliVerifyServerName = true" 
        "sslVerifyServerCert = true"
        "sendStrictTransportSecurityHeader = true"
    )
    
    # Ensure we have a server.conf to work with
    local local_dir="$(dirname "$server_conf")"
    create_splunk_directory "$local_dir"
    
    if [[ ! -f "$server_conf" ]]; then
        echo "[sslConfig]" > "$server_conf"
    fi
    
    # Add SSL verification settings
    for setting in "${ssl_settings[@]}"; do
        local key=$(echo "$setting" | cut -d' ' -f1)
        if ! grep -q "^$key" "$server_conf"; then
            echo "$setting" >> "$server_conf"
        else
            sed -i.bak "s|^$key.*|$setting|" "$server_conf"
        fi
    done
    
    set_splunk_file_permissions "$server_conf" 600
    success "SSL verification settings enabled"
    ((ISSUES_FIXED++)) || true
}

# Fix service user permissions
fix_service_user() {
    info "Ensuring Splunk services run as splunk user..."
    
    # Create splunk user if it doesn't exist
    if ! id "$SPLUNK_USER" &>/dev/null; then
        useradd -r -s /bin/false "$SPLUNK_USER"
        log "Created splunk user account"
    fi
    
    # Fix ownership of all Splunk directories
    chown -R "$SPLUNK_USER:$SPLUNK_GROUP" "$SPLUNK_HOME"
    
    # Ensure splunk can be started by systemd as splunk user
    if systemctl list-unit-files | grep -q splunk.service; then
        # Update systemd service to run as splunk user
        local service_dir="/etc/systemd/system/splunk.service.d"
        mkdir -p "$service_dir"
        
        cat > "$service_dir/user-override.conf" << EOF
[Service]
User=$SPLUNK_USER
Group=$SPLUNK_GROUP
EOF
        
        systemctl daemon-reload
        log "Updated systemd service to run as splunk user"
    fi
    
    success "Service user configuration updated"
    ((ISSUES_FIXED++)) || true
}

# Configure firewall rules
configure_firewall() {
    info "Configuring firewall rules for Splunk access..."
    
    # Check if firewalld is available
    if command -v firewall-cmd >/dev/null 2>&1; then
        configure_firewalld
    elif command -v ufw >/dev/null 2>&1; then
        configure_ufw
    elif command -v iptables >/dev/null 2>&1; then
        configure_iptables
    else
        warning "No supported firewall found, skipping firewall configuration"
        return
    fi
    
    success "Firewall configuration completed"
    ((ISSUES_FIXED++)) || true
}

# Configure firewalld
configure_firewalld() {
    info "Configuring FirewallD rules for Splunk access..."
    
    # Check if firewalld is installed
    if ! command -v firewall-cmd >/dev/null; then
        warning "FirewallD not installed, skipping firewall configuration"
        return 0
    fi
    
    # Check if firewalld is enabled
    if ! systemctl is-enabled --quiet firewalld; then
        warning "FirewallD is disabled"
        read -p "Enable FirewallD service? (y/N): " -r
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            systemctl enable firewalld || {
                warning "Failed to enable FirewallD, skipping firewall configuration"
                return 0
            }
            success "FirewallD enabled successfully"
        else
            warning "Skipping firewall configuration"
            return 0
        fi
    fi
    
    # Check if firewalld is running
    if ! systemctl is-active --quiet firewalld; then
        warning "FirewallD is not running"
        read -p "Start FirewallD service? (y/N): " -r
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            systemctl start firewalld || {
                warning "Failed to start FirewallD, skipping firewall configuration"
                return 0
            }
            success "FirewallD started successfully"
        else
            warning "Skipping firewall configuration"
            return 0
        fi
    fi

    local web_ports=("8000/tcp" "8089/tcp" "9997/tcp")
    local mongo_port="8191/tcp"
    
    # Configure standard Splunk ports for subnet access
    for port in "${web_ports[@]}"; do
        firewall-cmd --remove-port="$port" --permanent 2>/dev/null || true
        
        for network in "${ALLOWED_NETWORKS[@]}"; do
            firewall-cmd --add-rich-rule="rule family='ipv4' source address='$network' port protocol='tcp' port='${port%/*}' accept" --permanent
        done
    done
    
    # Configure MongoDB for localhost-only access
    firewall-cmd --remove-port="$mongo_port" --permanent 2>/dev/null || true
    firewall-cmd --add-rich-rule="rule family='ipv4' source address='127.0.0.1' port protocol='tcp' port='8191' accept" --permanent
    
    firewall-cmd --reload
    log "Configured firewalld rules for Splunk ports (MongoDB restricted to localhost)"
}
    
    firewall-cmd --reload
    log "Configured firewalld rules for Splunk ports"
}

# Configure UFW (Ubuntu/Debian)
configure_ufw() {
    local ports=("8000" "8089" "9997" "8191")
    
    for port in "${ports[@]}"; do
        # Remove any existing rules
        ufw delete allow "$port" 2>/dev/null || true
        
        # Add rules for allowed networks
        for network in "${ALLOWED_NETWORKS[@]}"; do
            ufw allow from "$network" to any port "$port"
        done
    done
    
    log "Configured UFW rules for Splunk ports"
}

# Configure iptables
configure_iptables() {
    local ports=("8000" "8089" "9997" "8191")
    
    # Create custom chain for Splunk
    iptables -N SPLUNK-ACCESS 2>/dev/null || true
    iptables -F SPLUNK-ACCESS
    
    # Add allowed networks to chain
    for network in "${ALLOWED_NETWORKS[@]}"; do
        for port in "${ports[@]}"; do
            iptables -A SPLUNK-ACCESS -s "$network" -p tcp --dport "$port" -j ACCEPT
        done
    done
    
    # Drop all other traffic to these ports
    for port in "${ports[@]}"; do
        iptables -A SPLUNK-ACCESS -p tcp --dport "$port" -j DROP
    done
    
    # Add jump to chain in INPUT
    iptables -I INPUT -j SPLUNK-ACCESS
    
    # Save rules (distribution-specific)
    if command -v iptables-save >/dev/null; then
        iptables-save > /etc/iptables/rules.v4 2>/dev/null || \
        iptables-save > /etc/sysconfig/iptables 2>/dev/null || true
    fi
    
    log "Configured iptables rules for Splunk ports"
}

# Fix file permissions
fix_file_permissions() {
    info "Fixing file permissions for security-critical files..."
    
    local critical_files=(
        "$SPLUNK_HOME/etc/system/local/server.conf:600"
        "$SPLUNK_HOME/etc/system/local/web.conf:640"
        "$SPLUNK_HOME/etc/auth/server.pem:600"
        "$SPLUNK_HOME/etc/auth/cacert.pem:644"
        "$SPLUNK_HOME/var/lib/splunk/kvstore/mongo/splunk.key:600"
        "$SPLUNK_HOME/etc/splunk-launch.conf:644"
    )
    
    for file_perm in "${critical_files[@]}"; do
        local file="${file_perm%:*}"
        local perm="${file_perm#*:}"
        
        if [[ -f "$file" ]]; then
            set_splunk_file_permissions "$file" "$perm"
        fi
    done
    
    success "File permissions updated"
    ((ISSUES_FIXED++)) || true
}

# Fix SELinux contexts
fix_selinux_contexts() {
    if check_selinux; then
        info "SELinux detected, restoring file contexts..."
        
        restorecon -R "$SPLUNK_HOME/etc/system/local/" 2>/dev/null || warning "Failed to restore some SELinux contexts"
        restorecon "$SPLUNK_HOME/etc/auth/"*.pem 2>/dev/null || warning "Failed to restore certificate contexts"
        restorecon -R "$SPLUNK_HOME/var/lib/splunk/kvstore/" 2>/dev/null || true
        
        success "SELinux contexts restored"
    else
        info "SELinux not enabled, skipping context restoration"
    fi
}

# ============================================================================
# SERVICE MANAGEMENT FUNCTIONS
# ============================================================================

# Stop Splunk services
stop_splunk_services() {
    info "Stopping Splunk services..."
    
    if systemctl is-active --quiet splunk 2>/dev/null; then
        systemctl stop splunk
    elif pgrep -f splunkd >/dev/null; then
        "$SPLUNK_HOME/bin/splunk" stop
    fi
    
    # Wait for services to stop
    local timeout=30
    local count=0
    while pgrep -f splunkd >/dev/null && [[ $count -lt $timeout ]]; do
        sleep 1
        ((count++)) || true
    done
    
    if pgrep -f splunkd >/dev/null; then
        warning "Splunk services did not stop gracefully, forcing stop..."
        pkill -f splunkd || true
        sleep 2
    fi
    
    success "Splunk services stopped"
}

# Start Splunk services
start_splunk_services() {
    info "Starting Splunk services..."
    
    if systemctl list-unit-files | grep -q splunk.service; then
        systemctl start splunk
    else
        sudo -u "$SPLUNK_USER" "$SPLUNK_HOME/bin/splunk" start --accept-license --no-prompt
    fi
    
    # Wait for services to start
    local timeout=60
    local count=0
    while ! pgrep -f splunkd >/dev/null && [[ $count -lt $timeout ]]; do
        sleep 2
        ((count++)) || true
    done
    
    if pgrep -f splunkd >/dev/null; then
        success "Splunk services started"
    else
        error_exit "Failed to start Splunk services"
    fi
}

# ============================================================================
# VERIFICATION FUNCTIONS
# ============================================================================

# Verify security hardening
verify_hardening() {
    echo -e "${CYAN}=== VERIFYING SECURITY HARDENING ===${NC}"
    log "Starting hardening verification"
    
    local verification_passed=0
    local verification_failed=0
    
    # Test HTTPS connectivity
    if curl -k -s --max-time 10 "https://$SPLUNK_SERVER_IP:8000" >/dev/null 2>&1; then
        success "HTTPS web interface accessible"
        ((verification_passed++)) || true
    else
        warning "HTTPS web interface not accessible"
        ((verification_failed++)) || true
    fi
    
    # Test Splunk API
    if curl -k -s --max-time 10 "https://$SPLUNK_SERVER_IP:8089/services/server/info" | grep -q "splunkd" 2>/dev/null; then
        success "Splunk API accessible via HTTPS"
        ((verification_passed++)) || true
    else
        warning "Splunk API not accessible"
        ((verification_failed++)) || true
    fi
    
    # Verify certificate SANs
    if openssl x509 -in "$SPLUNK_HOME/etc/auth/server.pem" -text -noout | grep -q "$SPLUNK_SERVER_IP" 2>/dev/null; then
        success "Certificate contains correct IP address in SAN"
        ((verification_passed++)) || true
    else
        warning "Certificate may not contain correct SANs"
        ((verification_failed++)) || true
    fi
    
    # Verify MongoDB binding
    if firewall-cmd --list-rich-rules 2>/dev/null | grep -q "source address=\"127.0.0.1\".*port=\"8191\""; then
        success "MongoDB secured via firewall (localhost-only access)"
        ((verification_passed++))
    else
        warning "MongoDB firewall protection verification failed"
        ((verification_failed++))
    fi
    
    # Verify service user
    if pgrep -f mongod >/dev/null; then
        local mongo_user=$(ps -eo pid,user,comm | grep mongod | grep -v grep | awk '{print $2}' | head -1)
        if [[ "$mongo_user" == "$SPLUNK_USER" ]]; then
            success "MongoDB running as splunk user"
            ((verification_passed++)) || true
        else
            warning "MongoDB not running as splunk user (running as: $mongo_user)"
            ((verification_failed++)) || true
        fi
    else
        warning "MongoDB not running"
        ((verification_failed++)) || true
    fi
    
    echo ""
    echo -e "${CYAN}=== VERIFICATION SUMMARY ===${NC}"
    echo -e "Verification Passed: ${GREEN}$verification_passed${NC}"
    echo -e "Verification Failed: ${RED}$verification_failed${NC}"
    
    if [[ $verification_failed -eq 0 ]]; then
        success "All verification tests passed"
    else
        warning "Some verification tests failed - see details above"
    fi
}

# ============================================================================
# COMPLIANCE REPORTING
# ============================================================================

# Generate security compliance report
generate_compliance_report() {
    local status="${1:-COMPLETED}"
    
    cat > "$COMPLIANCE_REPORT" << EOF
================================================================================
SPLUNK SECURITY HARDENING COMPLIANCE REPORT
================================================================================

Execution Details:
- Timestamp: $(date)
- Operation: $OPERATION
- Status: $status
- Executed by: $(whoami)
- Splunk Version: $(cat $SPLUNK_HOME/etc/splunk.version 2>/dev/null | grep VERSION | cut -d'=' -f2 || echo "Unknown")

System Information:
- Hostname: $(hostname)
- Operating System: $(cat /etc/os-release 2>/dev/null | grep PRETTY_NAME | cut -d'"' -f2 || uname -a)
- Splunk Home: $SPLUNK_HOME
- Splunk Server IP: $SPLUNK_SERVER_IP

Security Assessment Summary:
- Critical Issues Found: $CRITICAL_ISSUES_FOUND
- High Risk Issues Found: $HIGH_ISSUES_FOUND  
- Medium Risk Issues Found: $MEDIUM_ISSUES_FOUND
- Total Issues Fixed: $ISSUES_FIXED

Critical Security Issues Addressed:
$(if [[ $OPERATION == "apply-critical" ]] || [[ $OPERATION == "apply-all" ]]; then
echo "- Default symmetric key changed to secure 64-character key"
echo "- Default SSL password changed and new certificates generated"
echo "- HTTPS enabled for web interface"
echo "- Python HTTPS verification enabled"
fi)

Additional Hardening Applied:
$(if [[ $OPERATION == "apply-all" ]]; then
echo "- SSL certificate verification enabled"
echo "- MongoDB keyfile created/verified"
echo "- Service user security configured"
echo "- File permissions audited and fixed"
echo "- Firewall rules configured for network access control"
echo "- SELinux contexts restored (if applicable)"
fi)

Network Security:
- Allowed Networks: $(IFS=', '; echo "${ALLOWED_NETWORKS[*]}")
- Firewall Configuration: $(if [[ $OPERATION == "apply-all" ]]; then echo "Applied"; else echo "Not Modified"; fi)

Certificate Information:
- Certificate Subject: CN=$SPLUNK_HOSTNAME.$SPLUNK_DOMAIN, O=$CERT_ORGANIZATION, ST=$CERT_STATE, C=$CERT_COUNTRY
- Subject Alternative Names: $SPLUNK_SERVER_IP, 127.0.0.1, $SPLUNK_HOSTNAME, localhost
- Key Size: 4096 bits

Backup Information:
- Backup Created: $BACKUP_CREATED
- Backup Location: $BACKUP_DIR
- Rollback Available: $ROLLBACK_AVAILABLE

Recommendations for Ongoing Security:
- Monitor configuration file changes for unauthorized modifications
- Implement regular certificate rotation procedures
- Review firewall rules periodically for access requirements
- Monitor audit logs for suspicious authentication attempts
- Schedule quarterly security assessments

Next Steps for Blue Team Exercise:
- Distribute CA certificate to systems requiring centralized logging
- Configure Universal Forwarders on network devices
- Implement monitoring rules for certificate changes
- Test incident response procedures with hardened configuration

For detailed technical log, see: $LOG_FILE
For restoration procedures, see: $BACKUP_DIR/restore.sh

Report Generated: $(date)
================================================================================
EOF
    
    success "Compliance report generated: $COMPLIANCE_REPORT"
}

# ============================================================================
# MAIN EXECUTION FUNCTIONS
# ============================================================================

# Apply critical fixes only
apply_critical_fixes() {
    echo -e "${CYAN}=== APPLYING CRITICAL SECURITY FIXES ===${NC}"
    log "Starting critical security fixes"
    
    # Stop services for configuration changes
    stop_splunk_services
    
    # Apply critical fixes
    fix_symmetric_key
    fix_ssl_configuration
    enable_web_https
    fix_python_ssl_verification
    check_and_create_mongodb_keyfile
    fix_mongodb_binding
    
    # Validate configuration before restart
    validate_splunk_config "$SPLUNK_HOME/etc/system/local"
    
    # Fix file permissions
    fix_file_permissions
    
    # Start services
    start_splunk_services
    
    # Wait for services to fully start
    sleep 10
    
    success "Critical security fixes applied successfully"
}

# Apply all hardening measures
apply_all_hardening() {
    echo -e "${CYAN}=== APPLYING COMPREHENSIVE SECURITY HARDENING ===${NC}"
    log "Starting comprehensive security hardening"
    
    # Stop services for configuration changes
    stop_splunk_services
    
    # Apply all fixes
    fix_symmetric_key
    fix_ssl_configuration  
    enable_web_https
    fix_python_ssl_verification
    fix_ssl_verification_settings
    check_and_create_mongodb_keyfile
    fix_mongodb_binding
    fix_service_user
    fix_file_permissions
    
    # Validate configuration before restart
    validate_splunk_config "$SPLUNK_HOME/etc/system/local"
    
    # Fix SELinux contexts
    fix_selinux_contexts
    
    # Configure firewall
    configure_firewall
    
    # Start services
    start_splunk_services
    
    # Wait for services to fully start
    sleep 15
    
    success "Comprehensive security hardening applied successfully"
}

# Display help
show_help() {
    echo "Splunk Security Hardening Script"
    echo ""
    echo "Usage: $0 [OPERATION]"
    echo ""
    echo "Operations:"
    echo "  check           - Assess current security configuration (default)"
    echo "  backup          - Create backup of configuration files only"
    echo "  apply-critical  - Fix critical security issues only"
    echo "  apply-all       - Apply all security hardening measures"
    echo "  verify          - Verify security hardening was successful"
    echo "  rollback [DIR]  - Restore configuration from backup directory"
    echo "  --help          - Display this help message"
    echo ""
    echo "Critical Issues Addressed:"
    echo "  - Default symmetric key (pass4SymmKey = changeme)"
    echo "  - Default SSL password (sslPassword = password)"
    echo "  - Unencrypted web interface (enableSplunkWebSSL = false)"
    echo "  - Disabled Python HTTPS verification (PYTHONHTTPSVERIFY=0)"
    echo ""
    echo "Additional Hardening (apply-all only):"
    echo "  - SSL certificate verification settings"
    echo "  - MongoDB keyfile creation"
    echo "  - Service user security"
    echo "  - File permissions audit"
    echo "  - Firewall access control"
    echo "  - SELinux context restoration"
    echo ""
    echo "Configuration Variables:"
    echo "  SPLUNK_SERVER_IP: $SPLUNK_SERVER_IP"
    echo "  SPLUNK_DOMAIN: $SPLUNK_DOMAIN"
    echo "  SPLUNK_HOSTNAME: $SPLUNK_HOSTNAME"
    echo ""
    echo "Examples:"
    echo "  $0 check"
    echo "  $0 backup"
    echo "  $0 apply-critical"
    echo "  $0 apply-all"
    echo "  $0 verify"
    echo "  $0 rollback /tmp/splunk_config_backup_20251115_143022"
    echo ""
}

# ============================================================================
# MAIN SCRIPT EXECUTION
# ============================================================================

# Main function
main() {
    # Initialize
    init_logging
    
    # Handle help request
    if [[ "$OPERATION" == "--help" ]] || [[ "$OPERATION" == "-h" ]]; then
        show_help
        exit 0
    fi
    
    # Validate prerequisites
    check_root
    check_splunk_installed
    
    # Execute based on operation
    case "$OPERATION" in
        "check")
            check_current_security
            generate_compliance_report "ASSESSMENT_COMPLETED"
            ;;
        "backup")
            create_backup
            generate_compliance_report "BACKUP_COMPLETED"
            ;;
        "apply-critical")
            create_backup
            apply_critical_fixes
            verify_hardening
            generate_compliance_report "CRITICAL_FIXES_APPLIED"
            ;;
        "apply-all")
            create_backup
            apply_all_hardening
            verify_hardening
            generate_compliance_report "COMPREHENSIVE_HARDENING_APPLIED"
            ;;
        "verify")
            verify_hardening
            generate_compliance_report "VERIFICATION_COMPLETED"
            ;;
        "rollback")
            if [[ -n "${2:-}" ]]; then
                restore_from_backup "$2"
            else
                restore_from_backup
            fi
            generate_compliance_report "ROLLBACK_COMPLETED"
            ;;
        *)
            error_exit "Invalid operation: $OPERATION. Use --help for usage information."
            ;;
    esac
    
    success "Operation '$OPERATION' completed successfully"
    info "Detailed log: $LOG_FILE"
    info "Compliance report: $COMPLIANCE_REPORT"
}

# Execute main function
main "$@"