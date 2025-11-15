#!/bin/bash

# User enumeration script for security assessment
# Categorizes users by security risk level with suspicious users prioritized

set -euo pipefail

# Configuration
LOG_FILE="/var/log/get_users.log"
ENABLE_LOGGING=${ENABLE_LOGGING:-false}

# Column width configuration
USERNAME_WIDTH=18
UID_WIDTH=5
GROUPS_WIDTH=16
SHELL_WIDTH=18
HOME_WIDTH=20
NOTES_WIDTH=25

# Arrays to store users by category
declare -a high_risk_users
declare -a privileged_users  
declare -a standard_users

# Logging function
log() {
    if [[ "$ENABLE_LOGGING" == "true" ]]; then
        echo "$(date '+%Y-%m-%d %H:%M:%S') - $1" | tee -a "$LOG_FILE"
    fi
}

# Error handling
error_exit() {
    echo "ERROR: $1" >&2
    log "ERROR: $1"
    exit 1
}

# Check system compatibility
check_system() {
    if [[ ! -f /etc/passwd ]] || [[ ! -f /etc/shadow ]] || [[ ! -f /etc/group ]]; then
        error_exit "Required system files not found"
    fi
    
    # Check if we can read shadow file (requires root for password checks)
    if [[ $EUID -eq 0 ]] && [[ -r /etc/shadow ]]; then
        SHADOW_READABLE=true
    else
        SHADOW_READABLE=false
        echo "Warning: Running without root privileges - password checks disabled"
    fi
    
    log "System check passed - user enumeration starting"
}

# Check if user has empty/locked password
has_empty_password() {
    local username="$1"
    
    if [[ "$SHADOW_READABLE" == "false" ]]; then
        return 1
    fi
    
    local password_hash
    password_hash=$(getent shadow "$username" | cut -d: -f2)
    
    # Empty password or locked account patterns
    [[ -z "$password_hash" ]] || [[ "$password_hash" == "!" ]] || [[ "$password_hash" == "*" ]]
}

# Check if user was created recently (last 30 days)
is_recent_user() {
    local username="$1"
    local home_dir="$2"
    
    # Check if home directory was created in last 30 days
    if [[ -d "$home_dir" ]]; then
        local dir_age
        dir_age=$(find "$home_dir" -maxdepth 0 -mtime -30 2>/dev/null | wc -l)
        [[ "$dir_age" -gt 0 ]]
    else
        return 1
    fi
}

# Categorize users based on security risk
categorize_users() {
    log "Categorizing users by security risk level"
    
    # Read /etc/passwd and analyze each user
    while IFS=: read -r username password uid gid gecos home shell; do
        local groups user_groups notes=""
        
        # Get user's groups
        user_groups=$(groups "$username" 2>/dev/null | cut -d: -f2 | sed 's/^ *//; s/ /, /g' || echo "")
        
        # Determine user category and notes
        if [[ "$uid" -eq 0 && "$username" != "root" ]]; then
            # Non-root user with UID 0 - HIGH RISK
            notes="[SUSPICIOUS] Non-root UID 0"
            high_risk_users+=("$username|$uid|$user_groups|$shell|$home|$notes")
            
        elif [[ "$uid" -lt 1000 && "$shell" =~ /(bash|sh|zsh|fish)$ ]]; then
            # Service account with login shell - HIGH RISK
            notes="[SUSPICIOUS] Service account with login shell"
            high_risk_users+=("$username|$uid|$user_groups|$shell|$home|$notes")
            
        elif has_empty_password "$username"; then
            # Empty password - HIGH RISK
            notes="[SUSPICIOUS] Empty/locked password"
            high_risk_users+=("$username|$uid|$user_groups|$shell|$home|$notes")
            
        elif is_recent_user "$username" "$home"; then
            # Recently created user - potentially suspicious
            notes="[RECENT] Created within 30 days"
            high_risk_users+=("$username|$uid|$user_groups|$shell|$home|$notes")
            
        elif echo "$user_groups" | grep -qE "(wheel|sudo|admin|root)"; then
            # User has administrative privileges
            notes="Admin user"
            privileged_users+=("$username|$uid|$user_groups|$shell|$home|$notes")
            
        elif [[ "$uid" -ge 1000 && "$shell" =~ /(bash|sh|zsh|fish)$ ]]; then
            # Regular user account
            notes="Regular user"
            standard_users+=("$username|$uid|$user_groups|$shell|$home|$notes")
            
        elif [[ "$uid" -lt 1000 ]]; then
            # System account with nologin shell (normal)
            notes="System account"
            standard_users+=("$username|$uid|$user_groups|$shell|$home|$notes")
        fi
        
    done < /etc/passwd
}

# Function to print section header
print_header() {
    local title="$1"
    
    echo
    echo "=== $title ==="
    printf "%-${USERNAME_WIDTH}s %-${UID_WIDTH}s %-${GROUPS_WIDTH}s %-${SHELL_WIDTH}s %-${HOME_WIDTH}s %-${NOTES_WIDTH}s\n" \
        "USERNAME" "UID" "GROUPS" "SHELL" "HOME" "NOTES"
    printf "%-${USERNAME_WIDTH}s %-${UID_WIDTH}s %-${GROUPS_WIDTH}s %-${SHELL_WIDTH}s %-${HOME_WIDTH}s %-${NOTES_WIDTH}s\n" \
        "$(printf '%*s' 8 | tr ' ' '-')" \
        "$(printf '%*s' 3 | tr ' ' '-')" \
        "$(printf '%*s' 6 | tr ' ' '-')" \
        "$(printf '%*s' 5 | tr ' ' '-')" \
        "$(printf '%*s' 4 | tr ' ' '-')" \
        "$(printf '%*s' 5 | tr ' ' '-')"
}

# Function to print users from array
print_users() {
    local -n users_array=$1
    
    for user_entry in "${users_array[@]}"; do
        IFS='|' read -r username uid groups shell home notes <<< "$user_entry"
        printf "%-${USERNAME_WIDTH}s %-${UID_WIDTH}s %-${GROUPS_WIDTH}s %-${SHELL_WIDTH}s %-${HOME_WIDTH}s %-${NOTES_WIDTH}s\n" \
            "$username" \
            "$uid" \
            "${groups:0:$((GROUPS_WIDTH-1))}" \
            "$shell" \
            "${home:0:$((HOME_WIDTH-1))}" \
            "$notes"
    done
}

# Function to sort users alphabetically by username
sort_users_by_uid() {
    local -n users_array=$1
    local temp_file=$(mktemp)
    
    # Create sortable entries
    for user_entry in "${users_array[@]}"; do
        IFS='|' read -r username uid rest <<< "$user_entry"
        echo "${uid}|${user_entry}" >> "$temp_file"
    done
    
    # Sort by username, then extract original entries
    users_array=()
    while IFS='|' read -r uid original_entry; do
        users_array+=("$original_entry")
    done < <(sort -t'|' -k1,1n "$temp_file")
    
    rm "$temp_file"
}

# Main enumeration function
enumerate_users() {
    echo "User Enumeration - Security Assessment"
    echo "====================================="
    
    categorize_users
    
    # Sort arrays
    sort_users_by_uid high_risk_users
    sort_users_by_uid privileged_users
    sort_users_by_uid standard_users
    
    # Print High-Risk Users section
    print_header "High-Risk/Suspicious Users"
    if [[ ${#high_risk_users[@]} -eq 0 ]]; then
        echo "No high-risk users found."
    else
        print_users high_risk_users
    fi
    
    # Print Privileged Users section  
    print_header "Privileged Users"
    if [[ ${#privileged_users[@]} -eq 0 ]]; then
        echo "No privileged users found."
    else
        print_users privileged_users
    fi
    
    # Print Standard Users section
    print_header "Standard Users"
    if [[ ${#standard_users[@]} -eq 0 ]]; then
        echo "No standard users found."
    else
        print_users standard_users
    fi
    
    echo
    echo "Summary:"
    echo "  High-risk users: ${#high_risk_users[@]}"
    echo "  Privileged users: ${#privileged_users[@]}"
    echo "  Standard users: ${#standard_users[@]}"
    
    log "User enumeration completed - High-risk: ${#high_risk_users[@]}, Privileged: ${#privileged_users[@]}, Standard: ${#standard_users[@]}"
}

# Main function
main() {
    check_system
    enumerate_users
}

# Run main function
main