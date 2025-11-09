#!/bin/bash

# Comprehensive Firewall Rule Analysis Script
# Shows firewalld and iptables rules in unified precedence-ordered table

# Column widths
COL_PRECEDENCE=3
COL_SOURCE=10
COL_ZONE=20
COL_INTERFACE=10
COL_SERVICE=20
COL_PORT=15
COL_ACTION=10
COL_DETAILS=25

# Global variables
declare -a all_rules
declare -i rule_count=0
declare -i conflict_count=0

# Service to port mapping (common services)
declare -A service_ports
service_ports=(
    ["ssh"]="22/tcp"
    ["http"]="80/tcp" 
    ["https"]="443/tcp"
    ["ftp"]="21/tcp"
    ["smtp"]="25/tcp"
    ["dns"]="53/udp"
    ["dhcp"]="67/udp"
    ["dhcpv6"]="547/udp"
    ["dhcpv6-client"]="546/udp"
    ["ntp"]="123/udp"
    ["cockpit"]="9090/tcp"
    ["mysql"]="3306/tcp"
    ["postgresql"]="5432/tcp"
    ["samba"]="445/tcp"
    ["ldap"]="389/tcp"
    ["ldaps"]="636/tcp"
    ["mdn"]="5353/udp"
)

# Function to print table header
print_header() {
    printf "%-${COL_PRECEDENCE}s %-${COL_SOURCE}s %-${COL_ZONE}s %-${COL_INTERFACE}s %-${COL_SERVICE}s %-${COL_PORT}s %-${COL_ACTION}s %s\n" \
           "#" "SOURCE" "ZONE" "INTERFACE" "SERVICE" "PORT" "ACTION" "DETAILS"
    printf "%-${COL_PRECEDENCE}s %-${COL_SOURCE}s %-${COL_ZONE}s %-${COL_INTERFACE}s %-${COL_SERVICE}s %-${COL_PORT}s %-${COL_ACTION}s %s\n" \
           "---" "------" "----" "---------" "-------" "----" "------" "-------"
}

# Function to print rule row
print_rule() {
    local precedence="$1"
    local source="$2"
    local zone="$3"  
    local interface="$4"
    local service="$5"
    local port="$6"
    local action="$7"
    local details="$8"
    
    printf "%-${COL_PRECEDENCE}s %-${COL_SOURCE}s %-${COL_ZONE}s %-${COL_INTERFACE}s %-${COL_SERVICE}s %-${COL_PORT}s %-${COL_ACTION}s %s\n" \
           "$precedence" "$source" "$zone" "$interface" "$service" "$port" "$action" "$details"
}

# Function to get port from service name
get_service_port() {
    local service="$1"
    echo "${service_ports[$service]:-"-"}"
}

# Function to parse iptables interface
parse_iptables_interface() {
    local rule="$1"
    
    # Check for input interface (-i)
    if [[ $rule =~ -i[[:space:]]+([^[:space:]]+) ]]; then
        echo "${BASH_REMATCH[1]}"
    # Check for output interface (-o)
    elif [[ $rule =~ -o[[:space:]]+([^[:space:]]+) ]]; then
        echo "${BASH_REMATCH[1]}"
    else
        echo "ALL"  # No interface specified = all interfaces
    fi
}

# Function to parse iptables port
parse_iptables_port() {
    local rule="$1"
    
    # Look for --dport (destination port)
    if [[ $rule =~ --dport[[:space:]]+([0-9]+) ]]; then
        local port="${BASH_REMATCH[1]}"
        # Determine protocol
        if [[ $rule =~ -p[[:space:]]+tcp ]]; then
            echo "${port}/tcp"
        elif [[ $rule =~ -p[[:space:]]+udp ]]; then
            echo "${port}/udp"
        else
            echo "$port"
        fi
    # Look for --sport (source port)
    elif [[ $rule =~ --sport[[:space:]]+([0-9]+) ]]; then
        local port="${BASH_REMATCH[1]}"
        if [[ $rule =~ -p[[:space:]]+tcp ]]; then
            echo "${port}/tcp"
        elif [[ $rule =~ -p[[:space:]]+udp ]]; then
            echo "${port}/udp"
        else
            echo "$port"
        fi
    else
        echo "all"
    fi
}

# Function to parse iptables action
parse_iptables_action() {
    local rule="$1"
    
    if [[ $rule =~ -j[[:space:]]+ACCEPT ]]; then
        echo "allow"
    elif [[ $rule =~ -j[[:space:]]+DROP ]]; then
        echo "drop"
    elif [[ $rule =~ -j[[:space:]]+REJECT ]]; then
        echo "reject"
    elif [[ $rule =~ -j[[:space:]]+([A-Z_]+) ]]; then
        echo "${BASH_REMATCH[1],,}"  # Convert to lowercase
    else
        echo "unknown"
    fi
}

# Function to get manual iptables rules
get_manual_iptables_rules() {
    local precedence=1
    
    # Get iptables rules with line numbers, excluding firewalld chains
    sudo iptables -L INPUT -n --line-numbers 2>/dev/null | while read line_num target prot opt source destination extra; do
        # Skip header lines and firewalld chains
        if [[ "$line_num" =~ ^[0-9]+$ ]] && [[ ! "$target" =~ ^(FWDI|FWDO|FWDX) ]]; then
            # Parse the rule
            local full_rule=$(sudo iptables -L INPUT -n --line-numbers | grep "^$line_num")
            local interface=$(parse_iptables_interface "$full_rule")
            local port=$(parse_iptables_port "$full_rule")
            local action=$(parse_iptables_action "$full_rule")
            
            # Create rule entry
            all_rules+=("$line_num|iptables|-|$interface|-|$port|$action|MANUAL RULE")
            ((rule_count++))
        fi
    done
}

# Function to get firewalld rules
get_firewalld_rules() {
    if ! systemctl is-active firewalld >/dev/null 2>&1; then
        return
    fi
    
    local base_precedence=100  # Start firewalld rules after iptables
    local current_precedence=$base_precedence
    
    # Get default zone for reference
    local default_zone=$(sudo firewall-cmd --get-default-zone 2>/dev/null)
    
    # Process each zone
    for zone in $(sudo firewall-cmd --get-zones 2>/dev/null); do
        # Get zone information
        local interfaces=$(sudo firewall-cmd --zone="$zone" --list-interfaces 2>/dev/null)
        local services=$(sudo firewall-cmd --zone="$zone" --list-services 2>/dev/null)
        local ports=$(sudo firewall-cmd --zone="$zone" --list-ports 2>/dev/null)
        local sources=$(sudo firewall-cmd --zone="$zone" --list-sources 2>/dev/null)
        
        # Skip empty zones
        if [[ -z "$interfaces" && -z "$services" && -z "$ports" && -z "$sources" ]]; then
            continue
        fi
        
        # Determine if zone is active
        local zone_status="zone service"
        if [[ -z "$interfaces" && -z "$sources" ]]; then
            zone_status="INACTIVE ZONE"
        fi
        
        # Set interface list (handle multiple interfaces)
        local interface_list
        if [[ -n "$interfaces" ]]; then
            interface_list="$interfaces"
        elif [[ -n "$sources" ]]; then
            interface_list="-"
            zone_status="source: $(echo $sources | tr ' ' ',')"
        else
            interface_list="-"
        fi
        
        # Process services
        for service in $services; do
            local port=$(get_service_port "$service")
            
            if [[ "$interface_list" == "-" ]]; then
                # Single entry for zone with no interfaces
                all_rules+=("$current_precedence|firewalld|$zone|-|$service|$port|allow|$zone_status")
                ((current_precedence++))
                ((rule_count++))
            else
                # Separate entry for each interface
                for interface in $interface_list; do
                    all_rules+=("$current_precedence|firewalld|$zone|$interface|$service|$port|allow|$zone_status")
                    ((current_precedence++))
                    ((rule_count++))
                done
            fi
        done
        
        # Process custom ports
        for port in $ports; do
            if [[ "$interface_list" == "-" ]]; then
                all_rules+=("$current_precedence|firewalld|$zone|-|-|$port|allow|$zone_status")
                ((current_precedence++))
                ((rule_count++))
            else
                for interface in $interface_list; do
                    all_rules+=("$current_precedence|firewalld|$zone|$interface|-|$port|allow|$zone_status")
                    ((current_precedence++))
                    ((rule_count++))
                done
            fi
        done
    done
}

# Function to detect conflicts
detect_conflicts() {
    local conflicts=0
    
    # Simple conflict detection: look for manual iptables rules that could block firewalld
    declare -A manual_blocks
    declare -A firewalld_allows
    
    # Parse all rules to find conflicts
    for rule in "${all_rules[@]}"; do
        IFS='|' read -r precedence source zone interface service port action details <<< "$rule"
        
        if [[ "$source" == "iptables" && "$action" =~ ^(drop|reject)$ ]]; then
            # Manual rule that blocks
            if [[ "$interface" == "ALL" ]]; then
                manual_blocks["$port"]="ALL"
            else
                manual_blocks["$port:$interface"]="$interface"
            fi
        elif [[ "$source" == "firewalld" && "$action" == "allow" ]]; then
            # firewalld rule that allows
            firewalld_allows["$port:$interface"]="$port"
        fi
    done
    
    # Check for conflicts
    for fw_rule in "${!firewalld_allows[@]}"; do
        IFS=':' read -r port interface <<< "$fw_rule"
        
        # Check if blocked by manual rule
        if [[ -n "${manual_blocks[$port]}" || -n "${manual_blocks[$port:$interface]}" ]]; then
            ((conflicts++))
            
            # Update details to show bypass
            for i in "${!all_rules[@]}"; do
                if [[ "${all_rules[$i]}" =~ firewalld.*$port.*allow ]]; then
                    all_rules[$i]="${all_rules[$i]%|*}|BYPASSED by manual rule"
                fi
            done
        fi
    done
    
    echo $conflicts
}

# Function to print comprehensive footer
print_footer() {
    echo ""
    
    # Default zone
    if systemctl is-active firewalld >/dev/null 2>&1; then
        local default_zone=$(sudo firewall-cmd --get-default-zone 2>/dev/null)
        echo "Default firewalld zone is: $default_zone"
        
        # Active zones with interfaces
        local active_zones_output=""
        while IFS= read -r line; do
            if [[ "$line" =~ ^[[:space:]]*interfaces: ]]; then
                local interfaces=$(echo "$line" | sed 's/.*interfaces: //')
                if [ -n "$current_zone" ] && [ -n "$interfaces" ]; then
                    if [ -n "$active_zones_output" ]; then
                        active_zones_output="$active_zones_output, "
                    fi
                    active_zones_output="$active_zones_output$current_zone ($interfaces)"
                fi
            elif [[ ! "$line" =~ ^[[:space:]] ]]; then
                current_zone="$line"
            fi
        done < <(sudo firewall-cmd --get-active-zones 2>/dev/null)
        
        echo "Active zones: $active_zones_output"
    else
        echo "Default firewalld zone is: N/A (firewalld not active)"
        echo "Active zones: N/A (firewalld not active)"
    fi
    
    # Count manual iptables rules
    local manual_count=0
    if command -v iptables >/dev/null 2>&1; then
        manual_count=$(sudo iptables-save 2>/dev/null | grep -v "firewalld\|FWDI\|FWDO\|FWDX" | grep -E "^\-A" | wc -l)
    fi
    echo "Manual iptables rules detected: $manual_count"
    
    # Conflict detection
    echo "Conflicting rules detected: $conflict_count"
    
    # Firewalld service status
    local firewalld_status
    if systemctl is-active firewalld >/dev/null 2>&1; then
        firewalld_status="active"
    elif systemctl is-enabled firewalld >/dev/null 2>&1; then
        firewalld_status="inactive (enabled)"
    else
        firewalld_status="inactive (disabled)"
    fi
    echo "Firewalld service status: $firewalld_status"
    
    # Total rules count
    echo "Total rules displayed: $rule_count"
}

# Main execution
main() {
    echo "Comprehensive Firewall Rule Analysis"
    echo "====================================="
    echo ""
    
    # Check if running as root
    if [[ $EUID -ne 0 ]]; then
        echo "This script requires root privileges to access firewall rules."
        echo "Please run with sudo: sudo $0"
        exit 1
    fi
    
    # Collect all rules
    get_manual_iptables_rules
    get_firewalld_rules
    
    # Sort rules by precedence
    IFS=$'\n' all_rules=($(sort -t'|' -k1,1n <<< "${all_rules[*]}"))
    
    # Detect conflicts
    conflict_count=$(detect_conflicts)
    
    # Print table
    print_header
    
    # Print all rules in precedence order
    for rule in "${all_rules[@]}"; do
        IFS='|' read -r precedence source zone interface service port action details <<< "$rule"
        print_rule "$precedence" "$source" "$zone" "$interface" "$service" "$port" "$action" "$details"
    done
    
    # Print footer
    print_footer
}

# Run main function
main "$@"