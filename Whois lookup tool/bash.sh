#!/bin/bash

# Whois Lookup Tool - Bash Implementation

set -e

# Color codes
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Default values
TIMEOUT=10
OUTPUT_FILE=""
VERBOSE=false
JSON_OUTPUT=false
SUMMARY_ONLY=false

# Function to print colored output
print_info() { echo -e "${BLUE}[*]${NC} $1"; }
print_success() { echo -e "${GREEN}[+]${NC} $1"; }
print_error() { echo -e "${RED}[!]${NC} $1"; }
print_warning() { echo -e "${YELLOW}[⚠]${NC} $1"; }

# Help function
show_help() {
    cat << EOF
Whois Lookup Tool - Bash Version

Usage: $0 -d DOMAIN [OPTIONS]

Required:
    -d DOMAIN          Domain name to lookup

Options:
    -t TIMEOUT         Timeout in seconds (default: 10)
    -o OUTPUT          Output file to save results
    -v                 Verbose output (show all details)
    -j                 Output as JSON
    -s                 Show summary only
    -h                 Show this help message

Examples:
    $0 -d example.com
    $0 -d example.com -v
    $0 -d example.com -j -o results.json
    $0 -d example.com -s
EOF
}

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        -d) DOMAIN="$2"; shift 2 ;;
        -t) TIMEOUT="$2"; shift 2 ;;
        -o) OUTPUT_FILE="$2"; shift 2 ;;
        -v) VERBOSE=true; shift ;;
        -j) JSON_OUTPUT=true; shift ;;
        -s) SUMMARY_ONLY=true; shift ;;
        -h) show_help; exit 0 ;;
        *) print_error "Unknown option: $1"; show_help; exit 1 ;;
    esac
done

# Validate domain
if [[ -z "$DOMAIN" ]]; then
    print_error "Domain is required"
    show_help
    exit 1
fi

# Function to parse WHOIS data
parse_whois() {
    local domain=$1
    local whois_data
    
    # Perform WHOIS lookup
    whois_data=$(timeout "$TIMEOUT" whois "$domain" 2>/dev/null) || {
        print_error "WHOIS lookup failed or timed out"
        exit 1
    }
    
    # Extract key information
    registrar=$(echo "$whois_data" | grep -i "Registrar:" | head -1 | sed 's/Registrar:\s*//i')
    creation_date=$(echo "$whois_data" | grep -iE "Creation Date:|Created on:" | head -1 | sed -E 's/(Creation Date:|Created on:)//i' | xargs)
    expiration_date=$(echo "$whois_data" | grep -iE "Expiration Date:|Expiry Date:|Registry Expiry Date:" | head -1 | sed -E 's/(Expiration Date:|Expiry Date:|Registry Expiry Date:)//i' | xargs)
    updated_date=$(echo "$whois_data" | grep -iE "Updated Date:|Last Updated:" | head -1 | sed -E 's/(Updated Date:|Last Updated:)//i' | xargs)
    
    # Name servers
    name_servers=$(echo "$whois_data" | grep -i "Name Server:" | sed 's/Name Server:\s*//i' | head -5)
    
    # Status
    status=$(echo "$whois_data" | grep -i "Domain Status:" | sed 's/Domain Status:\s*//i' | head -3)
    
    # Contact information
    registrant_name=$(echo "$whois_data" | grep -i "Registrant Name:" | head -1 | sed 's/Registrant Name:\s*//i')
    registrant_org=$(echo "$whois_data" | grep -i "Registrant Organization:" | head -1 | sed 's/Registrant Organization:\s*//i')
    registrant_email=$(echo "$whois_data" | grep -i "Registrant Email:" | head -1 | sed 's/Registrant Email:\s*//i')
    registrant_phone=$(echo "$whois_data" | grep -i "Registrant Phone:" | head -1 | sed 's/Registrant Phone:\s*//i')
    
    # Store in associative array
    declare -gA WHOIS_DATA=(
        [domain]="$domain"
        [registrar]="$registrar"
        [creation_date]="$creation_date"
        [expiration_date]="$expiration_date"
        [updated_date]="$updated_date"
        [name_servers]="$name_servers"
        [status]="$status"
        [registrant_name]="$registrant_name"
        [registrant_org]="$registrant_org"
        [registrant_email]="$registrant_email"
        [registrant_phone]="$registrant_phone"
    )
    
    # Return raw data for JSON output
    echo "$whois_data"
}

# Function to check if domain expires soon
check_expiry() {
    local exp_date=$1
    local days=$2
    
    if [[ -z "$exp_date" ]]; then
        return 1
    fi
    
    # Convert date to timestamp (works on Linux and macOS)
    if date --version >/dev/null 2>&1; then
        # GNU date
        exp_timestamp=$(date -d "$exp_date" +%s 2>/dev/null) || return 1
    else
        # BSD date (macOS)
        exp_timestamp=$(date -j -f "%Y-%m-%d" "$exp_date" +%s 2>/dev/null) || return 1
    fi
    
    current_timestamp=$(date +%s)
    days_left=$(( (exp_timestamp - current_timestamp) / 86400 ))
    
    if [[ $days_left -ge 0 && $days_left -le $days ]]; then
        return 0
    else
        return 1
    fi
}

# Function to generate JSON output
generate_json() {
    cat << EOF
{
  "domain": "${WHOIS_DATA[domain]}",
  "registrar": "${WHOIS_DATA[registrar]}",
  "creation_date": "${WHOIS_DATA[creation_date]}",
  "expiration_date": "${WHOIS_DATA[expiration_date]}",
  "updated_date": "${WHOIS_DATA[updated_date]}",
  "name_servers": $(echo "${WHOIS_DATA[name_servers]}" | awk '{print "["; for(i=1;i<=NF;i++) printf "\"%s\",",$i; print "]"}'),
  "status": $(echo "${WHOIS_DATA[status]}" | awk '{print "["; for(i=1;i<=NF;i++) printf "\"%s\",",$i; print "]"}'),
  "registrant": {
    "name": "${WHOIS_DATA[registrant_name]}",
    "organization": "${WHOIS_DATA[registrant_org]}",
    "email": "${WHOIS_DATA[registrant_email]}",
    "phone": "${WHOIS_DATA[registrant_phone]}"
  }
}
EOF
}

# Main execution
main() {
    print_info "Performing WHOIS lookup for: $DOMAIN"
    
    # Perform lookup
    raw_data=$(parse_whois "$DOMAIN")
    
    # Output based on flags
    if [[ "$JSON_OUTPUT" == true ]]; then
        generate_json
    elif [[ "$SUMMARY_ONLY" == true ]]; then
        cat << EOF
{
  "domain": "${WHOIS_DATA[domain]}",
  "registrar": "${WHOIS_DATA[registrar]}",
  "creation_date": "${WHOIS_DATA[creation_date]}",
  "expiration_date": "${WHOIS_DATA[expiration_date]}",
  "name_servers": "$(echo "${WHOIS_DATA[name_servers]}" | tr '\n' ',' | sed 's/,$//')",
  "registrant_org": "${WHOIS_DATA[registrant_org]}",
  "status": "$(echo "${WHOIS_DATA[status]}" | head -1)"
}
EOF
    else
        # Pretty print
        echo ""
        echo "============================================================"
        echo "WHOIS Lookup Results for: $DOMAIN"
        echo "============================================================"
        echo ""
        
        if [[ "$VERBOSE" == true ]]; then
            echo "$raw_data"
        else
            echo "Registrar:        ${WHOIS_DATA[registrar]:-N/A}"
            echo "Created:          ${WHOIS_DATA[creation_date]:-N/A}"
            echo "Expires:          ${WHOIS_DATA[expiration_date]:-N/A}"
            echo "Updated:          ${WHOIS_DATA[updated_date]:-N/A}"
            echo ""
            echo "Name Servers:"
            if [[ -n "${WHOIS_DATA[name_servers]}" ]]; then
                echo "${WHOIS_DATA[name_servers]}" | while read ns; do
                    echo "  - $ns"
                done
            else
                echo "  N/A"
            fi
            echo ""
            echo "Domain Status:"
            if [[ -n "${WHOIS_DATA[status]}" ]]; then
                echo "${WHOIS_DATA[status]}" | while read st; do
                    echo "  - $st"
                done
            else
                echo "  N/A"
            fi
            echo ""
            echo "Registrant Contact:"
            echo "  Name:         ${WHOIS_DATA[registrant_name]:-N/A}"
            echo "  Organization: ${WHOIS_DATA[registrant_org]:-N/A}"
            echo "  Email:        ${WHOIS_DATA[registrant_email]:-N/A}"
            echo "  Phone:        ${WHOIS_DATA[registrant_phone]:-N/A}"
            
            # Check expiry warning
            if check_expiry "${WHOIS_DATA[expiration_date]}" 30; then
                echo ""
                print_warning "Domain expires within 30 days!"
            fi
        fi
        
        echo ""
        echo "============================================================"
        echo ""
    fi
    
    # Save to file
    if [[ -n "$OUTPUT_FILE" ]]; then
        if [[ "$JSON_OUTPUT" == true ]]; then
            generate_json > "$OUTPUT_FILE"
        else
            {
                echo "WHOIS Lookup Results for: $DOMAIN"
                echo "Generated: $(date)"
                echo ""
                echo "$raw_data"
            } > "$OUTPUT_FILE"
        fi
        print_success "Results saved to $OUTPUT_FILE"
    fi
}

# Check dependencies
check_dependencies() {
    if ! command -v whois >/dev/null 2>&1; then
        print_error "whois command not found. Please install whois package."
        exit 1
    fi
}

# Run
check_dependencies
main
