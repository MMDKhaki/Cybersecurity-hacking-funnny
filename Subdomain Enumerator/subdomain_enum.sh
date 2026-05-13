#!/bin/bash

# Subdomain Enumerator - Bash Implementation
# Combines DNS brute-forcing with API lookups

set -e

# Color codes
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Default values
THREADS=50
WORDLIST=""
DOMAIN=""
OUTPUT_FILE=""
SECURITYTRAILS_KEY=""
VIRUSTOTAL_KEY=""

# Temp files for parallel processing
TEMP_DIR=$(mktemp -d)
trap "rm -rf $TEMP_DIR" EXIT

# Function to print colored output
print_info() { echo -e "${BLUE}[*]${NC} $1"; }
print_success() { echo -e "${GREEN}[+]${NC} $1"; }
print_error() { echo -e "${RED}[!]${NC} $1"; }
print_found() { echo -e "${GREEN}[FOUND]${NC} $1"; }

# Help function
show_help() {
    cat << EOF
Subdomain Enumerator - Bash Version

Usage: $0 -d DOMAIN [OPTIONS]

Required:
    -d DOMAIN          Target domain (e.g., example.com)

Options:
    -w WORDLIST        Custom wordlist file (one subdomain per line)
    -t THREADS         Number of threads for parallel processing (default: 50)
    -o OUTPUT          Output file to save results
    --st-api KEY       SecurityTrails API key
    --vt-api KEY       VirusTotal API key
    -h                 Show this help message

Examples:
    $0 -d example.com
    $0 -d example.com -w subdomains.txt -t 100
    $0 -d example.com --st-api YOUR_API_KEY
EOF
}

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        -d) DOMAIN="$2"; shift 2 ;;
        -w) WORDLIST="$2"; shift 2 ;;
        -t) THREADS="$2"; shift 2 ;;
        -o) OUTPUT_FILE="$2"; shift 2 ;;
        --st-api) SECURITYTRAILS_KEY="$2"; shift 2 ;;
        --vt-api) VIRUSTOTAL_KEY="$2"; shift 2 ;;
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

# Default wordlist (embedded)
DEFAULT_WORDLIST=(
    "www" "mail" "ftp" "localhost" "webmail" "smtp" "pop" "ns1"
    "ns2" "cpanel" "whm" "test" "dev" "admin" "blog" "vpn" "api"
    "cdn" "stage" "secure" "portal" "dashboard" "stats" "media"
    "static" "img" "images" "download" "docs" "wiki" "forum"
)

# Load wordlist
load_wordlist() {
    local wordlist_file=$1
    local temp_wordlist="$TEMP_DIR/wordlist.txt"
    
    if [[ -n "$wordlist_file" && -f "$wordlist_file" ]]; then
        # Remove comments and empty lines
        grep -v '^#' "$wordlist_file" | grep -v '^$' > "$temp_wordlist"
        print_info "Loaded $(wc -l < "$temp_wordlist") subdomains from $wordlist_file"
    else
        # Use default wordlist
        printf "%s\n" "${DEFAULT_WORDLIST[@]}" > "$temp_wordlist"
        print_info "Using default wordlist with ${#DEFAULT_WORDLIST[@]} entries"
        if [[ -n "$wordlist_file" ]]; then
            print_error "Wordlist file not found: $wordlist_file"
        fi
    fi
    
    echo "$temp_wordlist"
}

# DNS resolution function
resolve_dns() {
    local subdomain=$1
    local domain=$2
    local target="${subdomain}.${domain}"
    
    # Try to resolve A record
    local ip=$(dig +short +timeout=2 +tries=1 "$target" A 2>/dev/null | head -1)
    
    if [[ -n "$ip" && "$ip" != *":"* ]]; then
        echo "$target -> $ip"
        return 0
    fi
    return 1
}

export -f resolve_dns

# DNS brute-force using parallel
dns_bruteforce() {
    local wordlist=$1
    local domain=$2
    local threads=$3
    local results_file="$TEMP_DIR/dns_results.txt"
    
    print_info "Starting DNS brute-force with $threads threads..."
    
    # Use parallel for concurrent resolution
    if command -v parallel >/dev/null 2>&1; then
        cat "$wordlist" | parallel -j "$threads" --bar "resolve_dns {} $domain" > "$results_file" 2>/dev/null
    else
        # Fallback to xargs if parallel not available
        cat "$wordlist" | xargs -P "$threads" -I {} bash -c "resolve_dns {} $domain" > "$results_file" 2>/dev/null
    fi
    
    # Extract subdomains from results
    cut -d' ' -f1 "$results_file" >> "$TEMP_DIR/all_subdomains.txt"
    
    local found=$(wc -l < "$results_file")
    print_success "DNS brute-force found $found subdomains"
    
    # Display results
    if [[ -s "$results_file" ]]; then
        while IFS= read -r line; do
            print_found "$line"
        done < "$results_file"
    fi
}

# SecurityTrails API
api_securitytrails() {
    local domain=$1
    local api_key=$2
    local output="$TEMP_DIR/securitytrails.txt"
    
    if [[ -z "$api_key" ]]; then
        return
    fi
    
    print_info "Querying SecurityTrails API..."
    
    local url="https://api.securitytrails.com/v1/domain/${domain}/subdomains"
    local response=$(curl -s -f -H "APIKEY: $api_key" "$url" 2>/dev/null) || return
    
    if [[ -n "$response" ]]; then
        echo "$response" | jq -r '.subdomains[]' 2>/dev/null | while read sub; do
            if [[ -n "$sub" ]]; then
                echo "${sub}.${domain}" >> "$output"
                print_found "[SecurityTrails] ${sub}.${domain}"
            fi
        done
    fi
}

# VirusTotal API
api_virustotal() {
    local domain=$1
    local api_key=$2
    local output="$TEMP_DIR/virustotal.txt"
    
    if [[ -z "$api_key" ]]; then
        return
    fi
    
    print_info "Querying VirusTotal API..."
    
    local url="https://www.virustotal.com/api/v3/domains/${domain}/subdomains"
    local response=$(curl -s -f -H "x-apikey: $api_key" "$url" 2>/dev/null) || return
    
    if [[ -n "$response" ]]; then
        echo "$response" | jq -r '.data[].id' 2>/dev/null | while read sub; do
            if [[ -n "$sub" && "$sub" == *".$domain" ]]; then
                echo "$sub" >> "$output"
                print_found "[VirusTotal] $sub"
            fi
        done
    fi
}

# Query Certificate Transparency logs (Bonus feature)
api_crt_sh() {
    local domain=$1
    local output="$TEMP_DIR/crtsh.txt"
    
    print_info "Querying crt.sh certificate logs..."
    
    local url="https://crt.sh/?q=%.${domain}&output=json"
    local response=$(curl -s -f "$url" 2>/dev/null) || return
    
    if [[ -n "$response" ]]; then
        echo "$response" | jq -r '.[].name_value' 2>/dev/null | \
            grep -i "\\.${domain}$" | \
            sort -u | \
            while read sub; do
                if [[ -n "$sub" ]]; then
                    echo "$sub" >> "$output"
                    print_found "[crt.sh] $sub"
                fi
            done
    fi
}

# Main enumeration function
main() {
    print_info "Starting subdomain enumeration for: $DOMAIN"
    
    # Create results directory
    mkdir -p "$TEMP_DIR"
    
    # Load wordlist
    WORDLIST_FILE=$(load_wordlist "$WORDLIST")
    
    # Initialize results file
    ALL_RESULTS="$TEMP_DIR/all_subdomains.txt"
    > "$ALL_RESULTS"
    
    # Query APIs
    print_info "Querying external APIs..."
    
    # Run APIs in parallel
    api_securitytrails "$DOMAIN" "$SECURITYTRAILS_KEY" &
    api_virustotal "$DOMAIN" "$VIRUSTOTAL_KEY" &
    api_crt_sh "$DOMAIN" &
    
    wait
    
    # Collect API results
    if [[ -f "$TEMP_DIR/securitytrails.txt" ]]; then
        cat "$TEMP_DIR/securitytrails.txt" >> "$ALL_RESULTS"
    fi
    if [[ -f "$TEMP_DIR/virustotal.txt" ]]; then
        cat "$TEMP_DIR/virustotal.txt" >> "$ALL_RESULTS"
    fi
    if [[ -f "$TEMP_DIR/crtsh.txt" ]]; then
        cat "$TEMP_DIR/crtsh.txt" >> "$ALL_RESULTS"
    fi
    
    # DNS brute-force
    dns_bruteforce "$WORDLIST_FILE" "$DOMAIN" "$THREADS"
    
    # Collect DNS results
    if [[ -f "$TEMP_DIR/dns_results.txt" ]]; then
        cut -d' ' -f1 "$TEMP_DIR/dns_results.txt" >> "$ALL_RESULTS"
    fi
    
    # Deduplicate results
    sort -u "$ALL_RESULTS" -o "$ALL_RESULTS"
    local total=$(wc -l < "$ALL_RESULTS")
    
    # Final summary
    echo ""
    print_success "Enumeration complete! Found $total unique subdomains"
    
    if [[ $total -gt 0 ]]; then
        echo ""
        print_info "Subdomains found:"
        cat "$ALL_RESULTS" | while read sub; do
            echo "  - $sub"
        done
        
        # Save to output file if specified
        if [[ -n "$OUTPUT_FILE" ]]; then
            cp "$ALL_RESULTS" "$OUTPUT_FILE"
            print_success "Results saved to $OUTPUT_FILE"
        fi
    else
        print_error "No subdomains found"
    fi
}

# Check dependencies
check_dependencies() {
    local deps=("dig" "curl")
    local missing=()
    
    for dep in "${deps[@]}"; do
        if ! command -v "$dep" >/dev/null 2>&1; then
            missing+=("$dep")
        fi
    done
    
    # jq is optional but recommended
    if ! command -v jq >/dev/null 2>&1; then
        print_info "jq not installed (optional for API parsing)"
    fi
    
    # parallel is optional but recommended for performance
    if ! command -v parallel >/dev/null 2>&1 && ! command -v xargs >/dev/null 2>&1; then
        print_error "Neither parallel nor xargs found. Please install one of them."
        exit 1
    fi
    
    if [[ ${#missing[@]} -gt 0 ]]; then
        print_error "Missing required dependencies: ${missing[*]}"
        exit 1
    fi
}

# Run main function
check_dependencies
main
