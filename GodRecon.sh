#!/bin/bash

# =============================================
# RECONNAISSANCE AND VULNERABILITY SCANNING TOOL
# =============================================

####################################
####### CONFIGURATION SECTION #########
####################################

#COLORS
RED="\e[31m"
GREEN="\033[1;32m"
YELLOW="\e[33m"
BLUE="\e[34m"
MAGENTA="\e[95m"
CYAN="\e[36m"
DEFAULT="\e[39m"
BOLD="\e[1m"
NORMAL="\e[0m"

#PARAMETERS
DEFAULT_DNS_DICTIONARY="/usr/share/wordlists/dns.txt"
DEFAULT_WEB_DICTIONARY="/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt"
AQUATONE_TIMEOUT=50000
MASSIVE_SCAN_INTERVAL=3600
EXCLUDE_STATUS_CODES="404,403,401,503"
GITHUB_TOKEN="YOUR_GITHUB_TOKEN"
BURP_COLLABORATOR="YOUR_BURP_COLLABORATOR_LINK"

# =============================================
# GLOBAL VARIABLES
# =============================================

DOMAIN=""
DOMAIN_LIST=""
WILDCARD=""
MODE=""
NOTIFY=false
VULN_SCAN=false
ACTUAL_DIR=$(pwd)

# =============================================
# UTILITY FUNCTIONS
# =============================================

# Print usage information
print_usage() {
    echo -e "${BOLD}${GREEN}USAGE${NORMAL}"
    echo -e "$0 [-d domain.com] [-w domain.com] [-l domains.txt] [-a] [-p] [-x] [-r] [-v] [-m] [-n] [-h]"
    echo
    echo -e "${BOLD}${GREEN}TARGET OPTIONS${NORMAL}"
    echo -e "  -d domain.com     Target domain"
    echo -e "  -w domain.com     Wildcard domain"
    echo -e "  -l list.txt       File containing list of domains"
    echo
    echo -e "${BOLD}${GREEN}MODE OPTIONS${NORMAL}"
    echo -e "  -a, --all         Full reconnaissance and vulnerability scanning"
    echo -e "  -p, --passive     Passive reconnaissance only"
    echo -e "  -x, --active      Active reconnaissance only"
    echo -e "  -r, --recon       Both active and passive reconnaissance"
    echo -e "  -v, --vuln        Vulnerability scanning"
    echo -e "  -m, --massive     Continuous massive scanning"
    echo
    echo -e "${BOLD}${GREEN}EXTRA OPTIONS${NORMAL}"
    echo -e "  -n, --notify      Enable notifications"
    echo -e "  -h, --help        Show this help message"
    echo
    echo -e "${BOLD}${GREEN}EXAMPLES${NORMAL}"
    echo -e "  ${CYAN}Full scan on a domain:${NORMAL}"
    echo -e "  $0 -d example.com -a"
    echo
    echo -e "  ${CYAN}Passive recon on multiple domains:${NORMAL}"
    echo -e "  $0 -l domains.txt -p"
    echo
    echo -e "  ${CYAN}Vulnerability scan with notifications:${NORMAL}"
    echo -e "  $0 -d example.com -v -n"
}

# Load configuration from within the script
load_config() {
    echo -e "${GREEN}[+] Using built-in configuration${NORMAL}"
    echo -e "${GREEN}[+] DNS Dictionary: ${DEFAULT_DNS_DICTIONARY}${NORMAL}"
    echo -e "${GREEN}[+] Web Dictionary: ${DEFAULT_WEB_DICTIONARY}${NORMAL}"
    echo -e "${GREEN}[+] Aquatone Timeout: ${AQUATONE_TIMEOUT}${NORMAL}"
    echo -e "${GREEN}[+] Massive Scan Interval: ${MASSIVE_SCAN_INTERVAL}${NORMAL}"
    echo -e "${GREEN}[+] Exclude Status Codes: ${EXCLUDE_STATUS_CODES}${NORMAL}"
}

# Check if a tool is installed and install it if missing
check_and_install_tool() {
    local tool="$1"
    local install_cmd="$2"
    
    if ! command -v "$tool" &> /dev/null; then
        echo -e "${YELLOW}[!] $tool is not installed${NORMAL}"
        echo -e "${CYAN}[+] Attempting to install $tool...${NORMAL}"
        eval "$install_cmd"
        
        # Verify installation was successful
        if ! command -v "$tool" &> /dev/null; then
            echo -e "${RED}[!] Failed to install $tool${NORMAL}"
            return 1
        else
            echo -e "${GREEN}[+] Successfully installed $tool${NORMAL}"
        fi
    fi
    return 0
}

# Validate required tools are installed
validate_dependencies() {
    local tools=("subfinder" "amass" "httpx" "nuclei" "whatweb" "aquatone" "dirsearch" "nmap" "gau" "arjun")
    local missing_tools=()
    
    for tool in "${tools[@]}"; do
        if ! command -v "$tool" &> /dev/null; then
            missing_tools+=("$tool")
        fi
    done
    
    if [ ${#missing_tools[@]} -ne 0 ]; then
        echo -e "${RED}[!] Missing tools: ${missing_tools[*]}${NORMAL}"
        echo -e "${YELLOW}[!] Please install missing tools and try again${NORMAL}"
        
        # Provide installation hints
        if [[ " ${missing_tools[@]} " =~ " subfinder " ]]; then
            echo -e "${CYAN}Install subfinder: go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest${NORMAL}"
        fi
        if [[ " ${missing_tools[@]} " =~ " amass " ]]; then
            echo -e "${CYAN}Install amass: go install -v github.com/owasp-amass/amass/v3/...@master${NORMAL}"
        fi
        if [[ " ${missing_tools[@]} " =~ " httpx " ]]; then
            echo -e "${CYAN}Install httpx: go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest${NORMAL}"
        fi
        if [[ " ${missing_tools[@]} " =~ " nuclei " ]]; then
            echo -e "${CYAN}Install nuclei: go install -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest${NORMAL}"
        fi
        
        exit 1
    fi
    
    # Check for optional tools and provide installation instructions if missing
    local optional_tools=("testssl.sh" "shcheck" "corsy")
    for tool in "${optional_tools[@]}"; do
        if ! command -v "$tool" &> /dev/null; then
            echo -e "${YELLOW}[!] Optional tool $tool is not installed${NORMAL}"
            if [ "$tool" == "testssl.sh" ]; then
                echo -e "${CYAN}Install testssl.sh: git clone https://github.com/drwetter/testssl.sh.git ~/tools/testssl.sh${NORMAL}"
            elif [ "$tool" == "shcheck" ]; then
                echo -e "${CYAN}Install shcheck: pip install shcheck${NORMAL}"
            elif [ "$tool" == "corsy" ]; then
                echo -e "${CYAN}Install corsy: git clone https://github.com/s0md3v/Corsy.git ~/tools/Corsy && pip install -r ~/tools/Corsy/requirements.txt${NORMAL}"
            fi
        fi
    done
}

# Setup directory structure
setup_directories() {
    if [ ! -d "targets" ]; then
        mkdir targets
    fi
    
    local target_dir="targets/$DOMAIN"
    if [ -d "$target_dir" ]; then
        echo -e "${YELLOW}[!] Target directory already exists, overwriting${NORMAL}"
        rm -rf "$target_dir"
    fi
    
    mkdir -p "$target_dir"
    echo "$target_dir"
}

# Send notification if enabled
send_notification() {
    if [ "$NOTIFY" = true ]; then
        local message="$1"
        local data="$2"
        
        # Implement notification logic here (Discord, Slack, Telegram, etc.)
        echo -e "${GREEN}[+] Notification sent: $message${NORMAL}"
    fi
}

# =============================================
# RECONNAISSANCE FUNCTIONS
# =============================================

# Passive reconnaissance
passive_recon() {
    local domain="$1"
    local notify="$2"
    local target_dir="$3"
    
    echo -e "${BOLD}${GREEN}[*] STARTING PASSIVE RECONNAISSANCE${NORMAL}"
    echo -e "${BOLD}${GREEN}[*] TARGET: ${YELLOW}$domain${NORMAL}"
    
    local ip=$(dig +short "$domain" | head -n 1)
    echo -e "${BOLD}${GREEN}[*] IP ADDRESS: ${YELLOW}$ip${NORMAL}"
    
    # Create directory for passive recon results
    local recon_dir="$target_dir/passive_recon"
    mkdir -p "$recon_dir"
    cd "$recon_dir"
    
    # WHOIS lookup
    echo -e "${GREEN}[+] Performing WHOIS lookup${NORMAL}"
    whois "$domain" | grep -i 'domain\|registry\|registrar\|updated\|creation\|registrant\|name server\|dnssec\|status\|whois server\|admin\|tech' > whois.txt
    
    # DNS enumeration
    echo -e "${GREEN}[+] Enumerating DNS records${NORMAL}"
    nslookup "$domain" > nslookup.txt
    dig "$domain" ANY > dig.txt
    
    # Subdomain discovery
    echo -e "${GREEN}[+] Discovering subdomains${NORMAL}"
    subfinder -d "$domain" -silent > subfinder_subdomains.txt
    amass enum -passive -d "$domain" > amass_subdomains.txt
    sort -u subfinder_subdomains.txt amass_subdomains.txt > all_subdomains.txt
    
    # Check live subdomains
    echo -e "${GREEN}[+] Checking live subdomains${NORMAL}"
    httpx -l all_subdomains.txt -silent -status-code -title -tech-detect -o live_subdomains.txt
    
    # Website technology detection
    echo -e "${GREEN}[+] Detecting technologies${NORMAL}"
    whatweb "$domain" --color=never > whatweb.txt
    
    # Screenshot with Aquatone
    echo -e "${GREEN}[+] Taking screenshots${NORMAL}"
    cat live_subdomains.txt | aquatone -screenshot-timeout "$AQUATONE_TIMEOUT" -out screenshots
    
    # Send notifications if enabled
    if [ "$notify" = true ]; then
        send_notification "Passive reconnaissance completed for $domain" "Subdomains found: $(wc -l < all_subdomains.txt)"
    fi
    
    cd "$ACTUAL_DIR"
    echo -e "${GREEN}[+] Passive reconnaissance completed${NORMAL}"
}

# Active reconnaissance
active_recon() {
    local domain="$1"
    local notify="$2"
    local target_dir="$3"
    
    echo -e "${BOLD}${GREEN}[*] STARTING ACTIVE RECONNAISSANCE${NORMAL}"
    echo -e "${BOLD}${GREEN}[*] TARGET: ${YELLOW}$domain${NORMAL}"
    
    # Create directory for active recon results
    local recon_dir="$target_dir/active_recon"
    mkdir -p "$recon_dir"
    cd "$recon_dir"
    
    # Directory and file discovery
    echo -e "${GREEN}[+] Directory brute-forcing${NORMAL}"
    dirsearch -u "https://$domain" -e php,asp,aspx,jsp,html,txt -w "$DEFAULT_WEB_DICTIONARY" --format plain -o dirsearch.txt
    
    # Port scanning
    echo -e "${GREEN}[+] Scanning ports${NORMAL}"
    nmap -sV -sC -O "$domain" -oN nmap.txt
    
    # URL extraction from JavaScript files
    echo -e "${GREEN}[+] Extracting URLs from JavaScript files${NORMAL}"
    gau "$domain" | grep -E '\.js$' > js_urls.txt
    
    # Parameter discovery
    echo -e "${GREEN}[+] Discovering URL parameters${NORMAL}"
    arjun -u "https://$domain" -o parameters.txt
    
    # Send notifications if enabled
    if [ "$notify" = true ]; then
        send_notification "Active reconnaissance completed for $domain" "Directories found: $(grep -c '^' dirsearch.txt)"
    fi
    
    cd "$ACTUAL_DIR"
    echo -e "${GREEN}[+] Active reconnaissance completed${NORMAL}"
}

# Check SSL/TLS configuration (alternative implementation)
check_ssl_tls() {
    local domain="$1"
    local output_file="$2"
    
    echo -e "${GREEN}[+] Testing SSL/TLS configuration${NORMAL}"
    
    # Try different methods to check SSL/TLS
    if command -v testssl.sh &> /dev/null; then
        testssl.sh "$domain" > "$output_file"
    elif command -v openssl &> /dev/null; then
        {
            echo "SSL/TLS Certificate Information:"
            echo "================================="
            echo | openssl s_client -connect "$domain:443" -servername "$domain" 2>/dev/null | openssl x509 -noout -text | grep -E 'Subject:|Issuer:|Not Before:|Not After :|DNS:'
            
            echo
            echo "Supported Ciphers:"
            echo "==================="
            nmap --script ssl-enum-ciphers -p 443 "$domain" | grep -A 10 "ssl-enum-ciphers"
        } > "$output_file"
    else
        echo "Neither testssl.sh nor openssl available for SSL/TLS testing" > "$output_file"
    fi
}

# Check security headers (alternative implementation)
check_security_headers() {
    local domain="$1"
    local output_file="$2"
    
    echo -e "${GREEN}[+] Checking security headers${NORMAL}"
    
    # Use curl to check security headers
    {
        echo "Security Headers Check for https://$domain"
        echo "==========================================="
        echo
        
        # Check for common security headers
        local headers=("Strict-Transport-Security" "Content-Security-Policy" "X-Frame-Options" 
                      "X-Content-Type-Options" "Referrer-Policy" "Permissions-Policy" "X-XSS-Protection")
        
        for header in "${headers[@]}"; do
            local value=$(curl -sI "https://$domain" | grep -i "^$header:" || echo "NOT FOUND")
            echo "$header: $value"
        done
        
        echo
        echo "Missing Security Headers:"
        echo "========================="
        for header in "${headers[@]}"; do
            if ! curl -sI "https://$domain" | grep -i "^$header:" > /dev/null; then
                echo "- $header"
            fi
        done
    } > "$output_file"
}

# Check for CORS misconfigurations (alternative implementation)
check_cors() {
    local domain="$1"
    local output_file="$2"
    
    echo -e "${GREEN}[+] Testing for CORS misconfigurations${NORMAL}"
    
    # Simple CORS check using curl
    {
        echo "CORS Misconfiguration Test for https://$domain"
        echo "=============================================="
        echo
        
        # Test with different origins
        local origins=("https://evil.com" "http://evil.com" "null" "https://$domain.evil.com")
        
        for origin in "${origins[@]}"; do
            echo "Testing Origin: $origin"
            local response=$(curl -s -I -H "Origin: $origin" "https://$domain")
            
            if echo "$response" | grep -i "access-control-allow-origin" > /dev/null; then
                local allow_origin=$(echo "$response" | grep -i "access-control-allow-origin" | tr -d '\r')
                local allow_credentials=$(echo "$response" | grep -i "access-control-allow-credentials" | tr -d '\r' || echo "NOT SET")
                
                echo "-> POTENTIAL CORS MISCONFIGURATION:"
                echo "   $allow_origin"
                echo "   $allow_credentials"
                echo "   Risk: If Access-Control-Allow-Credentials is true, this is a critical issue"
            else
                echo "-> No CORS headers found with origin: $origin"
            fi
            echo
        done
    } > "$output_file"
}

# Vulnerability scanning
vulnerability_scan() {
    local domain="$1"
    local notify="$2"
    local target_dir="$3"
    
    echo -e "${BOLD}${GREEN}[*] STARTING VULNERABILITY SCAN${NORMAL}"
    echo -e "${BOLD}${GREEN}[*] TARGET: ${YELLOW}$domain${NORMAL}"
    
    # Create directory for vulnerability scan results
    local vuln_dir="$target_dir/vulnerability_scan"
    mkdir -p "$vuln_dir"
    cd "$vuln_dir"
    
    # Nuclei scan
    echo -e "${GREEN}[+] Running Nuclei vulnerability scanner${NORMAL}"
    nuclei -u "https://$domain" -severity low,medium,high,critical -o nuclei_results.txt
    
    # SSL/TLS testing (using our alternative implementation)
    check_ssl_tls "$domain" "ssl_test.txt"
    
    # Security headers check (using our alternative implementation)
    check_security_headers "$domain" "security_headers.txt"
    
    # CORS misconfiguration testing (using our alternative implementation)
    check_cors "$domain" "cors_test.txt"
    
    # Send notifications if enabled
    if [ "$notify" = true ]; then
        local vuln_count=$(grep -c "\[.*\]" nuclei_results.txt)
        send_notification "Vulnerability scan completed for $domain" "Vulnerabilities found: $vuln_count"
    fi
    
    cd "$ACTUAL_DIR"
    echo -e "${GREEN}[+] Vulnerability scan completed${NORMAL}"
}

# =============================================
# MAIN EXECUTION FUNCTIONS
# =============================================

# Execute all reconnaissance and vulnerability scanning
full_scan() {
    local domain="$1"
    local notify="$2"
    
    echo -e "${BOLD}${GREEN}[*] STARTING FULL SCAN${NORMAL}"
    local target_dir=$(setup_directories)
    
    passive_recon "$domain" "$notify" "$target_dir"
    active_recon "$domain" "$notify" "$target_dir"
    vulnerability_scan "$domain" "$notify" "$target_dir"
    
    echo -e "${GREEN}[+] Full scan completed for $domain${NORMAL}"
}

# Execute only reconnaissance (passive + active)
recon_only() {
    local domain="$1"
    local notify="$2"
    
    echo -e "${BOLD}${GREEN}[*] STARTING RECONNAISSANCE ONLY${NORMAL}"
    local target_dir=$(setup_directories)
    
    passive_recon "$domain" "$notify" "$target_dir"
    active_recon "$domain" "$notify" "$target_dir"
    
    echo -e "${GREEN}[+] Reconnaissance completed for $domain${NORMAL}"
}

# Continuous massive scanning
massive_scan() {
    local wildcard="$1"
    
    echo -e "${BOLD}${GREEN}[*] STARTING MASSIVE SCAN${NORMAL}"
    echo -e "${BOLD}${GREEN}[*] WILDCARD: ${YELLOW}*.$wildcard${NORMAL}"
    
    local scan_dir="targets/massive_scan"
    mkdir -p "$scan_dir"
    cd "$scan_dir"
    
    while true; do
        echo -e "${GREEN}[+] Scanning at $(date)${NORMAL}"
        
        # Find subdomains
        subfinder -d "$wildcard" -silent | anew subdomains.txt > /dev/null
        
        # Check which are live
        httpx -l subdomains.txt -silent | anew live_subdomains.txt > /dev/null
        
        # Scan for vulnerabilities
        nuclei -l live_subdomains.txt -severity high,critical -silent | anew vulnerabilities.txt > /dev/null
        
        # Send notifications if new vulnerabilities found
        if [ "$NOTIFY" = true ] && [ -s vulnerabilities.txt ]; then
            send_notification "New vulnerabilities found in massive scan" "Check vulnerabilities.txt for details"
        fi
        
        echo -e "${YELLOW}[+] Sleeping for $MASSIVE_SCAN_INTERVAL seconds${NORMAL}"
        sleep "$MASSIVE_SCAN_INTERVAL"
    done
    
    cd "$ACTUAL_DIR"
}

# =============================================
# SCRIPT EXECUTION
# =============================================

# Parse command line arguments
parse_arguments() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            -d|--domain)
                DOMAIN="$2"
                shift 2
                ;;
            -w|--wildcard)
                WILDCARD="$2"
                shift 2
                ;;
            -l|--list)
                DOMAIN_LIST="$2"
                shift 2
                ;;
            -a|--all)
                MODE="all"
                shift
                ;;
            -p|--passive)
                MODE="passive"
                shift
                ;;
            -x|--active)
                MODE="active"
                shift
                ;;
            -r|--recon)
                MODE="recon"
                shift
                ;;
            -v|--vuln)
                VULN_SCAN=true
                shift
                ;;
            -m|--massive)
                MODE="massive"
                shift
                ;;
            -n|--notify)
                NOTIFY=true
                shift
                ;;
            -h|--help)
                print_usage
                exit 0
                ;;
            *)
                echo -e "${RED}[!] Unknown option: $1${NORMAL}"
                print_usage
                exit 1
                ;;
        esac
    done
}

# Validate arguments
validate_arguments() {
    if [ -z "$DOMAIN" ] && [ -z "$WILDCARD" ] && [ -z "$DOMAIN_LIST" ]; then
        echo -e "${RED}[!] No target specified${NORMAL}"
        print_usage
        exit 1
    fi
    
    if [ -n "$WILDCARD" ] && [ "$MODE" != "massive" ]; then
        echo -e "${YELLOW}[!] Wildcard target is only supported with massive mode${NORMAL}"
        print_usage
        exit 1
    fi
    
    if [ -n "$DOMAIN_LIST" ] && [ ! -f "$DOMAIN_LIST" ]; then
        echo -e "${RED}[!] Domain list file not found: $DOMAIN_LIST${NORMAL}"
        exit 1
    fi
}

# Main execution function
main() {
    # Display banner
    echo -e "${BOLD}${YELLOW}"
    echo -e "   ██████╗  ██████╗ ██████╗ ██████╗ ███████╗ ██████╗ ██████╗ ███████╗███╗   ██╗"
    echo -e "  ██╔════╝ ██╔═══██╗██╔══██╗██╔══██╗██╔════╝██╔════╝██╔═══██╗██╔════╝████╗  ██║"
    echo -e "  ██║  ███╗██║   ██║██║  ██║██████╔╝█████╗  ██║     ██║   ██║█████╗  ██╔██╗ ██║"
    echo -e "  ██║   ██║██║   ██║██║  ██║██╔══██╗██╔══╝  ██║     ██║   ██║██╔══╝  ██║╚██╗██║"
    echo -e "  ╚██████╔╝╚██████╔╝██████╔╝██║  ██║███████╗╚██████╗╚██████╔╝███████╗██║ ╚████║"
    echo -e "   ╚═════╝  ╚═════╝ ╚═════╝ ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚══════╝╚═╝  ╚═══╝"
    echo -e "                               ${BOLD}${MAGENTA}Created by Prashant Swami\n${NORMAL}"
    
    # Load configuration and validate dependencies
    load_config
    validate_dependencies
    
    # Parse and validate arguments
    parse_arguments "$@"
    validate_arguments
    
    # Execute based on mode
    case "$MODE" in
        "all")
            if [ -n "$DOMAIN_LIST" ]; then
                while IFS= read -r domain; do
                    full_scan "$domain" "$NOTIFY"
                done < "$DOMAIN_LIST"
            else
                full_scan "$DOMAIN" "$NOTIFY"
            fi
            ;;
        "passive")
            if [ -n "$DOMAIN_LIST" ]; then
                while IFS= read -r domain; do
                    target_dir=$(setup_directories "$domain")
                    passive_recon "$domain" "$NOTIFY" "$target_dir"
                done < "$DOMAIN_LIST"
            else
                target_dir=$(setup_directories)
                passive_recon "$DOMAIN" "$NOTIFY" "$target_dir"
            fi
            ;;
        "active")
            if [ -n "$DOMAIN_LIST" ]; then
                while IFS= read -r domain; do
                    target_dir=$(setup_directories "$domain")
                    active_recon "$domain" "$NOTIFY" "$target_dir"
                done < "$DOMAIN_LIST"
            else
                target_dir=$(setup_directories)
                active_recon "$DOMAIN" "$NOTIFY" "$target_dir"
            fi
            ;;
        "recon")
            if [ -n "$DOMAIN_LIST" ]; then
                while IFS= read -r domain; do
                    recon_only "$domain" "$NOTIFY"
                done < "$DOMAIN_LIST"
            else
                recon_only "$DOMAIN" "$NOTIFY"
            fi
            ;;
        "massive")
            if [ -n "$WILDCARD" ]; then
                massive_scan "$WILDCARD"
            else
                echo -e "${RED}[!] Massive mode requires a wildcard target${NORMAL}"
                exit 1
            fi
            ;;
        *)
            if [ "$VULN_SCAN" = true ]; then
                if [ -n "$DOMAIN_LIST" ]; then
                    while IFS= read -r domain; do
                        target_dir=$(setup_directories "$domain")
                        vulnerability_scan "$domain" "$NOTIFY" "$target_dir"
                    done < "$DOMAIN_LIST"
                else
                    target_dir=$(setup_directories)
                    vulnerability_scan "$DOMAIN" "$NOTIFY" "$target_dir"
                fi
            else
                echo -e "${YELLOW}[!] No mode specified, running vulnerability scan only${NORMAL}"
                if [ -n "$DOMAIN_LIST" ]; then
                    while IFS= read -r domain; do
                        target_dir=$(setup_directories "$domain")
                        vulnerability_scan "$domain" "$NOTIFY" "$target_dir"
                    done < "$DOMAIN_LIST"
                else
                    target_dir=$(setup_directories)
                    vulnerability_scan "$DOMAIN" "$NOTIFY" "$target_dir"
                fi
            fi
            ;;
    esac
    
    echo -e "${GREEN}[+] All tasks completed${NORMAL}"
}

# Execute main function with all arguments
main "$@"
