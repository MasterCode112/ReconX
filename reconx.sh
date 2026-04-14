#!/usr/bin/env bash
# ╔══════════════════════════════════════════════════════════════════╗
# ║                         R E C O N X                             ║
# ║          Modern Automated Recon & Enumeration Framework          ║
# ║                  Rebuilt from nmapAutomator                      ║
# ╚══════════════════════════════════════════════════════════════════╝
# Usage:   reconx.sh [OPTIONS] -t <TARGET> -s <SCAN_TYPE>
# Author:  ReconX Project
# License: MIT

set -euo pipefail

# ─────────────────────────── COLORS ───────────────────────────────
RED='\033[0;31m'
ORANGE='\033[0;33m'
YELLOW='\033[1;33m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
BOLD='\033[1m'
DIM='\033[2m'
NC='\033[0m'

# ─────────────────────────── GLOBALS ──────────────────────────────
RECONX_VERSION="2.0.0"
SECONDS=0
TARGET=""
SCAN_TYPE=""
OUTPUT_DIR=""
CUSTOM_OUTPUT=""
THREADS=30
RATE=500
TIMEOUT=5
VERBOSE=false
NO_PING=false
RESUME=false
MARKDOWN_REPORT=false
SLIP_SCAN=false  # stealth / low-noise mode
WORDLIST="/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt"
FUZZ_WORDLIST="/usr/share/seclists/Discovery/Web-Content/common.txt"

basicPorts=""
allPorts=""
udpPorts=""
extraPorts=""
osType="Unknown"
nmapBase="nmap"
subnet=""

# ────────────────────────── BANNER ────────────────────────────────
banner() {
    echo -e "${CYAN}"
    cat << 'EOF'
 ____                        __  __
|  _ \ ___  ___ ___  _ __   \ \/ /
| |_) / _ \/ __/ _ \| '_ \   \  / 
|  _ <  __/ (_| (_) | | | |  /  \ 
|_| \_\___|\___\___/|_| |_| /_/\_\
                                    v2.0.0
    Modern Automated Recon Framework
EOF
    echo -e "${NC}"
}

# ─────────────────────────── USAGE ────────────────────────────────
usage() {
    echo -e ""
    echo -e "${BOLD}${CYAN}ReconX v${RECONX_VERSION}${NC} — Automated Recon & Enumeration Framework"
    echo -e ""
    echo -e "${BOLD}Usage:${NC}"
    echo -e "  reconx.sh [OPTIONS] -t <TARGET> -s <SCAN_TYPE>"
    echo -e ""
    echo -e "${BOLD}Target:${NC}"
    echo -e "  -t <IP|HOSTNAME|CIDR>   Target IP, hostname, or CIDR range"
    echo -e ""
    echo -e "${BOLD}Scan Types:${NC} (${YELLOW}-s${NC})"
    echo -e "  ${GREEN}Quick${NC}     Fast port discovery (~15s)"
    echo -e "  ${GREEN}Basic${NC}     Quick scan + service/version detection (~5m)"
    echo -e "  ${GREEN}UDP${NC}       UDP port scan + service detection (~5m)"
    echo -e "  ${GREEN}Full${NC}      All 65535 ports + thorough scan on extras (~10m)"
    echo -e "  ${GREEN}Vulns${NC}     CVE + vuln script scan on all found ports (~15m)"
    echo -e "  ${GREEN}Recon${NC}     Smart recon: web, smb, dns, ldap, etc. (~20m)"
    echo -e "  ${GREEN}API${NC}       API surface enumeration (REST/GraphQL/Swagger)"
    echo -e "  ${GREEN}Cloud${NC}     Cloud asset probing (S3, Azure Blob, GCP)"
    echo -e "  ${GREEN}All${NC}       Runs everything sequentially (~30-45m)"
    echo -e ""
    echo -e "${BOLD}Options:${NC}"
    echo -e "  -o <DIR>          Custom output directory"
    echo -e "  -T <1-5>          Nmap timing template (default: 4)"
    echo -e "  -r <rate>         Packet rate for full scan (default: 500)"
    echo -e "  -w <wordlist>     Custom wordlist for web recon"
    echo -e "  --threads <n>     Threads for recon tools (default: 30)"
    echo -e "  --stealth         Low-noise mode (slower, harder to detect)"
    echo -e "  --no-ping         Treat host as alive (skip ping check)"
    echo -e "  --resume          Resume from existing scan files"
    echo -e "  --report          Generate markdown summary report"
    echo -e "  -v                Verbose mode"
    echo -e "  -h                Show this help"
    echo -e ""
    echo -e "${BOLD}Examples:${NC}"
    echo -e "  reconx.sh -t 10.10.10.5 -s All"
    echo -e "  reconx.sh -t 192.168.1.0/24 -s Quick"
    echo -e "  reconx.sh -t target.htb -s Recon --report -o ./results"
    echo -e "  reconx.sh -t 10.0.0.1 -s Full --stealth -T 2"
    echo -e ""
    exit 1
}

# ─────────────────────── ARG PARSING ──────────────────────────────
parse_args() {
    [[ $# -eq 0 ]] && usage

    local timing=4
    while [[ $# -gt 0 ]]; do
        case "$1" in
            -t|--target)    TARGET="$2";           shift 2 ;;
            -s|--scan)      SCAN_TYPE="${2^}";      shift 2 ;;
            -o|--output)    CUSTOM_OUTPUT="$2";     shift 2 ;;
            -T)             timing="$2";             shift 2 ;;
            -r|--rate)      RATE="$2";              shift 2 ;;
            -w|--wordlist)  WORDLIST="$2";           shift 2 ;;
            --threads)      THREADS="$2";            shift 2 ;;
            --stealth)      SLIP_SCAN=true;          shift   ;;
            --no-ping)      NO_PING=true;            shift   ;;
            --resume)       RESUME=true;             shift   ;;
            --report)       MARKDOWN_REPORT=true;    shift   ;;
            -v|--verbose)   VERBOSE=true;            shift   ;;
            -h|--help)      usage ;;
            *) echo -e "${RED}Unknown option: $1${NC}"; usage ;;
        esac
    done

    NMAP_TIMING="-T${timing}"
    [[ "$SLIP_SCAN" == true ]] && NMAP_TIMING="-T2" && RATE=100

    [[ -z "$TARGET" ]] && { echo -e "${RED}Error: No target specified.${NC}"; usage; }
    [[ -z "$SCAN_TYPE" ]] && { echo -e "${RED}Error: No scan type specified.${NC}"; usage; }
}

# ─────────────────────── VALIDATION ───────────────────────────────
validate_target() {
    local t="$1"
    # IPv4
    if [[ "$t" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then return 0; fi
    # CIDR
    if [[ "$t" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}/[0-9]{1,2}$ ]]; then return 0; fi
    # Hostname
    if [[ "$t" =~ ^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z]{2,})+$ ]]; then return 0; fi
    # Plain hostname (like "target" or "box.htb")
    if [[ "$t" =~ ^[a-zA-Z0-9._-]+$ ]]; then return 0; fi
    echo -e "${RED}Error: '$t' doesn't look like a valid IP, hostname, or CIDR.${NC}"
    exit 1
}

validate_scan_type() {
    local valid="Quick Basic Udp Full Vulns Recon Api Cloud All"
    for v in $valid; do
        [[ "${1^}" == "$v" ]] && return 0
    done
    echo -e "${RED}Error: Invalid scan type '${1}'.${NC}"
    usage
}

# ─────────────────────── SETUP OUTPUT ─────────────────────────────
setup_output() {
    if [[ -n "$CUSTOM_OUTPUT" ]]; then
        OUTPUT_DIR="$CUSTOM_OUTPUT"
    else
        # Sanitise target name for directory
        local safe_target
        safe_target=$(echo "$TARGET" | tr '/' '_' | tr ':' '_')
        OUTPUT_DIR="./reconx_${safe_target}"
    fi

    mkdir -p "${OUTPUT_DIR}/nmap" "${OUTPUT_DIR}/recon" "${OUTPUT_DIR}/web" "${OUTPUT_DIR}/screenshots"
    LOG_FILE="${OUTPUT_DIR}/reconx.log"
    touch "$LOG_FILE"
}

# ─────────────────────── LOGGING ──────────────────────────────────
log()  { echo -e "[$(date '+%H:%M:%S')] $*" | tee -a "$LOG_FILE"; }
info() { echo -e "${CYAN}[*]${NC} $*" | tee -a "$LOG_FILE"; }
ok()   { echo -e "${GREEN}[+]${NC} $*" | tee -a "$LOG_FILE"; }
warn() { echo -e "${YELLOW}[!]${NC} $*" | tee -a "$LOG_FILE"; }
err()  { echo -e "${RED}[✗]${NC} $*" | tee -a "$LOG_FILE"; }
sep()  { echo -e "${DIM}────────────────────────────────────────────────────────${NC}" | tee -a "$LOG_FILE"; }

# ─────────────────────── TOOL CHECKS ──────────────────────────────
check_tool() {
    command -v "$1" &>/dev/null
}

require_tool() {
    if ! check_tool "$1"; then
        err "Required tool not found: ${BOLD}$1${NC}"
        err "Install: ${DIM}$2${NC}"
        return 1
    fi
    return 0
}

check_dependencies() {
    info "Checking dependencies..."
    local missing=()

    require_tool nmap      "apt install nmap"            || missing+=(nmap)
    
    # Optional tools — warn but don't abort
    for t_pair in \
        "gobuster:apt install gobuster" \
        "ffuf:apt install ffuf OR go install github.com/ffuf/ffuf/v2@latest" \
        "nikto:apt install nikto" \
        "smbmap:apt install smbmap" \
        "enum4linux-ng:pip3 install enum4linux-ng" \
        "dnsrecon:apt install dnsrecon" \
        "whatweb:apt install whatweb" \
        "feroxbuster:apt install feroxbuster" \
        "nuclei:go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest" \
        "httpx:go install github.com/projectdiscovery/httpx/cmd/httpx@latest" \
        "wpscan:gem install wpscan" \
        "testssl.sh:apt install testssl.sh"
    do
        local tool="${t_pair%%:*}"
        local install="${t_pair#*:}"
        if ! check_tool "$tool"; then
            warn "Optional tool missing: ${BOLD}$tool${NC} — ${DIM}${install}${NC}"
        fi
    done

    if [[ ${#missing[@]} -gt 0 ]]; then
        err "Critical tools missing: ${missing[*]}. Aborting."
        exit 1
    fi
    ok "Core dependencies OK"
}

# ─────────────────────── HOST DETECTION ───────────────────────────
detect_host() {
    info "Probing host reachability..."

    local ping_result ttl
    ping_result=$(ping -c 2 -W 3 "$TARGET" 2>/dev/null | grep -i ttl || true)

    if [[ -z "$ping_result" ]]; then
        if [[ "$NO_PING" == true ]]; then
            warn "No ping response — continuing with -Pn (as requested)"
            nmapBase="nmap -Pn"
        else
            warn "No ping response — adding -Pn flag automatically"
            nmapBase="nmap -Pn"
        fi
    else
        nmapBase="nmap"
        ttl=$(echo "$ping_result" | grep -oP 'ttl=\K[0-9]+' | head -1)
        if [[ -n "$ttl" ]]; then
            osType=$(guess_os "$ttl")
            ok "Host alive — TTL=${ttl} → likely ${BOLD}${osType}${NC}"
        fi
    fi

    # Resolve hostname to IP if needed
    if [[ "$TARGET" =~ ^[a-zA-Z] ]] && ! [[ "$TARGET" =~ ^[0-9] ]]; then
        local resolved
        resolved=$(getent hosts "$TARGET" 2>/dev/null | awk '{print $1}' | head -1)
        if [[ -n "$resolved" ]]; then
            ok "Resolved ${TARGET} → ${resolved}"
        fi
    fi

    subnet=$(echo "$TARGET" | cut -d'.' -f1-3).0
}

guess_os() {
    local ttl="$1"
    if   (( ttl >= 253 )); then echo "OpenBSD/Cisco/Oracle"
    elif (( ttl >= 120 )); then echo "Windows"
    elif (( ttl >= 60  )); then echo "Linux/Unix"
    else                        echo "Unknown"
    fi
}

# ─────────────────────── PORT HELPERS ─────────────────────────────
assign_ports() {
    basicPorts=""
    allPorts=""
    udpPorts=""

    if [[ -f "${OUTPUT_DIR}/nmap/quick_${TARGET}.nmap" ]]; then
        basicPorts=$(grep -E '^[0-9]+/tcp.*open' "${OUTPUT_DIR}/nmap/quick_${TARGET}.nmap" \
            | awk -F'/' '{print $1}' | tr '\n' ',' | sed 's/,$//') || true
    fi

    local full_ports=""
    if [[ -f "${OUTPUT_DIR}/nmap/full_${TARGET}.nmap" ]]; then
        full_ports=$(grep -E '^[0-9]+/tcp.*open' "${OUTPUT_DIR}/nmap/full_${TARGET}.nmap" \
            | awk -F'/' '{print $1}' | tr '\n' ',' | sed 's/,$//') || true
    fi

    # Merge quick + full ports (unique)
    if [[ -n "$basicPorts" && -n "$full_ports" ]]; then
        allPorts=$(echo "${basicPorts},${full_ports}" | tr ',' '\n' | sort -un | tr '\n' ',' | sed 's/,$//') || true
    elif [[ -n "$full_ports" ]]; then
        allPorts="$full_ports"
    else
        allPorts="$basicPorts"
    fi

    if [[ -f "${OUTPUT_DIR}/nmap/udp_${TARGET}.nmap" ]]; then
        udpPorts=$(grep -E '^[0-9]+/udp.*open ' "${OUTPUT_DIR}/nmap/udp_${TARGET}.nmap" \
            | awk -F'/' '{print $1}' | tr '\n' ',' | sed 's/,$//') || true
    fi
}

extra_ports() {
    # Ports in allPorts that are NOT in basicPorts
    extraPorts=""
    if [[ -z "$allPorts" || -z "$basicPorts" ]]; then
        extraPorts="$allPorts"
        return
    fi
    extraPorts=$(comm -23 \
        <(echo "$allPorts" | tr ',' '\n' | sort -u) \
        <(echo "$basicPorts" | tr ',' '\n' | sort -u) \
        | tr '\n' ',' | sed 's/,$//') || true
}

# ─────────────────────── NMAP SCANS ───────────────────────────────
scan_quick() {
    local out="${OUTPUT_DIR}/nmap/quick_${TARGET}.nmap"
    [[ "$RESUME" == true && -f "$out" ]] && { warn "Resuming: quick scan results found"; assign_ports; return; }

    sep
    info "${BOLD}Quick Scan${NC} — fast TCP port discovery"
    sep

    $nmapBase $NMAP_TIMING --max-retries 1 --max-scan-delay 20 \
        --defeat-rst-ratelimit --open \
        -oN "$out" "$TARGET" 2>&1 | tee -a "$LOG_FILE"

    assign_ports

    if [[ -n "$basicPorts" ]]; then
        ok "Open TCP ports: ${BOLD}${basicPorts}${NC}"
    else
        warn "No open TCP ports found"
    fi
    echo ""
}

scan_basic() {
    local out="${OUTPUT_DIR}/nmap/basic_${TARGET}.nmap"
    [[ "$RESUME" == true && -f "$out" ]] && { warn "Resuming: basic scan results found"; return; }
    [[ -z "$basicPorts" ]] && { warn "No ports from quick scan — skipping basic scan"; return; }

    sep
    info "${BOLD}Basic Scan${NC} — service/version/scripts on open ports"
    sep

    $nmapBase -sCV -p"${basicPorts}" \
        --script="banner,ssl-cert,ssl-enum-ciphers,http-title,http-methods,ssh-auth-methods" \
        $NMAP_TIMING -oN "$out" "$TARGET" 2>&1 | tee -a "$LOG_FILE"

    # Refine OS guess from service banner
    if [[ -f "$out" ]]; then
        local svc_os
        svc_os=$(grep -i "Service Info: OS:" "$out" | cut -d: -f3 | sed 's/^ //;s/;//' | head -1) || true
        if [[ -n "$svc_os" && "$osType" != "$svc_os" ]]; then
            osType="$svc_os"
            ok "OS refined from service banner: ${BOLD}${osType}${NC}"
        fi
    fi
    echo ""
}

scan_udp() {
    local out="${OUTPUT_DIR}/nmap/udp_${TARGET}.nmap"
    [[ "$RESUME" == true && -f "$out" ]] && { warn "Resuming: UDP scan results found"; assign_ports; return; }

    sep
    info "${BOLD}UDP Scan${NC} — top UDP ports"
    sep

    $nmapBase -sU --max-retries 1 --open $NMAP_TIMING \
        -oN "$out" "$TARGET" 2>&1 | tee -a "$LOG_FILE"

    assign_ports

    if [[ -n "$udpPorts" ]]; then
        ok "Open UDP ports: ${BOLD}${udpPorts}${NC}"
        # Script scan on found UDP ports
        info "Running script scan on UDP ports: ${udpPorts}"
        local vuln_args=""
        [[ -f /usr/share/nmap/scripts/vulners.nse ]] && vuln_args="--script vulners --script-args mincvss=7.0"
        $nmapBase -sUCV $vuln_args -p"${udpPorts}" \
            -oN "${OUTPUT_DIR}/nmap/udp_detail_${TARGET}.nmap" "$TARGET" 2>&1 | tee -a "$LOG_FILE"
    else
        warn "No open UDP ports found"
    fi
    echo ""
}

scan_full() {
    local out="${OUTPUT_DIR}/nmap/full_${TARGET}.nmap"
    [[ "$RESUME" == true && -f "$out" ]] && { warn "Resuming: full scan results found"; assign_ports; return; }

    sep
    info "${BOLD}Full Scan${NC} — all 65535 TCP ports"
    sep

    $nmapBase -p- $NMAP_TIMING --max-retries 1 \
        --max-rate "$RATE" --max-scan-delay 20 -v \
        -oN "$out" "$TARGET" 2>&1 | tee -a "$LOG_FILE"

    assign_ports
    extra_ports

    if [[ -n "$extraPorts" ]]; then
        ok "Extra ports (not in quick scan): ${BOLD}${extraPorts}${NC}"
        info "Running script scan on extra ports..."
        $nmapBase -sCV -p"${extraPorts}" $NMAP_TIMING \
            -oN "${OUTPUT_DIR}/nmap/full_detail_${TARGET}.nmap" "$TARGET" 2>&1 | tee -a "$LOG_FILE"
        assign_ports
    else
        ok "No new ports found beyond quick scan"
    fi
    echo ""
}

scan_vulns() {
    local ports="${allPorts:-$basicPorts}"
    [[ -z "$ports" ]] && { warn "No ports available — run Quick/Basic first"; return; }

    sep
    info "${BOLD}Vulnerability Scan${NC} — CVE and vuln scripts"
    sep

    # Vulners CVE scan
    if [[ -f /usr/share/nmap/scripts/vulners.nse ]]; then
        info "Running vulners CVE scan..."
        $nmapBase -sV --script vulners --script-args mincvss=5.0 \
            -p"${ports}" $NMAP_TIMING \
            -oN "${OUTPUT_DIR}/nmap/cves_${TARGET}.nmap" "$TARGET" 2>&1 | tee -a "$LOG_FILE"
    else
        warn "vulners.nse not found — install from https://github.com/vulnersCom/nmap-vulners"
    fi

    # Built-in vuln scripts
    info "Running nmap vuln scripts..."
    $nmapBase -sV --script vuln -p"${ports}" $NMAP_TIMING \
        -oN "${OUTPUT_DIR}/nmap/vulns_${TARGET}.nmap" "$TARGET" 2>&1 | tee -a "$LOG_FILE"

    # Nuclei scan if available
    if check_tool nuclei; then
        info "Running Nuclei scan..."
        nuclei -target "$TARGET" -severity medium,high,critical \
            -o "${OUTPUT_DIR}/recon/nuclei_${TARGET}.txt" 2>&1 | tee -a "$LOG_FILE" || true
    fi

    echo ""
}

# ─────────────────────── RECON MODULE ─────────────────────────────
recon_web() {
    local port="$1"
    local scheme="$2"   # http or https
    local base_url="${scheme}://${TARGET}:${port}"

    info "Web recon → ${BOLD}${base_url}${NC}"
    local web_dir="${OUTPUT_DIR}/web/${port}"
    mkdir -p "$web_dir"

    # WhatWeb fingerprint
    if check_tool whatweb; then
        whatweb "$base_url" --no-errors -a 3 \
            | tee "${web_dir}/whatweb.txt" 2>&1 || true
    fi

    # SSL/TLS
    if [[ "$scheme" == "https" ]]; then
        if check_tool testssl.sh; then
            testssl.sh --quiet --color 0 "$base_url" \
                | tee "${web_dir}/testssl.txt" 2>&1 || true
        elif check_tool sslscan; then
            sslscan "$TARGET:${port}" \
                | tee "${web_dir}/sslscan.txt" 2>&1 || true
        fi
    fi

    # Directory bruteforce — prefer feroxbuster > ffuf > gobuster
    if check_tool feroxbuster; then
        info "Running feroxbuster on ${base_url}"
        feroxbuster -u "$base_url" -w "$WORDLIST" \
            -t "$THREADS" -o "${web_dir}/feroxbuster.txt" \
            --no-state 2>&1 | tee -a "$LOG_FILE" || true
    elif check_tool ffuf; then
        info "Running ffuf on ${base_url}"
        ffuf -u "${base_url}/FUZZ" -w "$WORDLIST" \
            -t "$THREADS" -mc 200,201,204,301,302,307,401,403 \
            -o "${web_dir}/ffuf.json" -of json 2>&1 | tee -a "$LOG_FILE" || true
    elif check_tool gobuster; then
        info "Running gobuster on ${base_url}"
        local ext=".php,.html,.txt"
        [[ "$osType" == *"Windows"* ]] && ext=".asp,.aspx,.php,.html,.txt"
        gobuster dir -u "$base_url" -w "$WORDLIST" \
            -t "$THREADS" -e -k -l -x "$ext" \
            -o "${web_dir}/gobuster.txt" 2>&1 | tee -a "$LOG_FILE" || true
    fi

    # Nikto
    if check_tool nikto; then
        info "Running nikto on ${base_url}"
        nikto -host "$base_url" -output "${web_dir}/nikto.txt" -nointeractive 2>&1 | tee -a "$LOG_FILE" || true
    fi

    # httpx probing (headers, techs, status codes)
    if check_tool httpx; then
        echo "$base_url" | httpx -title -tech-detect -status-code -content-length \
            -o "${web_dir}/httpx.txt" 2>&1 | tee -a "$LOG_FILE" || true
    fi

    # CMS detection from nmap output
    local cms=""
    if [[ -f "${OUTPUT_DIR}/nmap/basic_${TARGET}.nmap" ]]; then
        cms=$(grep http-generator "${OUTPUT_DIR}/nmap/basic_${TARGET}.nmap" \
            | awk '{print $2}' | head -1) || true
    fi
    case "${cms,,}" in
        wordpress) 
            if check_tool wpscan; then
                info "WordPress detected — running WPScan"
                wpscan --url "$base_url" --enumerate p,u,t,cb \
                    --output "${web_dir}/wpscan.txt" 2>&1 | tee -a "$LOG_FILE" || true
            fi ;;
        joomla*) 
            if check_tool joomscan; then
                info "Joomla detected — running JoomScan"
                joomscan --url "$base_url" | tee "${web_dir}/joomscan.txt" 2>&1 || true
            fi ;;
        drupal) 
            if check_tool droopescan; then
                info "Drupal detected — running droopescan"
                droopescan scan drupal -u "$base_url" | tee "${web_dir}/droopescan.txt" 2>&1 || true
            fi ;;
    esac
}

recon_smb() {
    local port="${1:-445}"
    sep
    info "${BOLD}SMB Recon${NC} (port ${port})"
    local smb_dir="${OUTPUT_DIR}/recon/smb"
    mkdir -p "$smb_dir"

    # smbmap
    if check_tool smbmap; then
        smbmap -H "$TARGET" -u '' -p '' 2>&1 | tee "${smb_dir}/smbmap.txt" || true
        smbmap -H "$TARGET" -u 'guest' -p '' 2>&1 | tee "${smb_dir}/smbmap_guest.txt" || true
    fi

    # smbclient
    if check_tool smbclient; then
        smbclient -L "//${TARGET}/" -U 'guest%' -N 2>&1 | tee "${smb_dir}/smbclient.txt" || true
    fi

    # enum4linux-ng (preferred over enum4linux)
    if check_tool enum4linux-ng; then
        enum4linux-ng -A "$TARGET" -oA "${smb_dir}/enum4linux-ng" 2>&1 | tee -a "$LOG_FILE" || true
    elif check_tool enum4linux; then
        enum4linux -a "$TARGET" 2>&1 | tee "${smb_dir}/enum4linux.txt" || true
    fi

    # nmap smb vuln scripts
    $nmapBase -p"${port}" --script "smb-vuln-*,smb2-security-mode,smb-os-discovery" \
        -oN "${smb_dir}/smb_vulns.nmap" "$TARGET" 2>&1 | tee -a "$LOG_FILE" || true

    # crackmapexec if available
    if check_tool crackmapexec; then
        crackmapexec smb "$TARGET" 2>&1 | tee "${smb_dir}/cme.txt" || true
    elif check_tool netexec; then
        netexec smb "$TARGET" 2>&1 | tee "${smb_dir}/netexec.txt" || true
    fi
}

recon_dns() {
    sep
    info "${BOLD}DNS Recon${NC} (port 53)"
    local dns_dir="${OUTPUT_DIR}/recon/dns"
    mkdir -p "$dns_dir"

    # Zone transfer attempt
    if check_tool dig; then
        dig axfr "@${TARGET}" 2>&1 | tee "${dns_dir}/zone_transfer.txt" || true
    fi

    if check_tool dnsrecon; then
        dnsrecon -r "${subnet}/24" -n "$TARGET" 2>&1 | tee "${dns_dir}/dnsrecon.txt" || true
        dnsrecon -r "127.0.0.0/24" -n "$TARGET" 2>&1 | tee "${dns_dir}/dnsrecon_local.txt" || true
    fi

    if check_tool dnsx; then
        dnsx -ptr -resp -silent -l <(echo "$TARGET") \
            | tee "${dns_dir}/dnsx.txt" || true
    fi
}

recon_ldap() {
    sep
    info "${BOLD}LDAP Recon${NC} (port 389/636)"
    local ldap_dir="${OUTPUT_DIR}/recon/ldap"
    mkdir -p "$ldap_dir"

    if check_tool ldapsearch; then
        # Anonymous bind attempt
        ldapsearch -x -H "ldap://${TARGET}" -b '' \
            -s base namingContexts 2>&1 | tee "${ldap_dir}/ldap_base.txt" || true
        local base
        base=$(grep -i namingContexts "${ldap_dir}/ldap_base.txt" | awk '{print $2}' | head -1) || true
        if [[ -n "$base" ]]; then
            ldapsearch -x -H "ldap://${TARGET}" -b "$base" \
                '(objectClass=*)' 2>&1 | tee "${ldap_dir}/ldap_dump.txt" || true
        fi
    fi

    $nmapBase -p389,636,3268,3269 --script "ldap-*" \
        -oN "${ldap_dir}/ldap_nmap.nmap" "$TARGET" 2>&1 | tee -a "$LOG_FILE" || true
}

recon_snmp() {
    sep
    info "${BOLD}SNMP Recon${NC} (port 161 UDP)"
    local snmp_dir="${OUTPUT_DIR}/recon/snmp"
    mkdir -p "$snmp_dir"

    if check_tool snmpwalk; then
        for community in public private community; do
            snmpwalk -Os -c "$community" -v1 "$TARGET" 2>/dev/null \
                | tee "${snmp_dir}/snmpwalk_${community}.txt" || true
        done
    fi

    if check_tool onesixtyone; then
        onesixtyone -c /usr/share/seclists/Discovery/SNMP/common-snmp-community-strings.txt \
            "$TARGET" 2>&1 | tee "${snmp_dir}/onesixtyone.txt" || true
    fi
}

recon_ftp() {
    local port="${1:-21}"
    sep
    info "${BOLD}FTP Recon${NC} (port ${port})"
    local ftp_dir="${OUTPUT_DIR}/recon/ftp"
    mkdir -p "$ftp_dir"

    $nmapBase -p"${port}" \
        --script "ftp-anon,ftp-bounce,ftp-syst,ftp-vsftpd-backdoor,ftp-vuln-*" \
        -oN "${ftp_dir}/ftp_nmap.nmap" "$TARGET" 2>&1 | tee -a "$LOG_FILE" || true

    # Anonymous login check
    if check_tool ftp; then
        timeout 10 ftp -n "$TARGET" <<EOF 2>&1 | tee "${ftp_dir}/ftp_anon.txt" || true
user anonymous anonymous
ls -la
quit
EOF
    fi
}

recon_ssh() {
    local port="${1:-22}"
    sep
    info "${BOLD}SSH Recon${NC} (port ${port})"
    local ssh_dir="${OUTPUT_DIR}/recon/ssh"
    mkdir -p "$ssh_dir"

    $nmapBase -p"${port}" \
        --script "ssh-auth-methods,ssh-hostkey,ssh2-enum-algos,sshv1" \
        -oN "${ssh_dir}/ssh_nmap.nmap" "$TARGET" 2>&1 | tee -a "$LOG_FILE" || true
}

recon_mssql() {
    local port="${1:-1433}"
    sep
    info "${BOLD}MSSQL Recon${NC} (port ${port})"
    local sql_dir="${OUTPUT_DIR}/recon/mssql"
    mkdir -p "$sql_dir"

    $nmapBase -p"${port}" \
        --script "ms-sql-info,ms-sql-empty-password,ms-sql-xp-cmdshell,ms-sql-config,ms-sql-ntlm-info" \
        -oN "${sql_dir}/mssql_nmap.nmap" "$TARGET" 2>&1 | tee -a "$LOG_FILE" || true
}

recon_mysql() {
    local port="${1:-3306}"
    sep
    info "${BOLD}MySQL Recon${NC} (port ${port})"
    local sql_dir="${OUTPUT_DIR}/recon/mysql"
    mkdir -p "$sql_dir"

    $nmapBase -p"${port}" \
        --script "mysql-info,mysql-empty-password,mysql-databases,mysql-users" \
        -oN "${sql_dir}/mysql_nmap.nmap" "$TARGET" 2>&1 | tee -a "$LOG_FILE" || true
}

recon_rdp() {
    local port="${1:-3389}"
    sep
    info "${BOLD}RDP Recon${NC} (port ${port})"
    local rdp_dir="${OUTPUT_DIR}/recon/rdp"
    mkdir -p "$rdp_dir"

    $nmapBase -p"${port}" \
        --script "rdp-vuln-ms12-020,rdp-enum-encryption,rdp-nla" \
        -oN "${rdp_dir}/rdp_nmap.nmap" "$TARGET" 2>&1 | tee -a "$LOG_FILE" || true
}

recon_oracle() {
    local port="${1:-1521}"
    sep
    info "${BOLD}Oracle DB Recon${NC} (port ${port})"
    local ora_dir="${OUTPUT_DIR}/recon/oracle"
    mkdir -p "$ora_dir"

    $nmapBase -p"${port}" \
        --script "oracle-sid-brute,oracle-tns-poison" \
        -oN "${ora_dir}/oracle_nmap.nmap" "$TARGET" 2>&1 | tee -a "$LOG_FILE" || true

    if [[ -f /opt/odat/odat.py ]]; then
        info "Running ODAT sid guesser..."
        python3 /opt/odat/odat.py sidguesser -s "$TARGET" -p "$port" \
            | tee "${ora_dir}/odat_sid.txt" || true
    fi
}

# ────────── API Surface Enumeration (NEW) ──────────────────────────
scan_api() {
    [[ -z "$basicPorts" && -z "$allPorts" ]] && scan_quick && scan_basic

    sep
    info "${BOLD}API Surface Scan${NC} — REST, GraphQL, Swagger"
    sep

    local ports="${allPorts:-$basicPorts}"
    local api_dir="${OUTPUT_DIR}/recon/api"
    mkdir -p "$api_dir"

    # Find HTTP/HTTPS ports
    for port in $(echo "$ports" | tr ',' '\n'); do
        for scheme in http https; do
            local url="${scheme}://${TARGET}:${port}"
            # Common API endpoints
            for path in \
                "/api" "/api/v1" "/api/v2" "/api/v3" \
                "/swagger" "/swagger-ui.html" "/swagger-ui" \
                "/openapi.json" "/openapi.yaml" "/api-docs" \
                "/graphql" "/graphiql" "/.well-known/openapi.json" \
                "/actuator" "/actuator/health" "/health" "/metrics" \
                "/v1" "/v2" "/rest" "/json" "/ws" "/websocket"
            do
                local status
                status=$(curl -sk -o /dev/null -w "%{http_code}" \
                    --connect-timeout "$TIMEOUT" "${url}${path}" 2>/dev/null) || true
                if [[ "$status" =~ ^(200|201|301|302|400|401|403)$ ]]; then
                    echo "${url}${path} → HTTP ${status}" | tee -a "${api_dir}/endpoints.txt"
                fi
            done

            # GraphQL introspection attempt
            local gql_status
            gql_status=$(curl -sk -o "${api_dir}/graphql_introspect.json" \
                -w "%{http_code}" --connect-timeout "$TIMEOUT" \
                -X POST -H "Content-Type: application/json" \
                -d '{"query":"{__schema{queryType{name}}}"}' \
                "${url}/graphql" 2>/dev/null) || true
            [[ "$gql_status" == "200" ]] && ok "GraphQL endpoint found at ${url}/graphql — introspection may be enabled"
        done
    done

    echo ""
}

# ────────── Cloud Asset Probing (NEW) ─────────────────────────────
scan_cloud() {
    sep
    info "${BOLD}Cloud Asset Probe${NC} — S3, Azure Blob, GCP Storage"
    sep

    local cloud_dir="${OUTPUT_DIR}/recon/cloud"
    mkdir -p "$cloud_dir"

    # Derive candidate bucket names from target
    local base_name
    base_name=$(echo "$TARGET" | sed 's/\..*//;s/-/ /g' | awk '{print $1}') 

    local bucket_names=("$base_name" "${base_name}-backup" "${base_name}-dev" \
        "${base_name}-prod" "${base_name}-staging" "${base_name}-assets" \
        "${base_name}-static" "${base_name}-data" "${base_name}-files")

    for name in "${bucket_names[@]}"; do
        # AWS S3
        local s3_status
        s3_status=$(curl -sk -o /dev/null -w "%{http_code}" \
            --connect-timeout "$TIMEOUT" "https://${name}.s3.amazonaws.com" 2>/dev/null) || true
        if [[ "$s3_status" =~ ^(200|403)$ ]]; then
            ok "S3 bucket found: ${name}.s3.amazonaws.com (HTTP ${s3_status})" | tee -a "${cloud_dir}/s3.txt"
        fi

        # Azure Blob
        local az_status
        az_status=$(curl -sk -o /dev/null -w "%{http_code}" \
            --connect-timeout "$TIMEOUT" "https://${name}.blob.core.windows.net" 2>/dev/null) || true
        if [[ "$az_status" =~ ^(200|400|403|404)$ && "$az_status" != "404" ]]; then
            ok "Azure Blob found: ${name}.blob.core.windows.net (HTTP ${az_status})" | tee -a "${cloud_dir}/azure.txt"
        fi

        # GCP
        local gcp_status
        gcp_status=$(curl -sk -o /dev/null -w "%{http_code}" \
            --connect-timeout "$TIMEOUT" "https://storage.googleapis.com/${name}" 2>/dev/null) || true
        if [[ "$gcp_status" =~ ^(200|403)$ ]]; then
            ok "GCP bucket found: storage.googleapis.com/${name} (HTTP ${gcp_status})" | tee -a "${cloud_dir}/gcp.txt"
        fi
    done

    # If cloud tools present
    if check_tool aws; then
        aws s3 ls "s3://${base_name}" --no-sign-request 2>&1 | tee "${cloud_dir}/aws_s3.txt" || true
    fi

    echo ""
}

# ──────────── Smart Recon Dispatcher ──────────────────────────────
scan_recon() {
    [[ -z "$basicPorts" ]] && { scan_quick; scan_basic; }

    sep
    info "${BOLD}Smart Recon${NC} — service-aware enumeration"
    sep

    local ports="${allPorts:-$basicPorts}"
    local open_services=""
    local detail_file="${OUTPUT_DIR}/nmap/basic_${TARGET}.nmap"
    [[ -f "${OUTPUT_DIR}/nmap/full_detail_${TARGET}.nmap" ]] && \
        detail_file="${OUTPUT_DIR}/nmap/basic_${TARGET}.nmap ${OUTPUT_DIR}/nmap/full_detail_${TARGET}.nmap"

    # Read open ports from nmap files
    # shellcheck disable=SC2086
    open_services=$(cat $detail_file 2>/dev/null | grep -w open || true)

    # Web
    for port in $(echo "$ports" | tr ',' '\n'); do
        local port_info
        port_info=$(echo "$open_services" | grep "^${port}/tcp" || true)
        if echo "$port_info" | grep -qi "http"; then
            if echo "$port_info" | grep -qi "ssl\|https"; then
                recon_web "$port" "https"
            else
                recon_web "$port" "http"
            fi
        fi
    done

    # SMB
    if echo "$open_services" | grep -qw "445/tcp"; then
        recon_smb 445
    elif echo "$open_services" | grep -qw "139/tcp"; then
        recon_smb 139
    fi

    # DNS
    echo "$open_services" | grep -qw "53/tcp" && recon_dns

    # LDAP/AD
    if echo "$open_services" | grep -qE "389/tcp|636/tcp|3268/tcp"; then
        recon_ldap
    fi

    # FTP
    for port in $(echo "$ports" | tr ',' '\n'); do
        echo "$open_services" | grep -q "^${port}/tcp.*ftp" && recon_ftp "$port"
    done

    # SSH
    for port in $(echo "$ports" | tr ',' '\n'); do
        echo "$open_services" | grep -q "^${port}/tcp.*ssh" && recon_ssh "$port"
    done

    # MSSQL
    echo "$open_services" | grep -qw "1433/tcp" && recon_mssql 1433

    # MySQL
    echo "$open_services" | grep -qw "3306/tcp" && recon_mysql 3306

    # RDP
    echo "$open_services" | grep -qw "3389/tcp" && recon_rdp 3389

    # Oracle
    echo "$open_services" | grep -qw "1521/tcp" && recon_oracle 1521

    # SNMP (from UDP results)
    [[ -n "$udpPorts" ]] && echo "$udpPorts" | grep -qw "161" && recon_snmp

    echo ""
}

# ─────────────────── MARKDOWN REPORT ──────────────────────────────
generate_report() {
    local report="${OUTPUT_DIR}/REPORT_${TARGET}.md"
    info "Generating markdown report → ${report}"

    local elapsed
    if (( SECONDS > 3600 )); then
        elapsed="$(( SECONDS/3600 ))h $(( (SECONDS%3600)/60 ))m $(( SECONDS%60 ))s"
    elif (( SECONDS > 60 )); then
        elapsed="$(( SECONDS/60 ))m $(( SECONDS%60 ))s"
    else
        elapsed="${SECONDS}s"
    fi

    cat > "$report" << EOF
# ReconX Report

**Target:** \`${TARGET}\`  
**Scan Type:** ${SCAN_TYPE}  
**Date:** $(date '+%Y-%m-%d %H:%M:%S')  
**Duration:** ${elapsed}  
**Detected OS:** ${osType}

---

## Open TCP Ports

\`\`\`
${basicPorts:-None found}
\`\`\`

## All Ports (including full scan)

\`\`\`
${allPorts:-None found}
\`\`\`

## Open UDP Ports

\`\`\`
${udpPorts:-None found}
\`\`\`

---

## Nmap Results

EOF

    for f in "${OUTPUT_DIR}"/nmap/*.nmap; do
        [[ -f "$f" ]] || continue
        echo "### $(basename "$f")" >> "$report"
        echo '```' >> "$report"
        cat "$f" >> "$report"
        echo '```' >> "$report"
        echo "" >> "$report"
    done

    cat >> "$report" << EOF

---

## Recon Output Summary

EOF

    find "${OUTPUT_DIR}/recon" -type f \( -name "*.txt" -o -name "*.json" \) 2>/dev/null | sort | while read -r f; do
        echo "- \`${f#${OUTPUT_DIR}/}\`" >> "$report"
    done

    cat >> "$report" << EOF

---

*Generated by ReconX v${RECONX_VERSION}*
EOF

    ok "Report saved: ${report}"
}

# ─────────────────────── HEADER / FOOTER ──────────────────────────
print_header() {
    echo ""
    sep
    echo -e "${BOLD}${CYAN}  ReconX v${RECONX_VERSION}${NC}"
    echo -e "  Target    : ${BOLD}${TARGET}${NC}"
    echo -e "  Scan Type : ${BOLD}${SCAN_TYPE}${NC}"
    echo -e "  Output    : ${BOLD}${OUTPUT_DIR}${NC}"
    echo -e "  OS Guess  : ${BOLD}${osType}${NC}"
    echo -e "  Stealth   : ${SLIP_SCAN}"
    sep
    echo ""
}

print_footer() {
    local elapsed
    if (( SECONDS > 3600 )); then
        elapsed="$(( SECONDS/3600 ))h $(( (SECONDS%3600)/60 ))m $(( SECONDS%60 ))s"
    elif (( SECONDS > 60 )); then
        elapsed="$(( SECONDS/60 ))m $(( SECONDS%60 ))s"
    else
        elapsed="${SECONDS}s"
    fi

    sep
    ok "${BOLD}All scans complete!${NC}"
    echo -e "  Results   : ${BOLD}${OUTPUT_DIR}${NC}"
    echo -e "  Duration  : ${BOLD}${elapsed}${NC}"
    sep
    echo ""
}

# ─────────────────────── MAIN ─────────────────────────────────────
main() {
    banner
    parse_args "$@"

    validate_target "$TARGET"
    validate_scan_type "$SCAN_TYPE"

    setup_output
    check_dependencies
    detect_host
    print_header

    case "${SCAN_TYPE}" in
        Quick)
            scan_quick ;;
        Basic)
            scan_quick
            scan_basic ;;
        Udp)
            scan_udp ;;
        Full)
            scan_quick
            scan_full ;;
        Vulns)
            scan_quick
            scan_basic
            scan_vulns ;;
        Recon)
            scan_quick
            scan_basic
            scan_recon ;;
        Api)
            scan_quick
            scan_basic
            scan_api ;;
        Cloud)
            scan_cloud ;;
        All)
            scan_quick
            scan_basic
            scan_udp
            scan_full
            scan_vulns
            scan_recon
            scan_api
            scan_cloud ;;
        *)
            err "Unknown scan type: ${SCAN_TYPE}"
            usage ;;
    esac

    [[ "$MARKDOWN_REPORT" == true ]] && generate_report

    print_footer
}

main "$@"
