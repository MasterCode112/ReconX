#!/usr/bin/env bash
# ╔══════════════════════════════════════════════════════════════════╗
# ║                         R E C O N X                             ║
# ║          Modern Automated Recon & Enumeration Framework          ║
# ╚══════════════════════════════════════════════════════════════════╝
# set -e is intentionally OMITTED — it causes silent exits when
# grep/ping/optional-tools return non-zero. Errors are handled per call.
set -uo pipefail

RED='\033[0;31m'; YELLOW='\033[1;33m'; GREEN='\033[0;32m'
CYAN='\033[0;36m'; BOLD='\033[1m'; DIM='\033[2m'; NC='\033[0m'

RECONX_VERSION="2.0.0"
SECONDS=0
TARGET=""; SCAN_TYPE=""; OUTPUT_DIR=""; CUSTOM_OUTPUT=""
THREADS=30; RATE=500; TIMEOUT=5
VERBOSE=false; NO_PING=false; RESUME=false; MARKDOWN_REPORT=false; STEALTH=false
NMAP_TIMING="-T4"; WORDLIST=""

basicPorts=""; allPorts=""; udpPorts=""; extraPorts=""
osType="Unknown"; nmapBase="nmap"; subnet="0.0.0.0"
LOG_FILE="/dev/null"   # safe before setup_output() runs

# ── Banner ─────────────────────────────────────────────────────────
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

# ── Usage ──────────────────────────────────────────────────────────
usage() {
    echo -e ""
    echo -e "${BOLD}${CYAN}ReconX v${RECONX_VERSION}${NC} — Automated Recon & Enumeration Framework"
    echo -e ""
    echo -e "${BOLD}Usage:${NC}  reconx.sh [OPTIONS] -t <TARGET> -s <TYPE>"
    echo -e ""
    echo -e "${BOLD}Scan Types:${NC}"
    echo -e "  ${GREEN}Quick${NC}   Fast TCP port discovery                (~15s)"
    echo -e "  ${GREEN}Basic${NC}   Quick + service/version/scripts         (~5m)"
    echo -e "  ${GREEN}UDP${NC}     UDP top ports + service detection       (~5m)"
    echo -e "  ${GREEN}Full${NC}    All 65535 TCP ports + detail on extras  (~10m)"
    echo -e "  ${GREEN}Vulns${NC}   CVE + vuln scripts + Nuclei             (~15m)"
    echo -e "  ${GREEN}Recon${NC}   Smart service-aware recon               (~20m)"
    echo -e "  ${GREEN}API${NC}     REST / GraphQL / Swagger enum           (~5m)"
    echo -e "  ${GREEN}Cloud${NC}   S3 / Azure Blob / GCP discovery        (~3m)"
    echo -e "  ${GREEN}All${NC}     Everything above                        (~45m)"
    echo -e ""
    echo -e "${BOLD}Options:${NC}"
    echo -e "  -t <target>      IP, hostname, or CIDR"
    echo -e "  -s <type>        Scan type (see above)"
    echo -e "  -o <dir>         Output directory (default: ./reconx_<target>)"
    echo -e "  -T <1-5>         Nmap timing template (default: 4)"
    echo -e "  -r <rate>        Packet rate for full scan (default: 500)"
    echo -e "  -w <wordlist>    Wordlist for web fuzzing"
    echo -e "  --threads <n>    Tool thread count (default: 30)"
    echo -e "  --stealth        Low-noise mode (T2, rate=100)"
    echo -e "  --no-ping        Force -Pn (skip ping check)"
    echo -e "  --resume         Skip scans with existing output files"
    echo -e "  --report         Generate Markdown summary report"
    echo -e "  -v               Verbose"
    echo -e "  -h               Help"
    echo -e ""
    echo -e "${BOLD}Examples:${NC}"
    echo -e "  reconx.sh -t 10.10.10.5 -s All --report"
    echo -e "  reconx.sh -t target.htb -s Recon -o ./results"
    echo -e "  reconx.sh -t 10.0.0.1  -s Full --stealth"
    echo -e ""
    exit 0
}

# ── Arg Parsing ────────────────────────────────────────────────────
parse_args() {
    [[ $# -eq 0 ]] && usage
    local timing=4
    while [[ $# -gt 0 ]]; do
        case "$1" in
            -t|--target)   TARGET="$2";  shift 2 ;;
            -s|--scan)     SCAN_TYPE="${2,,}"; shift 2 ;;
            -o|--output)   CUSTOM_OUTPUT="$2"; shift 2 ;;
            -T)            timing="$2";  shift 2 ;;
            -r|--rate)     RATE="$2";    shift 2 ;;
            -w|--wordlist) WORDLIST="$2"; shift 2 ;;
            --threads)     THREADS="$2"; shift 2 ;;
            --stealth)     STEALTH=true; shift ;;
            --no-ping)     NO_PING=true; shift ;;
            --resume)      RESUME=true;  shift ;;
            --report)      MARKDOWN_REPORT=true; shift ;;
            -v|--verbose)  VERBOSE=true; shift ;;
            -h|--help)     usage ;;
            *) echo -e "${RED}[!] Unknown option: $1${NC}"; usage ;;
        esac
    done

    if [[ "$STEALTH" == true ]]; then
        NMAP_TIMING="-T2"; RATE=100
    else
        NMAP_TIMING="-T${timing}"
    fi

    # Default wordlist — pick first one that exists
    if [[ -z "$WORDLIST" ]]; then
        for wl in \
            /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt \
            /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt \
            /usr/share/wordlists/dirb/common.txt \
            /usr/share/wordlists/dirbuster/directory-list-1.0.txt
        do
            if [[ -f "$wl" ]]; then WORDLIST="$wl"; break; fi
        done
        [[ -z "$WORDLIST" ]] && WORDLIST="/usr/share/wordlists/dirb/common.txt"
    fi
}

validate_args() {
    if [[ -z "$TARGET" ]]; then
        echo -e "${RED}[✗] No target. Use: -t <IP|HOST|CIDR>${NC}"
        exit 1
    fi
    if [[ -z "$SCAN_TYPE" ]]; then
        echo -e "${RED}[✗] No scan type. Use: -s <Quick|Basic|UDP|Full|Vulns|Recon|API|Cloud|All>${NC}"
        exit 1
    fi
    case "$SCAN_TYPE" in
        quick|basic|udp|full|vulns|recon|api|cloud|all) ;;
        *)
            echo -e "${RED}[✗] Invalid scan type: '${SCAN_TYPE}'${NC}"
            echo -e "${YELLOW}    Valid: Quick Basic UDP Full Vulns Recon API Cloud All${NC}"
            exit 1 ;;
    esac
}

# ── Output Setup ───────────────────────────────────────────────────
setup_output() {
    if [[ -n "$CUSTOM_OUTPUT" ]]; then
        OUTPUT_DIR="$CUSTOM_OUTPUT"
    else
        local safe
        safe=$(echo "$TARGET" | tr '/: ' '___')
        OUTPUT_DIR="./reconx_${safe}"
    fi
    mkdir -p "${OUTPUT_DIR}/nmap" "${OUTPUT_DIR}/recon" \
             "${OUTPUT_DIR}/web"  "${OUTPUT_DIR}/screenshots"
    LOG_FILE="${OUTPUT_DIR}/reconx.log"
    touch "$LOG_FILE"
}

# ── Logging ────────────────────────────────────────────────────────
info() { echo -e "${CYAN}[*]${NC} $*" | tee -a "$LOG_FILE"; }
ok()   { echo -e "${GREEN}[+]${NC} $*" | tee -a "$LOG_FILE"; }
warn() { echo -e "${YELLOW}[!]${NC} $*" | tee -a "$LOG_FILE"; }
err()  { echo -e "${RED}[✗]${NC} $*" | tee -a "$LOG_FILE"; }
sep()  { echo -e "${DIM}────────────────────────────────────────────────────────${NC}" | tee -a "$LOG_FILE"; }

# ── Tool Check ─────────────────────────────────────────────────────
check_tool() { command -v "$1" &>/dev/null && return 0 || return 1; }

check_dependencies() {
    info "Checking dependencies..."
    if ! check_tool nmap; then
        err "nmap is required: sudo apt install nmap"
        exit 1
    fi
    ok "nmap OK: $(nmap --version 2>/dev/null | head -1)"

    # Count optional tools (never abort on missing)
    local found=0 miss=0
    for t in gobuster ffuf feroxbuster nikto whatweb smbmap smbclient \
              enum4linux-ng enum4linux dnsrecon nuclei httpx testssl.sh \
              sslscan wpscan crackmapexec netexec ldapsearch snmpwalk; do
        if check_tool "$t"; then (( found++ )) || true
        else                     (( miss++ ))  || true
        fi
    done
    ok "Optional tools: ${found} available, ${miss} missing (missing ones are auto-skipped)"
}

# ── Host Detection ─────────────────────────────────────────────────
detect_host() {
    info "Probing ${TARGET}..."

    local ping_out
    ping_out=$(ping -c 2 -W 3 "$TARGET" 2>/dev/null) || true

    if echo "$ping_out" | grep -qi "ttl="; then
        local ttl
        ttl=$(echo "$ping_out" | grep -oP 'ttl=\K[0-9]+' | head -1) || true
        osType=$(guess_os "${ttl:-64}")
        nmapBase="nmap"
        ok "Host alive — TTL=${ttl} → likely ${BOLD}${osType}${NC}"
    else
        nmapBase="nmap -Pn"
        warn "No ICMP response — using -Pn"
    fi

    [[ "$NO_PING" == true ]] && nmapBase="nmap -Pn"

    # Resolve hostname
    if [[ ! "$TARGET" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9] ]]; then
        local res
        res=$(getent hosts "$TARGET" 2>/dev/null | awk '{print $1}' | head -1) || true
        [[ -n "$res" ]] && ok "Resolved ${TARGET} → ${res}"
    fi

    # /24 subnet
    if [[ "$TARGET" =~ ^([0-9]+\.[0-9]+\.[0-9]+)\.[0-9]+$ ]]; then
        subnet="${BASH_REMATCH[1]}.0"
    fi
}

guess_os() {
    local ttl="${1:-64}"
    if   (( ttl >= 200 )); then echo "OpenBSD/Cisco/Oracle"
    elif (( ttl >= 100 )); then echo "Windows"
    elif (( ttl >= 50  )); then echo "Linux/Unix"
    else                        echo "Unknown"
    fi
}

# ── Port Helpers ───────────────────────────────────────────────────
assign_ports() {
    basicPorts=""; allPorts=""; udpPorts=""

    local qf="${OUTPUT_DIR}/nmap/quick_${TARGET}.nmap"
    local ff="${OUTPUT_DIR}/nmap/full_${TARGET}.nmap"
    local uf="${OUTPUT_DIR}/nmap/udp_${TARGET}.nmap"

    [[ -f "$qf" ]] && basicPorts=$(grep -E '^[0-9]+/tcp.*open' "$qf" \
        | awk -F'/' '{print $1}' | tr '\n' ',' | sed 's/,$//' 2>/dev/null) || true

    local fp=""
    [[ -f "$ff" ]] && fp=$(grep -E '^[0-9]+/tcp.*open' "$ff" \
        | awk -F'/' '{print $1}' | tr '\n' ',' | sed 's/,$//' 2>/dev/null) || true

    local combined="${basicPorts},${fp}"; combined="${combined#,}"; combined="${combined%,}"
    if [[ -n "$combined" ]]; then
        allPorts=$(echo "$combined" | tr ',' '\n' | grep -v '^$' \
            | sort -un | tr '\n' ',' | sed 's/,$//' 2>/dev/null) || true
    fi
    [[ -z "$allPorts" ]] && allPorts="$basicPorts"

    [[ -f "$uf" ]] && udpPorts=$(grep -E '^[0-9]+/udp.*open ' "$uf" \
        | awk -F'/' '{print $1}' | tr '\n' ',' | sed 's/,$//' 2>/dev/null) || true
}

compute_extra() {
    extraPorts=""
    [[ -z "$basicPorts" ]] && { extraPorts="$allPorts"; return; }
    [[ -z "$allPorts"   ]] && return
    extraPorts=$(comm -23 \
        <(echo "$allPorts"   | tr ',' '\n' | sort -u) \
        <(echo "$basicPorts" | tr ',' '\n' | sort -u) \
        | tr '\n' ',' | sed 's/,$//') || true
}

# ── Nmap Scans ─────────────────────────────────────────────────────
scan_quick() {
    local out="${OUTPUT_DIR}/nmap/quick_${TARGET}.nmap"
    if [[ "$RESUME" == true && -f "$out" ]]; then
        warn "RESUME: quick scan skipped"; assign_ports; return
    fi
    sep; info "${BOLD}QUICK SCAN${NC} — fast TCP discovery"; sep
    # shellcheck disable=SC2086
    $nmapBase $NMAP_TIMING --max-retries 1 --max-scan-delay 20 \
        --defeat-rst-ratelimit --open \
        -oN "$out" "$TARGET" 2>&1 | tee -a "$LOG_FILE" || true
    assign_ports
    [[ -n "$basicPorts" ]] && ok "Open TCP: ${BOLD}${basicPorts}${NC}" \
                           || warn "No open TCP ports found"
    echo ""
}

scan_basic() {
    local out="${OUTPUT_DIR}/nmap/basic_${TARGET}.nmap"
    if [[ "$RESUME" == true && -f "$out" ]]; then warn "RESUME: basic scan skipped"; return; fi
    if [[ -z "$basicPorts" ]]; then warn "No ports — skipping basic scan"; return; fi
    sep; info "${BOLD}BASIC SCAN${NC} — sCV on: ${basicPorts}"; sep
    # shellcheck disable=SC2086
    $nmapBase -sCV -p "${basicPorts}" \
        --script "banner,ssl-cert,ssl-enum-ciphers,http-title,http-methods,ssh-auth-methods" \
        $NMAP_TIMING -oN "$out" "$TARGET" 2>&1 | tee -a "$LOG_FILE" || true
    if [[ -f "$out" ]]; then
        local svc_os
        svc_os=$(grep -i "Service Info: OS:" "$out" \
            | cut -d: -f3 | sed 's/^ //;s/;.*//' | head -1 2>/dev/null) || true
        [[ -n "$svc_os" ]] && osType="$svc_os" && ok "OS refined: ${BOLD}${osType}${NC}"
    fi
    echo ""
}

scan_udp() {
    local out="${OUTPUT_DIR}/nmap/udp_${TARGET}.nmap"
    if [[ "$RESUME" == true && -f "$out" ]]; then warn "RESUME: UDP scan skipped"; assign_ports; return; fi
    sep; info "${BOLD}UDP SCAN${NC} — top UDP ports"; sep
    # shellcheck disable=SC2086
    $nmapBase -sU --max-retries 1 --open $NMAP_TIMING \
        -oN "$out" "$TARGET" 2>&1 | tee -a "$LOG_FILE" || true
    assign_ports
    if [[ -n "$udpPorts" ]]; then
        ok "Open UDP: ${BOLD}${udpPorts}${NC}"
        local vf=""
        [[ -f /usr/share/nmap/scripts/vulners.nse ]] && \
            vf="--script vulners --script-args mincvss=7.0"
        # shellcheck disable=SC2086
        $nmapBase -sUCV $vf -p "${udpPorts}" \
            -oN "${OUTPUT_DIR}/nmap/udp_detail_${TARGET}.nmap" \
            "$TARGET" 2>&1 | tee -a "$LOG_FILE" || true
    else
        warn "No open UDP ports"
    fi
    echo ""
}

scan_full() {
    local out="${OUTPUT_DIR}/nmap/full_${TARGET}.nmap"
    if [[ "$RESUME" == true && -f "$out" ]]; then warn "RESUME: full scan skipped"; assign_ports; return; fi
    sep; info "${BOLD}FULL SCAN${NC} — all 65535 TCP (rate=${RATE})"; sep
    # shellcheck disable=SC2086
    $nmapBase -p- $NMAP_TIMING --max-retries 1 \
        --max-rate "$RATE" --max-scan-delay 20 -v \
        -oN "$out" "$TARGET" 2>&1 | tee -a "$LOG_FILE" || true
    assign_ports; compute_extra
    if [[ -n "$extraPorts" ]]; then
        ok "Extra ports: ${BOLD}${extraPorts}${NC}"
        # shellcheck disable=SC2086
        $nmapBase -sCV -p "${extraPorts}" $NMAP_TIMING \
            -oN "${OUTPUT_DIR}/nmap/full_detail_${TARGET}.nmap" \
            "$TARGET" 2>&1 | tee -a "$LOG_FILE" || true
        assign_ports
    else
        ok "No new ports beyond quick scan"
    fi
    echo ""
}

scan_vulns() {
    local ports="${allPorts:-$basicPorts}"
    if [[ -z "$ports" ]]; then scan_quick; scan_basic; ports="${allPorts:-$basicPorts}"; fi
    sep; info "${BOLD}VULN SCAN${NC} — on: ${ports}"; sep

    if [[ -f /usr/share/nmap/scripts/vulners.nse ]]; then
        # shellcheck disable=SC2086
        $nmapBase -sV --script vulners --script-args mincvss=5.0 \
            -p "${ports}" $NMAP_TIMING \
            -oN "${OUTPUT_DIR}/nmap/cves_${TARGET}.nmap" \
            "$TARGET" 2>&1 | tee -a "$LOG_FILE" || true
    else
        warn "vulners.nse missing — skipping CVE scan"
    fi

    # shellcheck disable=SC2086
    $nmapBase -sV --script vuln -p "${ports}" $NMAP_TIMING \
        -oN "${OUTPUT_DIR}/nmap/vulns_${TARGET}.nmap" \
        "$TARGET" 2>&1 | tee -a "$LOG_FILE" || true

    if check_tool nuclei; then
        nuclei -target "$TARGET" -severity medium,high,critical \
            -o "${OUTPUT_DIR}/recon/nuclei_${TARGET}.txt" 2>&1 | tee -a "$LOG_FILE" || true
    else
        warn "nuclei not found — skipping"
    fi
    echo ""
}

# ── Recon helpers ──────────────────────────────────────────────────
recon_web() {
    local port="$1" scheme="$2"
    local url="${scheme}://${TARGET}:${port}"
    local d="${OUTPUT_DIR}/web/${port}_${scheme}"; mkdir -p "$d"
    info "Web → ${BOLD}${url}${NC}"

    check_tool whatweb   && whatweb "$url" --no-errors -a 3 \
        | tee "${d}/whatweb.txt" 2>/dev/null || true

    if [[ "$scheme" == "https" ]]; then
        if check_tool testssl.sh; then
            testssl.sh --quiet --color 0 "${TARGET}:${port}" \
                | tee "${d}/testssl.txt" 2>/dev/null || true
        elif check_tool sslscan; then
            sslscan "${TARGET}:${port}" | tee "${d}/sslscan.txt" 2>/dev/null || true
        fi
    fi

    if check_tool feroxbuster; then
        feroxbuster -u "$url" -w "$WORDLIST" -t "$THREADS" --no-state \
            -o "${d}/feroxbuster.txt" 2>&1 | tee -a "$LOG_FILE" || true
    elif check_tool ffuf; then
        ffuf -u "${url}/FUZZ" -w "$WORDLIST" -t "$THREADS" \
            -mc 200,201,204,301,302,307,401,403 \
            -o "${d}/ffuf.json" -of json 2>&1 | tee -a "$LOG_FILE" || true
    elif check_tool gobuster; then
        local ext=".php,.html,.txt"
        [[ "$osType" == *"Windows"* ]] && ext=".asp,.aspx,.php,.html,.txt"
        gobuster dir -u "$url" -w "$WORDLIST" -t "$THREADS" -e -k -l -x "$ext" \
            -o "${d}/gobuster.txt" 2>&1 | tee -a "$LOG_FILE" || true
    fi

    check_tool nikto && nikto -host "$url" -output "${d}/nikto.txt" \
        -nointeractive 2>&1 | tee -a "$LOG_FILE" || true
    check_tool httpx && echo "$url" | httpx -title -tech-detect -status-code -content-length \
        -o "${d}/httpx.txt" 2>&1 | tee -a "$LOG_FILE" || true

    local cms=""
    local bf="${OUTPUT_DIR}/nmap/basic_${TARGET}.nmap"
    [[ -f "$bf" ]] && cms=$(grep http-generator "$bf" \
        | awk '{print $2}' | head -1 2>/dev/null) || true
    case "${cms,,}" in
        wordpress) check_tool wpscan && wpscan --url "$url" --enumerate p,u,t,cb \
            --output "${d}/wpscan.txt" 2>&1 | tee -a "$LOG_FILE" || true ;;
        joomla*)   check_tool joomscan && joomscan --url "$url" \
            | tee "${d}/joomscan.txt" 2>/dev/null || true ;;
        drupal)    check_tool droopescan && droopescan scan drupal -u "$url" \
            | tee "${d}/droopescan.txt" 2>/dev/null || true ;;
    esac
}

recon_smb() {
    local port="${1:-445}"
    sep; info "${BOLD}SMB RECON${NC} (port ${port})"
    local d="${OUTPUT_DIR}/recon/smb"; mkdir -p "$d"
    check_tool smbmap    && smbmap -H "$TARGET" -u '' -p '' \
        2>&1 | tee "${d}/smbmap_anon.txt"  || true
    check_tool smbmap    && smbmap -H "$TARGET" -u 'guest' -p '' \
        2>&1 | tee "${d}/smbmap_guest.txt" || true
    check_tool smbclient && smbclient -L "//${TARGET}/" -U 'guest%' -N \
        2>&1 | tee "${d}/smbclient.txt"    || true
    if check_tool enum4linux-ng; then
        enum4linux-ng -A "$TARGET" -oA "${d}/enum4linux-ng" \
            2>&1 | tee -a "$LOG_FILE" || true
    elif check_tool enum4linux; then
        enum4linux -a "$TARGET" 2>&1 | tee "${d}/enum4linux.txt" || true
    fi
    # shellcheck disable=SC2086
    $nmapBase -p "${port}" --script "smb-vuln-*,smb2-security-mode,smb-os-discovery" \
        -oN "${d}/smb_nmap.nmap" "$TARGET" 2>&1 | tee -a "$LOG_FILE" || true
    check_tool crackmapexec && crackmapexec smb "$TARGET" \
        2>&1 | tee "${d}/cme.txt" || true
    check_tool netexec      && netexec smb "$TARGET" \
        2>&1 | tee "${d}/netexec.txt" || true
}

recon_dns() {
    sep; info "${BOLD}DNS RECON${NC} (port 53)"
    local d="${OUTPUT_DIR}/recon/dns"; mkdir -p "$d"
    check_tool dig && dig axfr "@${TARGET}" 2>&1 | tee "${d}/zone_transfer.txt" || true
    if check_tool dnsrecon; then
        dnsrecon -r "${subnet}/24" -n "$TARGET" 2>&1 | tee "${d}/dnsrecon.txt"       || true
        dnsrecon -r "127.0.0.0/24" -n "$TARGET" 2>&1 | tee "${d}/dnsrecon_local.txt" || true
    fi
}

recon_ldap() {
    sep; info "${BOLD}LDAP RECON${NC} (port 389/636)"
    local d="${OUTPUT_DIR}/recon/ldap"; mkdir -p "$d"
    if check_tool ldapsearch; then
        ldapsearch -x -H "ldap://${TARGET}" -b '' -s base namingContexts \
            2>&1 | tee "${d}/ldap_base.txt" || true
        local base
        base=$(grep -i namingContexts "${d}/ldap_base.txt" 2>/dev/null \
            | awk '{print $2}' | head -1) || true
        [[ -n "$base" ]] && ldapsearch -x -H "ldap://${TARGET}" -b "$base" '(objectClass=*)' \
            2>&1 | tee "${d}/ldap_dump.txt" || true
    fi
    # shellcheck disable=SC2086
    $nmapBase -p 389,636,3268,3269 --script "ldap-*" \
        -oN "${d}/ldap_nmap.nmap" "$TARGET" 2>&1 | tee -a "$LOG_FILE" || true
}

recon_ftp() {
    local port="${1:-21}"
    sep; info "${BOLD}FTP RECON${NC} (port ${port})"
    local d="${OUTPUT_DIR}/recon/ftp"; mkdir -p "$d"
    # shellcheck disable=SC2086
    $nmapBase -p "${port}" \
        --script "ftp-anon,ftp-bounce,ftp-syst,ftp-vsftpd-backdoor,ftp-vuln-*" \
        -oN "${d}/ftp_nmap.nmap" "$TARGET" 2>&1 | tee -a "$LOG_FILE" || true
}

recon_ssh() {
    local port="${1:-22}"
    sep; info "${BOLD}SSH RECON${NC} (port ${port})"
    local d="${OUTPUT_DIR}/recon/ssh"; mkdir -p "$d"
    # shellcheck disable=SC2086
    $nmapBase -p "${port}" \
        --script "ssh-auth-methods,ssh-hostkey,ssh2-enum-algos,sshv1" \
        -oN "${d}/ssh_nmap.nmap" "$TARGET" 2>&1 | tee -a "$LOG_FILE" || true
}

recon_mssql() {
    local port="${1:-1433}"
    sep; info "${BOLD}MSSQL RECON${NC} (port ${port})"
    local d="${OUTPUT_DIR}/recon/mssql"; mkdir -p "$d"
    # shellcheck disable=SC2086
    $nmapBase -p "${port}" \
        --script "ms-sql-info,ms-sql-empty-password,ms-sql-xp-cmdshell,ms-sql-ntlm-info" \
        -oN "${d}/mssql_nmap.nmap" "$TARGET" 2>&1 | tee -a "$LOG_FILE" || true
}

recon_mysql() {
    local port="${1:-3306}"
    sep; info "${BOLD}MYSQL RECON${NC} (port ${port})"
    local d="${OUTPUT_DIR}/recon/mysql"; mkdir -p "$d"
    # shellcheck disable=SC2086
    $nmapBase -p "${port}" \
        --script "mysql-info,mysql-empty-password,mysql-databases,mysql-users" \
        -oN "${d}/mysql_nmap.nmap" "$TARGET" 2>&1 | tee -a "$LOG_FILE" || true
}

recon_rdp() {
    local port="${1:-3389}"
    sep; info "${BOLD}RDP RECON${NC} (port ${port})"
    local d="${OUTPUT_DIR}/recon/rdp"; mkdir -p "$d"
    # shellcheck disable=SC2086
    $nmapBase -p "${port}" \
        --script "rdp-vuln-ms12-020,rdp-enum-encryption,rdp-nla" \
        -oN "${d}/rdp_nmap.nmap" "$TARGET" 2>&1 | tee -a "$LOG_FILE" || true
}

recon_oracle() {
    local port="${1:-1521}"
    sep; info "${BOLD}ORACLE RECON${NC} (port ${port})"
    local d="${OUTPUT_DIR}/recon/oracle"; mkdir -p "$d"
    # shellcheck disable=SC2086
    $nmapBase -p "${port}" --script "oracle-sid-brute,oracle-tns-poison" \
        -oN "${d}/oracle_nmap.nmap" "$TARGET" 2>&1 | tee -a "$LOG_FILE" || true
}

recon_snmp() {
    sep; info "${BOLD}SNMP RECON${NC} (UDP 161)"
    local d="${OUTPUT_DIR}/recon/snmp"; mkdir -p "$d"
    if check_tool snmpwalk; then
        for c in public private community; do
            snmpwalk -Os -c "$c" -v1 "$TARGET" 2>/dev/null \
                | tee "${d}/snmpwalk_${c}.txt" || true
        done
    fi
}

# ── Smart Recon ────────────────────────────────────────────────────
scan_recon() {
    [[ -z "$basicPorts" ]] && scan_quick && scan_basic
    sep; info "${BOLD}SMART RECON${NC} — service-aware"; sep

    local ports="${allPorts:-$basicPorts}"
    local open_svcs=""
    for f in "${OUTPUT_DIR}/nmap/basic_${TARGET}.nmap" \
             "${OUTPUT_DIR}/nmap/full_detail_${TARGET}.nmap" \
             "${OUTPUT_DIR}/nmap/quick_${TARGET}.nmap"; do
        [[ -f "$f" ]] && open_svcs+="$(grep -w open "$f" 2>/dev/null || true)"$'\n'
    done

    # Web
    for port in $(echo "$ports" | tr ',' '\n'); do
        local ln
        ln=$(echo "$open_svcs" | grep "^${port}/tcp" || true)
        [[ -z "$ln" ]] && continue
        if   echo "$ln" | grep -qi "ssl/http\|https"; then recon_web "$port" "https"
        elif echo "$ln" | grep -qi "http";             then recon_web "$port" "http"
        fi
    done

    # Protocol modules
    echo "$open_svcs" | grep -qw "445/tcp" && recon_smb 445 || true
    echo "$open_svcs" | grep -qw "139/tcp" && ! echo "$open_svcs" | grep -qw "445/tcp" \
        && recon_smb 139 || true
    echo "$open_svcs" | grep -qw "53/tcp"  && recon_dns  || true
    echo "$open_svcs" | grep -qE "389/tcp|636/tcp|3268/tcp" && recon_ldap || true

    for port in $(echo "$ports" | tr ',' '\n'); do
        local ln
        ln=$(echo "$open_svcs" | grep "^${port}/tcp" || true)
        [[ -z "$ln" ]] && continue
        echo "$ln" | grep -qi "ftp"              && recon_ftp    "$port" || true
        echo "$ln" | grep -qi "ssh"              && recon_ssh    "$port" || true
        echo "$ln" | grep -qi "ms-sql\|1433"     && recon_mssql  "$port" || true
        echo "$ln" | grep -qi "mysql\|3306"      && recon_mysql  "$port" || true
        echo "$ln" | grep -qi "ms-wbt\|rdp\|3389" && recon_rdp  "$port" || true
        echo "$ln" | grep -qi "oracle\|1521"     && recon_oracle "$port" || true
    done

    [[ -n "$udpPorts" ]] && echo "$udpPorts" | tr ',' '\n' | grep -q "^161$" \
        && recon_snmp || true
    echo ""
}

# ── API Scan ───────────────────────────────────────────────────────
scan_api() {
    [[ -z "$basicPorts" ]] && scan_quick && scan_basic
    sep; info "${BOLD}API SCAN${NC} — REST / GraphQL / Swagger"; sep
    local d="${OUTPUT_DIR}/recon/api"; mkdir -p "$d"

    local api_paths=("/api" "/api/v1" "/api/v2" "/swagger" "/swagger-ui.html"
        "/openapi.json" "/openapi.yaml" "/api-docs" "/graphql" "/graphiql"
        "/actuator" "/actuator/health" "/health" "/metrics" "/v1" "/v2" "/rest")

    for port in $(echo "${allPorts:-$basicPorts}" | tr ',' '\n'); do
        for scheme in http https; do
            local url="${scheme}://${TARGET}:${port}"
            for path in "${api_paths[@]}"; do
                local st
                st=$(curl -sk -o /dev/null -w "%{http_code}" \
                    --connect-timeout "$TIMEOUT" "${url}${path}" 2>/dev/null) || true
                [[ "$st" =~ ^(200|201|301|302|400|401|403)$ ]] && \
                    echo "${url}${path}  →  HTTP ${st}" | tee -a "${d}/endpoints.txt"
            done
            # GraphQL introspection
            local gql
            gql=$(curl -sk -o "${d}/graphql_${port}.json" -w "%{http_code}" \
                --connect-timeout "$TIMEOUT" \
                -X POST -H "Content-Type: application/json" \
                -d '{"query":"{__schema{queryType{name}}}"}' \
                "${url}/graphql" 2>/dev/null) || true
            [[ "$gql" == "200" ]] && ok "GraphQL introspection enabled: ${url}/graphql"
        done
    done
    echo ""
}

# ── Cloud Scan ─────────────────────────────────────────────────────
scan_cloud() {
    sep; info "${BOLD}CLOUD SCAN${NC} — S3 / Azure / GCP buckets"; sep
    local d="${OUTPUT_DIR}/recon/cloud"; mkdir -p "$d"
    local base
    base=$(echo "$TARGET" | sed 's/\..*//' | tr '[:upper:]' '[:lower:]')

    for name in "$base" "${base}-backup" "${base}-dev" "${base}-prod" \
                "${base}-staging" "${base}-assets" "${base}-static" \
                "${base}-data" "${base}-files" "${base}-uploads"; do
        local s3 az gcp
        s3=$(curl -sk -o /dev/null -w "%{http_code}" --connect-timeout "$TIMEOUT" \
            "https://${name}.s3.amazonaws.com" 2>/dev/null) || true
        az=$(curl -sk -o /dev/null -w "%{http_code}" --connect-timeout "$TIMEOUT" \
            "https://${name}.blob.core.windows.net" 2>/dev/null) || true
        gcp=$(curl -sk -o /dev/null -w "%{http_code}" --connect-timeout "$TIMEOUT" \
            "https://storage.googleapis.com/${name}" 2>/dev/null) || true

        [[ "$s3"  =~ ^(200|403)$ ]] && ok "S3:  ${name}.s3.amazonaws.com (${s3})" \
            | tee -a "${d}/s3.txt"
        [[ "$az"  =~ ^(200|400|403)$ ]] && ok "Azure: ${name}.blob.core.windows.net (${az})" \
            | tee -a "${d}/azure.txt"
        [[ "$gcp" =~ ^(200|403)$ ]] && ok "GCP: storage.googleapis.com/${name} (${gcp})" \
            | tee -a "${d}/gcp.txt"
    done
    echo ""
}

# ── Report ─────────────────────────────────────────────────────────
generate_report() {
    local rpt="${OUTPUT_DIR}/REPORT_${TARGET}.md"
    info "Generating report → ${rpt}"
    local elapsed
    if   (( SECONDS > 3600 )); then elapsed="$((SECONDS/3600))h $(((SECONDS%3600)/60))m $((SECONDS%60))s"
    elif (( SECONDS > 60   )); then elapsed="$((SECONDS/60))m $((SECONDS%60))s"
    else                             elapsed="${SECONDS}s"
    fi
    {
        echo "# ReconX Report"
        echo "| | |"; echo "|---|---|"
        echo "| Target | \`${TARGET}\` |"
        echo "| Scan   | ${SCAN_TYPE} |"
        echo "| Date   | $(date '+%Y-%m-%d %H:%M:%S') |"
        echo "| Time   | ${elapsed} |"
        echo "| OS     | ${osType} |"
        echo "| TCP    | \`${allPorts:-${basicPorts:-none}}\` |"
        echo "| UDP    | \`${udpPorts:-none}\` |"
        echo ""; echo "---"; echo "## Nmap Results"; echo ""
        for f in "${OUTPUT_DIR}"/nmap/*.nmap; do
            [[ -f "$f" ]] || continue
            echo "### $(basename "$f")"; echo '```'; cat "$f"; echo '```'; echo ""
        done
        echo "---"; echo "## Recon Files"; echo ""
        find "${OUTPUT_DIR}/recon" -type f \( -name "*.txt" -o -name "*.json" \) \
            2>/dev/null | sort | while read -r f; do echo "- \`${f#${OUTPUT_DIR}/}\`"; done
        echo ""; echo "---"; echo "*ReconX v${RECONX_VERSION}*"
    } > "$rpt"
    ok "Report saved: ${rpt}"
}

# ── Header / Footer ────────────────────────────────────────────────
print_header() {
    echo ""; sep
    echo -e "  ${BOLD}${CYAN}ReconX v${RECONX_VERSION}${NC}"
    echo -e "  Target    : ${BOLD}${TARGET}${NC}"
    echo -e "  Scan Type : ${BOLD}${SCAN_TYPE}${NC}"
    echo -e "  Output    : ${BOLD}${OUTPUT_DIR}${NC}"
    echo -e "  Timing    : ${BOLD}${NMAP_TIMING}${NC}   Stealth: ${BOLD}${STEALTH}${NC}"
    sep; echo ""
}

print_footer() {
    local elapsed
    if   (( SECONDS > 3600 )); then elapsed="$((SECONDS/3600))h $(((SECONDS%3600)/60))m $((SECONDS%60))s"
    elif (( SECONDS > 60   )); then elapsed="$((SECONDS/60))m $((SECONDS%60))s"
    else                             elapsed="${SECONDS}s"
    fi
    sep
    ok "${BOLD}All scans complete!${NC}"
    echo -e "  Results : ${BOLD}${OUTPUT_DIR}${NC}"
    echo -e "  Log     : ${BOLD}${LOG_FILE}${NC}"
    echo -e "  Time    : ${BOLD}${elapsed}${NC}"
    sep; echo ""
}

# ── Main ───────────────────────────────────────────────────────────
main() {
    banner
    parse_args "$@"
    validate_args
    setup_output
    check_dependencies
    detect_host
    print_header

    case "$SCAN_TYPE" in
        quick)   scan_quick ;;
        basic)   scan_quick; scan_basic ;;
        udp)     scan_udp ;;
        full)    scan_quick; scan_full ;;
        vulns)   scan_quick; scan_basic; scan_vulns ;;
        recon)   scan_quick; scan_basic; scan_recon ;;
        api)     scan_quick; scan_basic; scan_api ;;
        cloud)   scan_cloud ;;
        all)     scan_quick; scan_basic; scan_udp; scan_full
                 scan_vulns; scan_recon; scan_api; scan_cloud ;;
        *)       err "Unknown scan type: ${SCAN_TYPE}"; exit 1 ;;
    esac

    [[ "$MARKDOWN_REPORT" == true ]] && generate_report
    print_footer
}

main "$@"
