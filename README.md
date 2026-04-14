# ReconX 🔍

> **Modern Automated Recon & Enumeration Framework**  
> A complete rebuild and upgrade of nmapAutomator faster, smarter, and packed with new capabilities.

---

## What's New vs nmapAutomator

| Feature | nmapAutomator | ReconX |
|---|---|---|
| Scan types | 7 | **9** (+ API, Cloud) |
| Target support | IP only | IP, hostname, CIDR |
| Web tools | gobuster, nikto | feroxbuster > ffuf > gobuster + nikto + whatweb + httpx |
| SMB recon | enum4linux | **enum4linux-ng** + CrackMapExec/NetExec |
| Vuln scanning | vulners + vuln | vulners + vuln + **Nuclei** |
| TLS/SSL | sslscan | **testssl.sh** > sslscan |
| API scanning | ❌ | ✅ REST, GraphQL, Swagger, OpenAPI |
| Cloud assets | ❌ | ✅ S3, Azure Blob, GCP Storage |
| OS detection | TTL only | TTL + service banner refinement |
| Output | flat nmap/ | structured `nmap/`, `recon/`, `web/`, `screenshots/` |
| Resume | ❌ | ✅ `--resume` flag |
| Reports | ❌ | ✅ Markdown report with `--report` |
| Stealth mode | ❌ | ✅ `--stealth` (T2, low rate) |
| Logging | stdout | stdout + timestamped log file |
| Error handling | basic | `set -euo pipefail` + per-tool fallbacks |
| Argument style | positional | named flags (`-t`, `-s`) |

---

## Installation

```bash
git clone https://github.com/mastercode112/reconx.git
cd reconx
chmod +x reconx.sh

# Symlink for system-wide use
sudo ln -s "$(pwd)/reconx.sh" /usr/local/bin/reconx
```

### Dependencies

**Required:**
- `nmap`

**Recommended (auto-detected, graceful fallback if missing):**

```bash
# Kali / Debian
sudo apt install -y gobuster ffuf feroxbuster nikto smbmap \
    enum4linux testssl.sh whatweb dnsrecon sslscan

# Go tools
go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
go install github.com/projectdiscovery/httpx/cmd/httpx@latest

# enum4linux-ng (Python)
pip3 install enum4linux-ng

# wpscan
gem install wpscan

# nmap vulners script
git clone https://github.com/vulnersCom/nmap-vulners /usr/share/nmap/scripts/
nmap --script-updatedb
```

---

## Usage

```bash
reconx.sh [OPTIONS] -t <TARGET> -s <SCAN_TYPE>
```

### Scan Types

| Type | Description | ~Time |
|---|---|---|
| `Quick` | Fast TCP port discovery | 15s |
| `Basic` | Quick + service/version/scripts on open ports | 5m |
| `UDP` | UDP port scan + service detection | 5m |
| `Full` | All 65535 TCP ports + thorough scan on extras | 10m |
| `Vulns` | CVE (vulners) + nmap vuln scripts + Nuclei | 15m |
| `Recon` | Smart service-aware recon (web/smb/ldap/dns/etc.) | 20m |
| `API` | REST/GraphQL/Swagger surface enumeration | 5m |
| `Cloud` | S3/Azure Blob/GCP bucket discovery | 3m |
| `All` | Everything above sequentially | 30-45m |

### Options

```
-t <target>     IP, hostname, or CIDR (e.g., 10.10.10.5, box.htb, 10.0.0.0/24)
-s <type>       Scan type (see table above)
-o <dir>        Custom output directory (default: ./reconx_<target>)
-T <1-5>        Nmap timing template (default: 4)
-r <rate>       Packet rate for full scan (default: 500)
-w <wordlist>   Custom wordlist for web fuzzing
--threads <n>   Threads for recon tools (default: 30)
--stealth       Low-noise mode: T2 timing, rate=100
--no-ping       Skip ping check, force -Pn
--resume        Skip scans where output files already exist
--report        Generate markdown summary report at end
-v              Verbose mode
-h              Help
```

### Examples

```bash
# Quick check for open ports
reconx.sh -t 10.10.10.5 -s Quick

# Full HackTheBox / CTF workflow
reconx.sh -t target.htb -s All --report

# Thorough production recon with stealth
reconx.sh -t 192.168.1.100 -s Recon --stealth -T 2 -o ./client_recon

# API-focused assessment
reconx.sh -t api.target.com -s Basic
reconx.sh -t api.target.com -s API

# Wide subnet discovery
reconx.sh -t 10.0.0.0/24 -s Quick

# Resume after interruption
reconx.sh -t 10.10.10.5 -s All --resume --report
```

---

## Output Structure

```
reconx_10.10.10.5/
├── reconx.log              # Full timestamped session log
├── REPORT_10.10.10.5.md    # Markdown report (if --report used)
├── nmap/
│   ├── quick_10.10.10.5.nmap
│   ├── basic_10.10.10.5.nmap
│   ├── full_10.10.10.5.nmap
│   ├── full_detail_10.10.10.5.nmap
│   ├── udp_10.10.10.5.nmap
│   ├── udp_detail_10.10.10.5.nmap
│   ├── cves_10.10.10.5.nmap
│   └── vulns_10.10.10.5.nmap
├── web/
│   └── 80/
│       ├── whatweb.txt
│       ├── gobuster.txt / ffuf.json / feroxbuster.txt
│       ├── nikto.txt
│       └── httpx.txt
├── recon/
│   ├── smb/
│   │   ├── smbmap.txt
│   │   ├── enum4linux-ng.json
│   │   └── smb_vulns.nmap
│   ├── dns/
│   │   ├── zone_transfer.txt
│   │   └── dnsrecon.txt
│   ├── ldap/
│   │   └── ldap_dump.txt
│   ├── api/
│   │   ├── endpoints.txt
│   │   └── graphql_introspect.json
│   ├── cloud/
│   │   ├── s3.txt
│   │   └── azure.txt
│   ├── nuclei_10.10.10.5.txt
│   └── snmp/, ftp/, ssh/, mssql/, mysql/, rdp/, oracle/
└── screenshots/            # For future eyewitness/gowitness support
```

---

## What Gets Detected & Enumerated

| Service | Detection | Recon Actions |
|---|---|---|
| HTTP/HTTPS | Port + banner | whatweb, feroxbuster/ffuf/gobuster, nikto, httpx, CMS scan, testssl |
| SMB (445/139) | Port | smbmap, smbclient, enum4linux-ng, CrackMapExec, vuln scripts |
| DNS (53) | Port | zone transfer, dnsrecon, dnsx |
| LDAP (389/636) | Port | anonymous bind, base dump, nmap scripts |
| FTP (21) | Port + banner | anon login, vuln scripts |
| SSH (22) | Port + banner | auth methods, host key, algo enum |
| MSSQL (1433) | Port | info, empty password, xp_cmdshell check |
| MySQL (3306) | Port | info, empty password, user/db dump |
| RDP (3389) | Port | MS12-020, encryption check, NLA |
| Oracle (1521) | Port | SID guesser, ODAT integration |
| SNMP (161/UDP) | UDP port | community string walk (public/private) |
| GraphQL | HTTP endpoint | introspection query |
| REST APIs | HTTP endpoint | common path brute force |
| S3/Azure/GCP | Derived from target | bucket name enumeration |

---

## Tips

- Always run as **root** or with `sudo` for UDP scans and raw socket operations.
- Add targets to `/etc/hosts` before running: `echo "10.10.10.5 target.htb" >> /etc/hosts`
- Use `--resume` when re-running after a crash or interruption.
- Combine with [tmux](https://github.com/tmux/tmux) to run in background: `tmux new -s recon "reconx.sh -t 10.10.10.5 -s All --report"`

---

## Contributing

PRs welcome! Ideas for future additions:

- [ ] `eyewitness`/`gowitness` for web screenshots
- [ ] Automatic report to HTML via pandoc
- [ ] SMTP/IMAP/POP3 enum module
- [ ] Kubernetes/Docker API detection
- [ ] IPv6 support
- [ ] Concurrent multi-target mode

---

## Credits

Inspired by [nmapAutomator](https://github.com/21y4d/nmapAutomator) by 21y4d.  
Rebuilt and significantly extended.

## License

MIT
