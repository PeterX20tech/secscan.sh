#!/bin/bash
REPORT_DIR="Reports"
RED='\033[0;31m'
GREEN='\033[0;32m'
ORANGE='\033[1;33m'
PINK='\033[0;34m'
NO_TING='\033[0m'

log_info() { echo -e "${PINK}[*] $1${NO_TING}"; }
log_success() { echo -e "${GREEN}[+] $1${NO_TING}"; }
log_warn() { echo -e "${ORANGE}[!] $1${NO_TING}"; }
log_error() { echo -e "${RED}[-] $1${NO_TING}"; }

show_help() {
    echo "**************************************************"
    echo "Usage: $0 [TARGET | -f TARGETS_FILE] [OPTIONS]"
    echo ""
    echo "Options:"
    echo "  -h, --help      Display this help message and exit"
    echo "  -f <file>       Scan multiple targets listed in a file"
    echo ""
    echo "Examples:"
    echo "  $0 192.168.xx.xx"
    echo "  $0 -f targets.txt"
    echo "**************************************************"
    exit 0
}

show_version() {
    echo "secscan - Security Assessment Framework v1.0.0"
    exit 0
}

check_dependencies() {
    local deps="nmap nc curl"
    for tool in $deps; do
        if ! command -v "$tool" > /dev/null 2>&1; then
            log_error "Missing dependency: '$tool' is not installed."
            exit 1
        fi
    done
}

load_modules() {
    if [ -f "modules/ftp.sh" ]; then source modules/ftp.sh; fi
    if [ -f "modules/ssh.sh" ]; then source modules/ssh.sh; fi
    if [ -f "modules/http.sh" ]; then source modules/http.sh; fi
    if [ -f "modules/smb.sh" ]; then source modules/smb.sh; fi
    if [ -f "modules/dns.sh" ]; then source modules/dns.sh; fi
    if [ -f "modules/smtp.sh" ]; then source modules/smtp.sh; fi
}

scan_single_target() {
    local TARGET="$1"
    local TARGET_DIR="$REPORT_DIR/$TARGET"
    local RAW_SCAN_FILE="$TARGET_DIR/scan.txt"
    local FINDINGS_FILE="$TARGET_DIR/findings.txt"
    local SUMMARY_FILE="$TARGET_DIR/summary.txt"
    local HTML_REPORT="$TARGET_DIR/report.html"

    log_info "Processing target: $TARGET"

    if ! ping -c 2 -W 2 "$TARGET" > /dev/null 2>&1; then
        log_error "Target $TARGET is unreachable. Skipping."
        return 1
    fi

    mkdir -p "$TARGET_DIR"
    > "$RAW_SCAN_FILE"
    > "$FINDINGS_FILE"
    > "$SUMMARY_FILE"

    log_info "Starting TCP Port & Service Enumeration..."
    nmap -sV --top-ports 100 -T4 "$TARGET" -oN "$RAW_SCAN_FILE" > /dev/null 2>&1

    if grep -q "21/tcp.*open" "$RAW_SCAN_FILE" && declare -f check_ftp > /dev/null; then check_ftp "$TARGET" "$FINDINGS_FILE"; fi
    if grep -q "22/tcp.*open" "$RAW_SCAN_FILE" && declare -f check_ssh > /dev/null; then check_ssh "$TARGET" "$FINDINGS_FILE"; fi
    if grep -qE "(80|8080)/tcp.*open" "$RAW_SCAN_FILE" && declare -f check_http > /dev/null; then check_http "$TARGET" "80" "$FINDINGS_FILE"; fi
    if grep -qE "(445|139)/tcp.*open" "$RAW_SCAN_FILE" && declare -f check_smb > /dev/null; then check_smb "$TARGET" "$FINDINGS_FILE"; fi
    if grep -q "53/tcp.*open" "$RAW_SCAN_FILE" && declare -f check_dns > /dev/null; then check_dns "$TARGET" "$FINDINGS_FILE"; fi
    if grep -q "25/tcp.*open" "$RAW_SCAN_FILE" && declare -f check_smtp > /dev/null; then check_smtp "$TARGET" "$FINDINGS_FILE"; fi

    local open_count
    open_count=$(grep -c -E "^[0-9]+/(tcp|udp).*open" "$RAW_SCAN_FILE" || echo "0")
    local findings_count
    findings_count=$(grep -c "Finding:" "$FINDINGS_FILE" || echo "0")

    cat <<EOF > "$SUMMARY_FILE"
**************************************************
        SECURITY ASSESSMENT SUMMARY REPORT
**************************************************

Target IP/Host : $TARGET
Scan Date      : $(date)
Status         : COMPLETED

[+] ENUMERATION OVERVIEW:
- Total Open Ports Found : $open_count
- Identified Findings    : $findings_count

[+] GENERATED REPORTS LOCATION:
- Raw Scan Log : $RAW_SCAN_FILE
- Findings Log : $FINDINGS_FILE
- Summary Log  : $SUMMARY_FILE

**************************************************
EOF

    local findings_display
    if [ -s "$FINDINGS_FILE" ]; then
        findings_display=$(cat "$FINDINGS_FILE")
    else
        findings_display="No specific security findings or open vulnerabilities detected for this target."
    fi

    local raw_scan_display
    if [ -s "$RAW_SCAN_FILE" ]; then
        raw_scan_display=$(cat "$RAW_SCAN_FILE")
    else
        raw_scan_display="No raw scan results recorded."
    fi

    cat <<EOF > "$HTML_REPORT"
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Security Report - $TARGET</title>
    <style>
        body {
            background-color: #0d0d0d;
            color: #e6e6e6;
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            margin: 0;
            padding: 30px;
        }
        h1 {
            color: #d4af37;
            text-align: center;
            border-bottom: 2px solid #d4af37;
            padding-bottom: 10px;
            text-transform: uppercase;
            letter-spacing: 2px;
        }
        h2 {
            color: #f3e5ab;
            margin-top: 0;
            border-bottom: 1px solid #444;
            padding-bottom: 5px;
        }
        .card {
            background-color: #1a1a1a;
            border: 1px solid #d4af37;
            border-radius: 8px;
            padding: 20px;
            margin-bottom: 25px;
            box-shadow: 0 4px 10px rgba(212, 175, 55, 0.15);
        }
        .highlight {
            color: #d4af37;
            font-weight: bold;
        }
        pre {
            background-color: #050505;
            color: #00ff66;
            border: 1px solid #333;
            padding: 15px;
            border-radius: 5px;
            overflow-x: auto;
            font-family: 'Courier New', Courier, monospace;
            white-space: pre-wrap;
        }
        .separator {
            color: #d4af37;
            font-weight: bold;
            margin: 10px 0;
        }
    </style>
</head>
<body>
    <h1>Security Assessment Report</h1>

    <div class="card">
        <h2>Target Overview</h2>
        <p><span class="highlight">Target IP/Host:</span> $TARGET</p>
        <p><span class="highlight">Scan Date:</span> $(date)</p>
        <p><span class="highlight">Open Ports Found:</span> $open_count</p>
        <p><span class="highlight">Total Findings:</span> $findings_count</p>
    </div>

    <div class="card">
        <h2>Detailed Findings</h2>
        <div class="separator">**************************************************</div>
        <pre>$findings_display</pre>
        <div class="separator">**************************************************</div>
    </div>

    <div class="card">
        <h2>Raw Scan Logs</h2>
        <div class="separator">**************************************************</div>
        <pre>$raw_scan_display</pre>
        <div class="separator">**************************************************</div>
    </div>
</body>
</html>
EOF

    log_success "Target $TARGET completed. Reports saved in $TARGET_DIR/"
}

main() {
    check_dependencies
    load_modules

    if [ "$#" -eq 0 ]; then
        show_help
    fi

    case "$1" in
        -h|--help)
            show_help
            ;;
        -v|--version)
            show_version
            ;;
        -f)
            if [ -z "$2" ] || [ ! -f "$2" ]; then
                log_error "File not found or not specified."
                exit 1
            fi
            while IFS= read -r line || [ -n "$line" ]; do
                [ -z "$line" ] && continue
                scan_single_target "$line"
            done < "$2"
            ;;
        *)
            scan_single_target "$1"
            ;;
    esac
}

main "$@"
