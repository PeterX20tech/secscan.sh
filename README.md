# secscan.sh
secscan.sh 
# secscan - Security Assessment Framework 

A modular, bash-based automated security reconnaissance and network scanner designed to streamline target enumeration, service vulnerability identification, and detailed reporting.

---

## Features

- **Automated Enumeration**: Quick TCP port and service scanning using `Nmap`.
- **Modular Architecture**: Modular shell scripts (`modules/`) tailored for specific services (FTP, SSH, HTTP, SMB, DNS, SMTP).
- **Multi-Target Support**: Scan single IP/domain targets or pass a list of targets via a file (`-f`).
- **Comprehensive Reporting**: Generates styled HTML reports, text summaries, and raw scan logs per target under `Reports/`.
- **Colorized Console UI**: Clean and informative terminal output with color-coded status loggers.

---

## Repository Structure

```text
.
├── secscan.sh            # Main execution script
└── modules/              # Enumeration modules
    ├── ftp.sh            # Anonymous FTP check module
    ├── ssh.sh            # SSH banner grab module
    ├── http.sh           # Web server header & robots.txt module
    ├── smb.sh            # SMB share enumeration module
    ├── dns.sh            # DNS zone transfer module
    └── smtp.sh           # SMTP banner check module
