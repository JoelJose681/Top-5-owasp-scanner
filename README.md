# DVWA OWASP Top 5 Vulnerability Scanner

A beginner-friendly Python scanner built for local DVWA testing on Kali Linux. The tool checks a small set of OWASP Top 5 style issues against a local DVWA instance and generates a clean HTML report.

## Project structure

- `scanner.py` — main Python scanner script
- `requirements.txt` — Python dependencies
- `README.md` — project documentation
- `reports/scan_report.html` — generated HTML scan report
- `.gitignore` — local ignore rules

## Prerequisites

- Kali Linux
- DVWA installed locally and accessible via `http://localhost/DVWA`
- Python 3
- `pip3`

## Setup

1. Install Python dependencies:
   ```bash
   cd /home/kali/Projects/dvwa_scanner
   pip3 install -r requirements.txt
   ```

2. Make sure DVWA is running locally and that the security level is set to `low`.

## Run the scanner

```bash
cd /home/kali/Projects/dvwa_scanner
python3 scanner.py http://localhost/DVWA
```

The scanner will:

- log in to DVWA using default credentials
- test for SQL Injection, XSS, security headers, weak authentication, and sensitive data exposure
- save the report to `reports/scan_report.html`

## View the report

Open the generated report in your browser:

```bash
xdg-open reports/scan_report.html
```

## Ethical use disclaimer

This tool is designed only for local security testing and learning. Use it only against systems you own or are authorized to test. Do not scan external or unauthorized websites.


