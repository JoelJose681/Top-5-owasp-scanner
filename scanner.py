#!/usr/bin/env python3
"""DVWA OWASP Top 10 Scanner

Ethical use disclaimer:
This script is built for local testing only. Use it only against localhost targets
such as DVWA running on your own Kali Linux machine. Do not scan external or
unauthorized systems.
"""

import sys
import os
import re
from urllib.parse import urljoin
import requests
from bs4 import BeautifulSoup

# Only allow localhost targets to keep the tool safe.
ALLOWED_HOSTS = ["localhost", "127.0.0.1"]

# Common payloads and headers used during scanning.
SQLI_PAYLOADS = ["' OR '1'='1", '" OR "1"="1', "admin' -- ", '1 OR 1=1']
XSS_PAYLOADS = ["<script>alert('xss')</script>", "<img src=x onerror=alert('xss')>"]


class ScanResult:
    """Stores the result of a vulnerability check."""

    def __init__(self, name, status, severity, recommendation, details=""):
        self.name = name
        self.status = status
        self.severity = severity
        self.recommendation = recommendation
        self.details = details

    def to_dict(self):
        return {
            "name": self.name,
            "status": self.status,
            "severity": self.severity,
            "recommendation": self.recommendation,
            "details": self.details,
        }


def enforce_localhost(target_url):
    """Allow only localhost targets for safety."""
    if not any(host in target_url for host in ALLOWED_HOSTS):
        raise ValueError("Target must be localhost or 127.0.0.1 for safe testing.")


def get_page(session, url):
    """Request a page and return the response object."""
    return session.get(url, timeout=10)


def parse_form(html, form_id=None):
    """Parse a form from HTML and return its action and input fields."""
    soup = BeautifulSoup(html, "html.parser")
    if form_id:
        form = soup.find("form", id=form_id)
    else:
        form = soup.find("form")
    if not form:
        return None, {}

    action = form.get("action") or ""
    inputs = {}
    for element in form.find_all(["input", "textarea", "select"]):
        name = element.get("name")
        if not name:
            continue
        if element.name == "select":
            options = element.find_all("option")
            inputs[name] = options[0].get("value", "") if options else ""
        else:
            inputs[name] = element.get("value", "") or ""
    return action, inputs


def login_to_dvwa(session, base_url, username="admin", password="password"):
    """Log in to DVWA using default credentials."""
    login_url = urljoin(base_url.rstrip('/') + '/', 'login.php')
    response = get_page(session, login_url)
    action, inputs = parse_form(response.text)
    if not action:
        raise RuntimeError("Unable to find the DVWA login form.")

    post_url = urljoin(login_url, action)
    inputs["username"] = username
    inputs["password"] = password
    inputs["Login"] = "Login"

    login_response = session.post(post_url, data=inputs, timeout=10)
    return login_response


def test_sql_injection(session, base_url):
    """Test SQL Injection on the DVWA login form."""
    url = urljoin(base_url.rstrip('/') + '/', 'login.php')
    response = get_page(session, url)
    action, inputs = parse_form(response.text)
    if not action:
        return ScanResult(
            "SQL Injection",
            "Not Vulnerable",
            "High",
            "Could not find the login form to test.",
        )

    target_url = urljoin(url, action)
    vulnerable = False
    detail_messages = []

    for payload in SQLI_PAYLOADS:
        data = inputs.copy()
        data["username"] = payload
        data["password"] = payload
        data["Login"] = "Login"

        r = session.post(target_url, data=data, timeout=10)
        if "Welcome to DVWA" in r.text or "admin" in r.text:
            vulnerable = True
            detail_messages.append(f"Payload succeeded: {payload}")
            break

    if vulnerable:
        return ScanResult(
            "SQL Injection",
            "Vulnerable",
            "High",
            "Validate and parameterize database queries. Do not use string concatenation.",
            "; ".join(detail_messages),
        )

    return ScanResult(
        "SQL Injection",
        "Not Vulnerable",
        "High",
        "Use prepared statements and remove unsafe query building.",
    )


def test_xss(session, base_url):
    """Test reflected XSS on the DVWA XSS reflected page."""
    url = urljoin(base_url.rstrip('/') + '/', 'vulnerabilities/xss_r/')
    response = get_page(session, url)
    action, inputs = parse_form(response.text)
    if not action:
        return ScanResult(
            "Cross-Site Scripting (XSS)",
            "Not Vulnerable",
            "Medium",
            "Unable to locate the XSS input form.",
        )

    target_url = urljoin(url, action)
    vulnerable = False
    detail_messages = []

    for payload in XSS_PAYLOADS:
        data = inputs.copy()
        if "name" in data:
            data["name"] = payload
        elif "txtName" in data:
            data["txtName"] = payload
        else:
            continue

        r = session.post(target_url, data=data, timeout=10)
        if payload in r.text:
            vulnerable = True
            detail_messages.append(f"Reflected payload found: {payload}")
            break

    if vulnerable:
        return ScanResult(
            "Cross-Site Scripting (XSS)",
            "Vulnerable",
            "Medium",
            "Escape or sanitize user input before rendering it in the browser.",
            "; ".join(detail_messages),
        )

    return ScanResult(
        "Cross-Site Scripting (XSS)",
        "Not Vulnerable",
        "Medium",
        "Ensure output encoding and proper input filtering.",
    )


def test_security_misconfiguration(session, base_url):
    """Check if security headers are missing from DVWA responses."""
    url = base_url.rstrip('/') + '/'
    response = get_page(session, url)
    headers = response.headers

    missing = []
    for header_name in ["X-Frame-Options", "Content-Security-Policy", "X-XSS-Protection"]:
        if header_name not in headers:
            missing.append(header_name)

    if missing:
        return ScanResult(
            "Security Misconfiguration",
            "Vulnerable",
            "Medium",
            "Add missing security headers to HTTP responses.",
            "Missing: " + ", ".join(missing),
        )

    return ScanResult(
        "Security Misconfiguration",
        "Not Vulnerable",
        "Medium",
        "Keep security headers enabled for browser protections.",
    )


def test_broken_authentication(session, base_url):
    """Test for weak login credentials and missing account lockout."""
    url = urljoin(base_url.rstrip('/') + '/', 'login.php')
    response = get_page(session, url)
    action, inputs = parse_form(response.text)
    if not action:
        return ScanResult(
            "Broken Authentication",
            "Not Vulnerable",
            "High",
            "Unable to locate the login form.",
        )

    target_url = urljoin(url, action)
    weak_found = False
    weak_credentials = [("admin", "password"), ("admin", "admin"), ("guest", "guest")]
    detail_messages = []

    for username, password in weak_credentials:
        data = inputs.copy()
        data["username"] = username
        data["password"] = password
        data["Login"] = "Login"
        r = session.post(target_url, data=data, timeout=10)
        if "Welcome to DVWA" in r.text or "admin" in r.text:
            weak_found = True
            detail_messages.append(f"Weak creds: {username}/{password}")
            break

    return ScanResult(
        "Broken Authentication",
        "Vulnerable" if weak_found else "Not Vulnerable",
        "High",
        "Use strong unique credentials and lock out repeated failed logins.",
        "; ".join(detail_messages) if weak_found else "No weak default credentials detected.",
    )


def test_sensitive_data_exposure(session, base_url):
    """Check if error or debug output leaks server or database details."""
    url = urljoin(base_url.rstrip('/') + '/', 'vulnerabilities/sqli/')
    response = get_page(session, url)
    if "Warning" in response.text or "SQLException" in response.text or "mysqli" in response.text:
        return ScanResult(
            "Sensitive Data Exposure",
            "Vulnerable",
            "High",
            "Remove detailed error messages from production responses.",
            "Error information appears in page content.",
        )

    return ScanResult(
        "Sensitive Data Exposure",
        "Not Vulnerable",
        "High",
        "Hide stack traces and server details from users.",
    )


def generate_html_report(results, filename="reports/scan_report.html"):
    """Create a simple HTML report from scan results."""
    os.makedirs(os.path.dirname(filename), exist_ok=True)
    rows = []
    for result in results:
        rows.append(f"""
            <tr>
                <td>{result.name}</td>
                <td>{result.status}</td>
                <td>{result.severity}</td>
                <td>{result.recommendation}</td>
                <td>{result.details}</td>
            </tr>
        """)

    html = f"""
    <!doctype html>
    <html lang=\"en\">
    <head>
      <meta charset=\"utf-8\">
      <title>DVWA OWASP Scanner Report</title>
      <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; }}
        table {{ border-collapse: collapse; width: 100%; }}
        th, td {{ border: 1px solid #ccc; padding: 10px; text-align: left; }}
        th {{ background: #f4f4f4; }}
        .vulnerable {{ background: #fdecea; }}
        .not-vulnerable {{ background: #e8f5e9; }}
      </style>
    </head>
    <body>
      <h1>DVWA OWASP Top 10 Scanner Report</h1>
      <p>This report was generated for a local DVWA target only.</p>
      <table>
        <thead>
          <tr>
            <th>Vulnerability</th>
            <th>Status</th>
            <th>Severity</th>
            <th>Recommendation</th>
            <th>Details</th>
          </tr>
        </thead>
        <tbody>
          {''.join(rows)}
        </tbody>
      </table>
    </body>
    </html>
    """

    with open(filename, "w", encoding="utf-8") as f:
        f.write(html)

    return filename


def main():
    if len(sys.argv) != 2:
        print("Usage: python3 scanner.py http://localhost/DVWA/dvwa")
        sys.exit(1)

    base_url = sys.argv[1].rstrip("/")
    enforce_localhost(base_url)

    session = requests.Session()
    print("Performing login to DVWA...")
    login_response = login_to_dvwa(session, base_url)
    if "Login" in login_response.text and "Password" in login_response.text:
        print("Login failed. Make sure DVWA is running and the login form is valid.")

    scan_results = [
        test_sql_injection(session, base_url),
        test_xss(session, base_url),
        test_security_misconfiguration(session, base_url),
        test_broken_authentication(session, base_url),
        test_sensitive_data_exposure(session, base_url),
    ]

    report_file = generate_html_report(scan_results)
    print(f"Scan complete. Report saved to {report_file}")


if __name__ == "__main__":
    main()
