#!/usr/bin/env python3
"""
WebHunter - Sensitive Data Exposure Scanner
"""

import re
from core.logger import HunterLogger
from core.engine import Vulnerability
from core.utils import make_request, delay

log = HunterLogger("SensitiveData")


class SensitiveDataScanner:
    """Sensitive Data Exposure scanner (OWASP A02)"""

    def __init__(self, target, engine):
        self.target = target
        self.engine = engine
        self.findings = []

    def scan(self):
        """Run sensitive data exposure scan"""
        log.info(f"Testing Sensitive Data Exposure on {self.target.url}")

        self._check_ssl_tls()
        self._check_sensitive_data_in_response()
        self._check_api_keys_exposure()
        self._check_backup_files()
        self._check_source_code_exposure()

        return self.findings

    def _check_ssl_tls(self):
        """Check SSL/TLS configuration"""
        if self.target.scheme == "http":
            vuln = Vulnerability(
                title="No HTTPS Encryption",
                severity="HIGH",
                description="Website uses HTTP instead of HTTPS",
                url=self.target.url,
                evidence="Scheme: HTTP",
                remediation="Implement HTTPS with a valid SSL/TLS certificate.",
                owasp_category="A02 - Cryptographic Failures",
                module="Sensitive Data Scanner"
            )
            self.engine.add_vulnerability(vuln)
            self.findings.append(vuln)

        r = make_request(self.target.url)
        if r and "Strict-Transport-Security" not in r.headers:
            vuln = Vulnerability(
                title="Missing HSTS Header",
                severity="MEDIUM",
                description="Strict-Transport-Security header is not set",
                url=self.target.url,
                remediation="Add Strict-Transport-Security header with max-age.",
                owasp_category="A02 - Cryptographic Failures",
                module="Sensitive Data Scanner"
            )
            self.engine.add_vulnerability(vuln)
            self.findings.append(vuln)

    def _check_sensitive_data_in_response(self):
        """Check for sensitive data in HTTP responses"""
        r = make_request(self.target.url)
        if not r:
            return

        # Patterns stored as list of tuples to avoid dict brace issues
        patterns = [
            ("Email Address",
             r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'),
            ("API Key Pattern",
             r'(?:api[_-]?key|apikey|api_secret)\s*[:=]\s*["\']?([a-zA-Z0-9_\-]{20,})["\']?'),
            ("AWS Access Key",
             r'AKIA[0-9A-Z]{16}'),
            ("AWS Secret Key",
             r'(?:aws_secret|secret_key)\s*[:=]\s*["\']?([a-zA-Z0-9/+=]{40})["\']?'),
            ("Private Key",
             r'-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----'),
            ("Password in Source",
             r'(?:password|passwd|pwd)\s*[:=]\s*["\']([^"\']+)["\']'),
            ("Database Connection",
             r'(?:mysql|postgres|mongodb|redis)://[^\s<>"]+'),
            ("JWT Token",
             r'eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+'),
            ("Internal IP",
             r'(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})'),
            ("Social Security Number",
             r'\b\d{3}-\d{2}-\d{4}\b'),
            ("Credit Card",
             r'\b(?:4\d{3}|5[1-5]\d{2}|3[47]\d{2}|6011)\d{12}\b'),
            ("Google API Key",
             r'AIza[0-9A-Za-z_-]{35}'),
            ("Slack Token",
             r'xox[baprs]-[0-9A-Za-z-]+'),
            ("GitHub Token",
             r'gh[pousr]_[A-Za-z0-9_]{36}'),
        ]

        critical_names = [
            "AWS Access Key", "Private Key", "Password in Source",
            "Database Connection", "Credit Card"
        ]

        for name, pattern in patterns:
            try:
                matches = re.findall(pattern, r.text, re.IGNORECASE)
            except re.error:
                continue

            if matches:
                severity = "CRITICAL" if name in critical_names else "HIGH"
                vuln = Vulnerability(
                    title="Sensitive Data Exposed: " + name,
                    severity=severity,
                    description=name + " found in response body (" + str(len(matches)) + " occurrence(s))",
                    url=self.target.url,
                    evidence=str(matches[:3]),
                    remediation="Remove " + name + " from client-side code. Use environment variables.",
                    owasp_category="A02 - Cryptographic Failures",
                    module="Sensitive Data Scanner"
                )
                self.engine.add_vulnerability(vuln)
                self.findings.append(vuln)

    def _check_api_keys_exposure(self):
        """Check common API key exposure paths"""
        api_paths = [
            "/api/config", "/api/settings", "/api/v1/config",
            "/config.json", "/settings.json", "/app.config",
            "/env.json", "/api/env", "/.env.json",
        ]

        sensitive_keys = [
            "key", "secret", "password", "token", "api_key",
            "database", "db_", "mysql", "redis", "mongo"
        ]

        for path in api_paths:
            url = self.target.url + path
            r = make_request(url)
            if r and r.status_code == 200:
                body_lower = r.text.lower()
                found = [k for k in sensitive_keys if k in body_lower]

                if found:
                    vuln = Vulnerability(
                        title="API Configuration Exposed: " + path,
                        severity="HIGH",
                        description="Sensitive configuration data exposed at " + url,
                        url=url,
                        evidence="Contains keys: " + ", ".join(found),
                        remediation="Restrict access to configuration endpoints.",
                        owasp_category="A02 - Cryptographic Failures",
                        module="Sensitive Data Scanner"
                    )
                    self.engine.add_vulnerability(vuln)
                    self.findings.append(vuln)
            delay()

    def _check_backup_files(self):
        """Check for backup files with sensitive data"""
        backup_extensions = [
            ".bak", ".old", ".backup", ".save", ".orig",
            ".swp", ".swo", "~", ".copy", ".tmp"
        ]

        test_files = [
            "index", "config", "database", "web", "app",
            "settings", "wp-config", ".htaccess"
        ]

        log.info("Checking for backup files...")
        for f in test_files:
            for ext in backup_extensions:
                url = self.target.url + "/" + f + ext
                r = make_request(url)
                if r and r.status_code == 200 and len(r.text) > 20:
                    if "404" not in r.text.lower()[:100]:
                        vuln = Vulnerability(
                            title="Backup File Found: " + f + ext,
                            severity="HIGH",
                            description="Backup file accessible at " + url,
                            url=url,
                            evidence="HTTP 200 - Size: " + str(len(r.text)) + " bytes",
                            remediation="Remove backup files from production server.",
                            owasp_category="A02 - Cryptographic Failures",
                            module="Sensitive Data Scanner"
                        )
                        self.engine.add_vulnerability(vuln)
                        self.findings.append(vuln)

    def _check_source_code_exposure(self):
        """Check for source code exposure"""
        source_paths = [
            "/.git/HEAD", "/.svn/entries", "/.hg/",
            "/.bzr/", "/CVS/Root", "/WEB-INF/web.xml",
            "/.idea/workspace.xml", "/.vscode/settings.json",
        ]

        for path in source_paths:
            url = self.target.url + path
            r = make_request(url)
            if r and r.status_code == 200 and len(r.text) > 5:
                vuln = Vulnerability(
                    title="Source Code Repository Exposed: " + path,
                    severity="CRITICAL",
                    description="Version control / IDE files accessible at " + url,
                    url=url,
                    evidence=r.text[:200],
                    remediation="Block access to VCS directories in server config.",
                    owasp_category="A05 - Security Misconfiguration",
                    module="Sensitive Data Scanner"
                )
                self.engine.add_vulnerability(vuln)
                self.findings.append(vuln)
            delay()

        return self.findings
