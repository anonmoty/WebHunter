#!/usr/bin/env python3
"""
WebHunter - Security Headers Check Module
"""

from core.logger import HunterLogger
from core.engine import Vulnerability
from core.utils import make_request

log = HunterLogger("Headers")


class HeaderCheckScanner:
    """Security Headers checker"""

    def __init__(self, target, engine):
        self.target = target
        self.engine = engine
        self.findings = []

        self.security_headers = {
            "Content-Security-Policy": {
                "severity": "MEDIUM",
                "description": "CSP helps prevent XSS and data injection attacks",
                "remediation": "Add Content-Security-Policy header with restrictive directives."
            },
            "X-Frame-Options": {
                "severity": "MEDIUM",
                "description": "Protects against clickjacking attacks",
                "remediation": "Add 'X-Frame-Options: DENY' or 'SAMEORIGIN' header."
            },
            "X-Content-Type-Options": {
                "severity": "LOW",
                "description": "Prevents MIME type sniffing",
                "remediation": "Add 'X-Content-Type-Options: nosniff' header."
            },
            "X-XSS-Protection": {
                "severity": "LOW",
                "description": "Enables browser XSS filter",
                "remediation": "Add 'X-XSS-Protection: 1; mode=block' header."
            },
            "Strict-Transport-Security": {
                "severity": "MEDIUM",
                "description": "Enforces HTTPS connections",
                "remediation": "Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains' header."
            },
            "Referrer-Policy": {
                "severity": "LOW",
                "description": "Controls referrer information sent with requests",
                "remediation": "Add 'Referrer-Policy: strict-origin-when-cross-origin' header."
            },
            "Permissions-Policy": {
                "severity": "LOW",
                "description": "Controls which browser features can be used",
                "remediation": "Add Permissions-Policy header to restrict unnecessary features."
            },
            "X-Permitted-Cross-Domain-Policies": {
                "severity": "LOW",
                "description": "Controls cross-domain policy for Flash/PDF",
                "remediation": "Add 'X-Permitted-Cross-Domain-Policies: none' header."
            },
        }

    def scan(self):
        """Run security headers check"""
        log.info(f"Checking Security Headers on {self.target.url}")

        r = make_request(self.target.url)
        if not r:
            log.error("Could not fetch target for header analysis")
            return self.findings

        response_headers = r.headers
        missing_count = 0

        for header, info in self.security_headers.items():
            if header not in response_headers:
                missing_count += 1
                vuln = Vulnerability(
                    title=f"Missing Security Header: {header}",
                    severity=info["severity"],
                    description=info["description"],
                    url=self.target.url,
                    evidence=f"Header '{header}' not present in response",
                    remediation=info["remediation"],
                    owasp_category="A05 - Security Misconfiguration",
                    module="Header Check"
                )
                self.engine.add_vulnerability(vuln)
                self.findings.append(vuln)
            else:
                log.info(f"✅ {header}: {response_headers[header][:80]}")

        # Check for dangerous headers
        dangerous_headers = {
            "X-Powered-By": "Reveals technology stack",
            "Server": "Reveals server software",
            "X-AspNet-Version": "Reveals ASP.NET version",
            "X-AspNetMvc-Version": "Reveals MVC version",
        }

        for header, desc in dangerous_headers.items():
            if header in response_headers:
                vuln = Vulnerability(
                    title=f"Information Disclosure Header: {header}",
                    severity="LOW",
                    description=f"{desc}: {response_headers[header]}",
                    url=self.target.url,
                    evidence=f"{header}: {response_headers[header]}",
                    remediation=f"Remove or suppress the '{header}' header.",
                    owasp_category="A05 - Security Misconfiguration",
                    module="Header Check"
                )
                self.engine.add_vulnerability(vuln)
                self.findings.append(vuln)

        # Cookie security
        cookies = response_headers.get("Set-Cookie", "")
        if cookies:
            if "httponly" not in cookies.lower():
                vuln = Vulnerability(
                    title="Cookie Missing HttpOnly Flag",
                    severity="MEDIUM",
                    description="Cookies accessible via JavaScript (no HttpOnly flag)",
                    url=self.target.url,
                    evidence=f"Set-Cookie: {cookies[:150]}",
                    remediation="Add HttpOnly flag to sensitive cookies.",
                    owasp_category="A05 - Security Misconfiguration",
                    module="Header Check"
                )
                self.engine.add_vulnerability(vuln)
                self.findings.append(vuln)

            if "secure" not in cookies.lower():
                vuln = Vulnerability(
                    title="Cookie Missing Secure Flag",
                    severity="MEDIUM",
                    description="Cookies sent over insecure connections (no Secure flag)",
                    url=self.target.url,
                    evidence=f"Set-Cookie: {cookies[:150]}",
                    remediation="Add Secure flag to all cookies.",
                    owasp_category="A05 - Security Misconfiguration",
                    module="Header Check"
                )
                self.engine.add_vulnerability(vuln)
                self.findings.append(vuln)

        log.info(f"Missing {missing_count}/{len(self.security_headers)} security headers")
        return self.findings
