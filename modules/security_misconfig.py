#!/usr/bin/env python3
"""
WebHunter - Security Misconfiguration Scanner
"""

import re
from core.logger import HunterLogger
from core.engine import Vulnerability
from core.utils import make_request, delay

log = HunterLogger("Misconfig")


class SecurityMisconfigScanner:
    """Security Misconfiguration scanner (OWASP A05)"""

    def __init__(self, target, engine):
        self.target = target
        self.engine = engine
        self.findings = []

    def scan(self):
        """Run security misconfiguration scan"""
        log.info(f"Testing Security Misconfiguration on {self.target.url}")

        self._check_debug_mode()
        self._check_directory_listing()
        self._check_http_methods()
        self._check_error_handling()
        self._check_server_info()
        self._check_default_pages()

        return self.findings

    def _check_debug_mode(self):
        """Check if debug mode is enabled"""
        debug_paths = [
            "/__debug__/", "/debug/", "/debug/default/",
            "/elmah.axd", "/trace.axd",
            "/_debugbar/", "/api/debug",
            "/telescope", "/horizon",
            "/__swagger__/", "/swagger-ui.html", "/api-docs",
            "/graphql", "/graphiql",
            "/actuator", "/actuator/health", "/actuator/env",
            "/env", "/configprops", "/metrics",
        ]

        log.info("Checking for debug/development endpoints...")
        for path in debug_paths:
            url = f"{self.target.url}{path}"
            r = make_request(url)
            if r and r.status_code == 200 and len(r.text) > 50:
                if "404" not in r.text.lower()[:200] and "not found" not in r.text.lower()[:200]:
                    vuln = Vulnerability(
                        title=f"Debug/Development Endpoint Exposed: {path}",
                        severity="HIGH",
                        description=f"Debug endpoint accessible at {url}",
                        url=url,
                        evidence=f"HTTP 200 - Content length: {len(r.text)}",
                        remediation="Disable debug mode in production. Remove development endpoints.",
                        owasp_category="A05 - Security Misconfiguration",
                        module="Misconfig Scanner"
                    )
                    self.engine.add_vulnerability(vuln)
                    self.findings.append(vuln)
            delay()

    def _check_directory_listing(self):
        """Check for directory listing"""
        dirs = ["/", "/images/", "/uploads/", "/assets/", "/static/",
                "/css/", "/js/", "/media/", "/files/", "/documents/",
                "/backup/", "/tmp/", "/temp/", "/data/", "/logs/"]

        indicators = ["Index of /", "Directory listing", "Parent Directory",
                       "<title>Index of", "directory listing for"]

        log.info("Checking for directory listing...")
        for d in dirs:
            url = f"{self.target.url}{d}"
            r = make_request(url)
            if r:
                for indicator in indicators:
                    if indicator.lower() in r.text.lower():
                        vuln = Vulnerability(
                            title=f"Directory Listing Enabled: {d}",
                            severity="MEDIUM",
                            description=f"Directory listing is enabled at {url}",
                            url=url,
                            evidence=indicator,
                            remediation="Disable directory listing in web server configuration.",
                            owasp_category="A05 - Security Misconfiguration",
                            module="Misconfig Scanner"
                        )
                        self.engine.add_vulnerability(vuln)
                        self.findings.append(vuln)
                        break
            delay()

    def _check_http_methods(self):
        """Check for dangerous HTTP methods"""
        url = self.target.url
        r = make_request(url, method="OPTIONS")

        if r:
            allow = r.headers.get("Allow", "")
            if allow:
                dangerous = ["PUT", "DELETE", "TRACE", "CONNECT"]
                found_dangerous = [m for m in dangerous if m in allow.upper()]

                if found_dangerous:
                    vuln = Vulnerability(
                        title="Dangerous HTTP Methods Enabled",
                        severity="MEDIUM",
                        description=f"Dangerous methods allowed: {', '.join(found_dangerous)}",
                        url=url,
                        evidence=f"Allow header: {allow}",
                        remediation="Disable unnecessary HTTP methods in server configuration.",
                        owasp_category="A05 - Security Misconfiguration",
                        module="Misconfig Scanner"
                    )
                    self.engine.add_vulnerability(vuln)
                    self.findings.append(vuln)

        # Test TRACE
        r = make_request(url, method="TRACE" if hasattr(make_request, '__code__') else "GET")

    def _check_error_handling(self):
        """Check for verbose error pages"""
        error_urls = [
            f"{self.target.url}/nonexistent_page_12345",
            f"{self.target.url}/'",
            f"{self.target.url}/%00",
            f"{self.target.url}/..%2f..%2fetc%2fpasswd",
            f"{self.target.url}/?id=1'",
        ]

        error_indicators = [
            "stack trace", "traceback", "exception", "error in",
            "syntax error", "parse error", "fatal error",
            "warning:", "notice:", "debug",
            "at line", "on line", "file path",
            r"\/home\/", r"\/var\/www", r"C:\\",
            "microsoft", "apache", "nginx",
        ]

        for url in error_urls:
            r = make_request(url)
            if r:
                for indicator in error_indicators:
                    if re.search(indicator, r.text, re.IGNORECASE):
                        vuln = Vulnerability(
                            title="Verbose Error Messages",
                            severity="LOW",
                            description="Application exposes detailed error information",
                            url=url,
                            evidence=indicator,
                            remediation="Implement custom error pages. Disable verbose errors in production.",
                            owasp_category="A05 - Security Misconfiguration",
                            module="Misconfig Scanner"
                        )
                        self.engine.add_vulnerability(vuln)
                        self.findings.append(vuln)
                        return
            delay()

    def _check_server_info(self):
        """Check for server information disclosure"""
        r = make_request(self.target.url)
        if not r:
            return

        info_headers = ["Server", "X-Powered-By", "X-AspNet-Version",
                        "X-AspNetMvc-Version", "X-Generator"]

        for header in info_headers:
            if header in r.headers:
                vuln = Vulnerability(
                    title=f"Server Information Disclosure: {header}",
                    severity="LOW",
                    description=f"Header '{header}' reveals: {r.headers[header]}",
                    url=self.target.url,
                    evidence=f"{header}: {r.headers[header]}",
                    remediation=f"Remove or modify the '{header}' header.",
                    owasp_category="A05 - Security Misconfiguration",
                    module="Misconfig Scanner"
                )
                self.engine.add_vulnerability(vuln)
                self.findings.append(vuln)

    def _check_default_pages(self):
        """Check for default installation pages"""
        default_pages = {
            "/icons/README": "Apache Default",
            "/server-status": "Apache Status",
            "/nginx_status": "Nginx Status",
            "/web-console/": "JBoss Console",
            "/jmx-console/": "JBoss JMX",
            "/invoker/JMXInvokerServlet": "JBoss Invoker",
        }

        for path, desc in default_pages.items():
            url = f"{self.target.url}{path}"
            r = make_request(url)
            if r and r.status_code == 200 and len(r.text) > 50:
                vuln = Vulnerability(
                    title=f"Default Page Found: {desc}",
                    severity="LOW",
                    description=f"Default {desc} page is accessible",
                    url=url,
                    evidence=f"HTTP 200 at {path}",
                    remediation="Remove or restrict access to default pages.",
                    owasp_category="A05 - Security Misconfiguration",
                    module="Misconfig Scanner"
                )
                self.engine.add_vulnerability(vuln)
                self.findings.append(vuln)
            delay()

        return self.findings
