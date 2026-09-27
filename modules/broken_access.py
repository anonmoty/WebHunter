#!/usr/bin/env python3
"""
WebHunter - Broken Access Control Scanner
"""

from core.logger import HunterLogger
from core.engine import Vulnerability
from core.utils import make_request, get_headers, delay

log = HunterLogger("BrokenAccess")


class BrokenAccessScanner:
    """Broken Access Control scanner (OWASP A01)"""

    def __init__(self, target, engine):
        self.target = target
        self.engine = engine
        self.findings = []

    def scan(self):
        """Run broken access control scan"""
        log.info(f"Testing Broken Access Control on {self.target.url}")

        self._test_path_traversal()
        self._test_privilege_escalation_endpoints()
        self._test_api_access()
        self._test_forced_browsing()

        return self.findings

    def _test_path_traversal(self):
        """Test for path traversal vulnerabilities"""
        traversal_payloads = [
            "../../../etc/passwd",
            "..\\..\\..\\windows\\win.ini",
            "....//....//....//etc/passwd",
            "..%2f..%2f..%2fetc%2fpasswd",
            "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
            "..%252f..%252f..%252fetc%252fpasswd",
            "/etc/passwd",
            "....\\....\\....\\etc\\passwd",
            "..%c0%af..%c0%af..%c0%afetc/passwd",
            "..%ef%bc%8f..%ef%bc%8f..%ef%bc%8fetc/passwd",
        ]

        success_indicators = ["root:", "/bin/bash", "/bin/sh", "[fonts]", "[extensions]"]

        # Test in URL path
        for payload in traversal_payloads:
            url = f"{self.target.url}/{payload}"
            r = make_request(url)
            if r:
                for ind in success_indicators:
                    if ind in r.text:
                        vuln = Vulnerability(
                            title="Path Traversal / Local File Inclusion",
                            severity="CRITICAL",
                            description="Path traversal allows reading arbitrary server files",
                            url=url,
                            payload=payload,
                            evidence=ind,
                            remediation="Validate and sanitize file paths. Use whitelists.",
                            owasp_category="A01 - Broken Access Control",
                            module="Broken Access Scanner"
                        )
                        self.engine.add_vulnerability(vuln)
                        self.findings.append(vuln)
                        return
            delay()

        # Test in parameters
        if "?" in self.target.url:
            from core.utils import inject_payload_in_params
            for payload in traversal_payloads[:5]:
                injected = inject_payload_in_params(self.target.url, payload)
                for inj in injected:
                    r = make_request(inj["url"])
                    if r:
                        for ind in success_indicators:
                            if ind in r.text:
                                vuln = Vulnerability(
                                    title="Path Traversal via Parameter",
                                    severity="CRITICAL",
                                    description=f"Path traversal in parameter '{inj['param']}'",
                                    url=inj["url"],
                                    param=inj["param"],
                                    payload=payload,
                                    evidence=ind,
                                    remediation="Validate file path parameters. Block path traversal sequences.",
                                    owasp_category="A01 - Broken Access Control",
                                    module="Broken Access Scanner"
                                )
                                self.engine.add_vulnerability(vuln)
                                self.findings.append(vuln)
                                return

    def _test_privilege_escalation_endpoints(self):
        """Test for privilege escalation endpoints"""
        priv_paths = [
            "/api/users", "/api/v1/users", "/api/admin/users",
            "/api/user/1", "/api/user/2", "/api/users/all",
            "/api/admin", "/api/admin/settings",
            "/api/config", "/api/v1/config",
            "/users", "/users/admin",
            "/admin/users", "/admin/settings",
            "/api/roles", "/api/permissions",
        ]

        for path in priv_paths:
            url = f"{self.target.url}{path}"
            r = make_request(url)
            if r and r.status_code == 200:
                # Check for user data
                user_indicators = ["username", "email", "role", "admin",
                                   "password", "token", "users"]
                body_lower = r.text.lower()
                found = [ind for ind in user_indicators if ind in body_lower]

                if len(found) >= 2:
                    vuln = Vulnerability(
                        title=f"Unauthorized Data Access: {path}",
                        severity="HIGH",
                        description=f"Sensitive endpoint accessible without proper auth: {url}",
                        url=url,
                        evidence=f"Contains: {', '.join(found)}",
                        remediation="Implement proper authorization. Use role-based access control.",
                        owasp_category="A01 - Broken Access Control",
                        module="Broken Access Scanner"
                    )
                    self.engine.add_vulnerability(vuln)
                    self.findings.append(vuln)
            delay()

    def _test_api_access(self):
        """Test API endpoints without authentication"""
        api_versions = ["/api/v1", "/api/v2", "/api"]
        api_endpoints = ["/users", "/config", "/admin", "/settings",
                         "/data", "/export", "/backup", "/logs"]

        for ver in api_versions:
            for endpoint in api_endpoints:
                url = f"{self.target.url}{ver}{endpoint}"
                r = make_request(url)
                if r and r.status_code == 200 and len(r.text) > 50:
                    try:
                        import json
                        data = json.loads(r.text)
                        if isinstance(data, (list, dict)) and len(str(data)) > 100:
                            vuln = Vulnerability(
                                title=f"Unprotected API Endpoint: {ver}{endpoint}",
                                severity="HIGH",
                                description=f"API endpoint returns data without authentication",
                                url=url,
                                evidence=f"JSON data returned ({len(r.text)} bytes)",
                                remediation="Add authentication to API endpoints. Use API keys or OAuth.",
                                owasp_category="A01 - Broken Access Control",
                                module="Broken Access Scanner"
                            )
                            self.engine.add_vulnerability(vuln)
                            self.findings.append(vuln)
                    except (json.JSONDecodeError, ValueError):
                        pass
                delay()

    def _test_forced_browsing(self):
        """Test for forced browsing to restricted resources"""
        restricted_paths = [
            "/admin/config", "/admin/backup", "/admin/export",
            "/admin/database", "/admin/logs", "/admin/users/delete",
            "/internal", "/private", "/secret",
            "/api/internal", "/debug/vars",
        ]

        for path in restricted_paths:
            url = f"{self.target.url}{path}"
            r = make_request(url)
            if r and r.status_code == 200 and len(r.text) > 100:
                if "404" not in r.text.lower()[:100] and "not found" not in r.text.lower()[:100]:
                    vuln = Vulnerability(
                        title=f"Forced Browsing: {path}",
                        severity="MEDIUM",
                        description=f"Restricted path accessible via direct browsing: {url}",
                        url=url,
                        evidence=f"HTTP 200 - Size: {len(r.text)}",
                        remediation="Implement proper access controls. Don't rely on obscurity.",
                        owasp_category="A01 - Broken Access Control",
                        module="Broken Access Scanner"
                    )
                    self.engine.add_vulnerability(vuln)
                    self.findings.append(vuln)
            delay()

        return self.findings
