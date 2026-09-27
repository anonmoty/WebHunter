#!/usr/bin/env python3
"""
WebHunter - CORS Misconfiguration Scanner
"""

from core.logger import HunterLogger
from core.engine import Vulnerability
from core.utils import make_request, get_headers, delay

log = HunterLogger("CORS")


class CORSCheckScanner:
    """CORS Misconfiguration scanner"""

    def __init__(self, target, engine):
        self.target = target
        self.engine = engine
        self.findings = []

    def scan(self):
        """Run CORS misconfiguration scan"""
        log.info(f"Testing CORS Misconfiguration on {self.target.url}")

        self._test_arbitrary_origin()
        self._test_null_origin()
        self._test_subdomain_origin()
        self._test_prefix_match()

        return self.findings

    def _test_arbitrary_origin(self):
        """Test if arbitrary Origin is reflected"""
        evil_origin = "https://evil-attacker.com"
        headers = get_headers({"Origin": evil_origin})
        r = make_request(self.target.url, headers=headers)

        if r:
            acao = r.headers.get("Access-Control-Allow-Origin", "")
            acac = r.headers.get("Access-Control-Allow-Credentials", "")

            if evil_origin in acao:
                severity = "HIGH" if "true" in acac.lower() else "MEDIUM"
                vuln = Vulnerability(
                    title="CORS: Arbitrary Origin Reflected",
                    severity=severity,
                    description=f"Server reflects arbitrary Origin header in ACAO",
                    url=self.target.url,
                    payload=f"Origin: {evil_origin}",
                    evidence=f"ACAO: {acao}, ACAC: {acac}",
                    remediation="Whitelist specific allowed origins. Don't reflect Origin blindly.",
                    owasp_category="A05 - Security Misconfiguration",
                    module="CORS Scanner"
                )
                self.engine.add_vulnerability(vuln)
                self.findings.append(vuln)

            elif acao == "*":
                vuln = Vulnerability(
                    title="CORS: Wildcard Origin",
                    severity="MEDIUM",
                    description="Server allows any origin with wildcard (*)",
                    url=self.target.url,
                    evidence=f"ACAO: {acao}",
                    remediation="Replace wildcard with specific allowed origins.",
                    owasp_category="A05 - Security Misconfiguration",
                    module="CORS Scanner"
                )
                self.engine.add_vulnerability(vuln)
                self.findings.append(vuln)

    def _test_null_origin(self):
        """Test null origin"""
        headers = get_headers({"Origin": "null"})
        r = make_request(self.target.url, headers=headers)

        if r:
            acao = r.headers.get("Access-Control-Allow-Origin", "")
            if acao == "null":
                vuln = Vulnerability(
                    title="CORS: Null Origin Allowed",
                    severity="HIGH",
                    description="Server allows null Origin which can be exploited via sandboxed iframes",
                    url=self.target.url,
                    payload="Origin: null",
                    evidence=f"ACAO: {acao}",
                    remediation="Don't allow null origin in CORS configuration.",
                    owasp_category="A05 - Security Misconfiguration",
                    module="CORS Scanner"
                )
                self.engine.add_vulnerability(vuln)
                self.findings.append(vuln)

    def _test_subdomain_origin(self):
        """Test if subdomains are trusted"""
        evil_subdomain = f"https://evil.{self.target.hostname}"
        headers = get_headers({"Origin": evil_subdomain})
        r = make_request(self.target.url, headers=headers)

        if r:
            acao = r.headers.get("Access-Control-Allow-Origin", "")
            if evil_subdomain in acao:
                vuln = Vulnerability(
                    title="CORS: Subdomain Trust",
                    severity="MEDIUM",
                    description="Server trusts any subdomain as Origin",
                    url=self.target.url,
                    payload=f"Origin: {evil_subdomain}",
                    evidence=f"ACAO: {acao}",
                    remediation="Validate specific trusted subdomains. Use strict domain matching.",
                    owasp_category="A05 - Security Misconfiguration",
                    module="CORS Scanner"
                )
                self.engine.add_vulnerability(vuln)
                self.findings.append(vuln)

    def _test_prefix_match(self):
        """Test for prefix/suffix matching bypass"""
        test_origins = [
            f"https://{self.target.hostname}.evil.com",
            f"https://evil{self.target.hostname}",
            f"https://{self.target.hostname}evil.com",
        ]

        for origin in test_origins:
            headers = get_headers({"Origin": origin})
            r = make_request(self.target.url, headers=headers)

            if r:
                acao = r.headers.get("Access-Control-Allow-Origin", "")
                if origin in acao:
                    vuln = Vulnerability(
                        title="CORS: Origin Validation Bypass",
                        severity="HIGH",
                        description=f"CORS origin validation can be bypassed with: {origin}",
                        url=self.target.url,
                        payload=f"Origin: {origin}",
                        evidence=f"ACAO: {acao}",
                        remediation="Use strict origin matching. Don't use regex prefix/suffix matching.",
                        owasp_category="A05 - Security Misconfiguration",
                        module="CORS Scanner"
                    )
                    self.engine.add_vulnerability(vuln)
                    self.findings.append(vuln)
                    break
            delay()

        return self.findings
