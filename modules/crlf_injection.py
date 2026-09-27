#!/usr/bin/env python3
"""
WebHunter - CRLF Injection Scanner
"""

from core.logger import HunterLogger
from core.engine import Vulnerability
from core.utils import make_request, inject_payload_in_params, delay

log = HunterLogger("CRLF")


class CRLFInjectionScanner:
    """CRLF Injection scanner"""

    def __init__(self, target, engine):
        self.target = target
        self.engine = engine
        self.findings = []

        self.payloads = [
            "%0d%0aSet-Cookie:crlf=injection",
            "%0aSet-Cookie:crlf=injection",
            "%0d%0a%0d%0a<script>alert(1)</script>",
            "%0d%0aContent-Type:text/html%0d%0a%0d%0a<h1>CRLF</h1>",
            "%%0d0a%0d%0aSet-Cookie:crlf=injection",
            "%E5%98%8A%E5%98%8DSet-Cookie:crlf=injection",  # Unicode bypass
            "%0d%0aLocation:https://evil.com",
            "\r\nSet-Cookie:crlf=injection",
            "\nSet-Cookie:crlf=injection",
            "%0d%0aX-Injected:header",
        ]

    def scan(self):
        """Run CRLF injection scan"""
        log.info(f"Testing CRLF Injection on {self.target.url}")

        self._test_url_crlf()
        self._test_header_crlf()

        return self.findings

    def _test_url_crlf(self):
        """Test URL for CRLF injection"""
        for payload in self.payloads:
            url = f"{self.target.url}/{payload}"
            r = make_request(url, allow_redirects=False)

            if r:
                # Check if injected header appears in response
                if "crlf" in str(r.headers).lower() or "x-injected" in str(r.headers).lower():
                    vuln = Vulnerability(
                        title="CRLF Injection in URL",
                        severity="HIGH",
                        description="CRLF characters in URL cause header injection",
                        url=url,
                        payload=payload,
                        evidence=f"Injected header found in response",
                        remediation="Sanitize all user input. Remove CRLF characters from URLs.",
                        owasp_category="A03 - Injection",
                        module="CRLF Scanner"
                    )
                    self.engine.add_vulnerability(vuln)
                    self.findings.append(vuln)
                    return

                # Check for Set-Cookie injection
                set_cookie = r.headers.get("Set-Cookie", "")
                if "crlf=injection" in set_cookie:
                    vuln = Vulnerability(
                        title="CRLF Injection - Cookie Injection",
                        severity="HIGH",
                        description="CRLF injection allows setting arbitrary cookies",
                        url=url,
                        payload=payload,
                        evidence=f"Set-Cookie: {set_cookie}",
                        remediation="Encode CRLF characters. Validate redirect URLs.",
                        owasp_category="A03 - Injection",
                        module="CRLF Scanner"
                    )
                    self.engine.add_vulnerability(vuln)
                    self.findings.append(vuln)
                    return
            delay()

        # Test in parameters
        if "?" in self.target.url:
            for payload in self.payloads[:5]:
                injected = inject_payload_in_params(self.target.url, payload)
                for inj in injected:
                    r = make_request(inj["url"], allow_redirects=False)
                    if r:
                        if "crlf" in str(r.headers).lower():
                            vuln = Vulnerability(
                                title="CRLF Injection via Parameter",
                                severity="HIGH",
                                description=f"CRLF injection in parameter '{inj['param']}'",
                                url=inj["url"],
                                param=inj["param"],
                                payload=payload,
                                evidence="Header injection detected",
                                remediation="Sanitize parameters. Strip CRLF sequences.",
                                owasp_category="A03 - Injection",
                                module="CRLF Scanner"
                            )
                            self.engine.add_vulnerability(vuln)
                            self.findings.append(vuln)
                            return
                    delay()

    def _test_header_crlf(self):
        """Test for CRLF in headers (via redirect)"""
        redirect_params = ["url", "redirect", "return", "next", "goto"]

        for param in redirect_params:
            for payload in self.payloads[:3]:
                url = f"{self.target.url}?{param}=/{payload}"
                r = make_request(url, allow_redirects=False)
                if r and r.status_code in [301, 302, 307]:
                    location = r.headers.get("Location", "")
                    if "crlf" in str(r.headers).lower():
                        vuln = Vulnerability(
                            title="CRLF Injection via Redirect",
                            severity="HIGH",
                            description=f"CRLF injection via redirect parameter '{param}'",
                            url=url,
                            param=param,
                            payload=payload,
                            evidence=f"Location: {location}",
                            remediation="Validate redirect URLs. Strip CRLF characters.",
                            owasp_category="A03 - Injection",
                            module="CRLF Scanner"
                        )
                        self.engine.add_vulnerability(vuln)
                        self.findings.append(vuln)
                        return
                delay()

        return self.findings
