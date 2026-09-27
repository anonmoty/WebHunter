#!/usr/bin/env python3
"""
WebHunter - Open Redirect Scanner
"""

from urllib.parse import urlparse
from core.logger import HunterLogger
from core.engine import Vulnerability
from core.utils import make_request, inject_payload_in_params, extract_links, delay

log = HunterLogger("OpenRedirect")


class OpenRedirectScanner:
    """Open Redirect vulnerability scanner"""

    def __init__(self, target, engine):
        self.target = target
        self.engine = engine
        self.findings = []

        self.payloads = [
            "https://evil.com",
            "//evil.com",
            "///evil.com",
            "/\\evil.com",
            "https://evil.com%23",
            "https://evil.com%2f%2f",
            "//evil.com/%2f..",
            "https:///evil.com",
            "////evil.com",
            "https://evil.com@{target}",
            "javascript:alert(1)",
            "data:text/html,<script>alert(1)</script>",
            "https://evil.com#@{target}",
            "/redirect?url=https://evil.com",
            "https://evil.com\\@{target}",
        ]

        self.redirect_params = [
            "url", "redirect", "redirect_url", "redirect_uri", "return",
            "return_url", "returnTo", "return_to", "next", "goto", "go",
            "dest", "destination", "redir", "redirect_to", "out", "view",
            "target", "rurl", "continue", "forward", "path", "checkout_url",
            "login_url", "image_url", "callback", "ref",
        ]

    def scan(self):
        """Run Open Redirect scan"""
        log.info(f"Testing Open Redirect on {self.target.url}")

        self._test_url_params()
        self._test_common_redirect_endpoints()

        return self.findings

    def _test_url_params(self):
        """Test URL parameters for open redirect"""
        resp = make_request(self.target.url)
        if not resp:
            return

        links = extract_links(resp.text, self.target.url)
        param_urls = [l for l in links if "?" in l and
                      any(p in l.lower() for p in self.redirect_params)]

        test_urls = param_urls[:10]
        if "?" in self.target.url:
            test_urls.insert(0, self.target.url)

        for url in test_urls:
            for payload in self.payloads[:8]:
                real_payload = payload.replace("{target}", self.target.hostname)
                injected = inject_payload_in_params(url, real_payload)

                for inj in injected:
                    r = make_request(inj["url"], allow_redirects=False)
                    if r and r.status_code in [301, 302, 303, 307, 308]:
                        location = r.headers.get("Location", "")
                        if "evil.com" in location:
                            vuln = Vulnerability(
                                title="Open Redirect",
                                severity="MEDIUM",
                                description=f"Open redirect via parameter '{inj['param']}'",
                                url=inj["url"],
                                param=inj["param"],
                                payload=real_payload,
                                evidence=f"Redirects to: {location}",
                                remediation="Whitelist allowed redirect URLs. Validate redirect targets.",
                                owasp_category="A01 - Broken Access Control",
                                module="Open Redirect Scanner"
                            )
                            self.engine.add_vulnerability(vuln)
                            self.findings.append(vuln)
                            return
                    delay()

    def _test_common_redirect_endpoints(self):
        """Test common redirect endpoints"""
        for param in self.redirect_params:
            for payload in self.payloads[:5]:
                real_payload = payload.replace("{target}", self.target.hostname)
                url = f"{self.target.url}?{param}={real_payload}"
                r = make_request(url, allow_redirects=False)

                if r and r.status_code in [301, 302, 303, 307, 308]:
                    location = r.headers.get("Location", "")
                    if "evil.com" in location:
                        vuln = Vulnerability(
                            title="Open Redirect via Common Parameter",
                            severity="MEDIUM",
                            description=f"Open redirect found using parameter '{param}'",
                            url=url,
                            param=param,
                            payload=real_payload,
                            evidence=f"Redirect Location: {location}",
                            remediation="Validate redirect URLs against whitelist.",
                            owasp_category="A01 - Broken Access Control",
                            module="Open Redirect Scanner"
                        )
                        self.engine.add_vulnerability(vuln)
                        self.findings.append(vuln)
                        return
                delay()

        return self.findings
