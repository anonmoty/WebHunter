#!/usr/bin/env python3
"""
WebHunter - IDOR (Insecure Direct Object Reference) Scanner
"""

import re
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from core.logger import HunterLogger
from core.engine import Vulnerability
from core.utils import make_request, extract_links, delay

log = HunterLogger("IDOR")


class IDORScanner:
    """IDOR vulnerability scanner"""

    def __init__(self, target, engine):
        self.target = target
        self.engine = engine
        self.findings = []

        self.id_params = [
            "id", "uid", "user_id", "userId", "account", "account_id",
            "doc", "doc_id", "order", "order_id", "invoice", "profile",
            "no", "number", "item", "file", "key", "report", "project",
            "ticket", "customer", "email", "group", "role",
        ]

    def scan(self):
        """Run IDOR scan"""
        log.info(f"Testing IDOR on {self.target.url}")

        self._test_numeric_idor()
        self._test_path_idor()

        return self.findings

    def _test_numeric_idor(self):
        """Test numeric ID parameter manipulation"""
        resp = make_request(self.target.url)
        if not resp:
            return

        links = extract_links(resp.text, self.target.url)
        param_urls = [l for l in links if "?" in l]

        test_urls = param_urls[:20]
        if "?" in self.target.url:
            test_urls.insert(0, self.target.url)

        for url in test_urls:
            parsed = urlparse(url)
            params = parse_qs(parsed.query, keep_blank_values=True)

            for param, values in params.items():
                if param.lower() in self.id_params or (values and values[0].isdigit()):
                    original_value = values[0]

                    # Get original response
                    orig_resp = make_request(url)
                    if not orig_resp:
                        continue

                    # Try different IDs
                    test_values = []
                    if original_value.isdigit():
                        val = int(original_value)
                        test_values = [str(val + 1), str(val - 1), str(val + 100), "1", "0"]
                    else:
                        test_values = ["1", "2", "admin", "test"]

                    for test_val in test_values:
                        modified_params = params.copy()
                        modified_params[param] = [test_val]
                        new_query = urlencode(modified_params, doseq=True)
                        new_url = urlunparse((
                            parsed.scheme, parsed.netloc, parsed.path,
                            parsed.params, new_query, parsed.fragment
                        ))

                        r = make_request(new_url)
                        if r and r.status_code == 200:
                            # Check if different data is returned
                            if (len(r.text) > 100 and
                                    r.text != orig_resp.text and
                                    abs(len(r.text) - len(orig_resp.text)) > 50):
                                vuln = Vulnerability(
                                    title="Potential IDOR - Different Data Accessed",
                                    severity="HIGH",
                                    description=f"Changing parameter '{param}' from '{original_value}' to '{test_val}' returned different data",
                                    url=new_url,
                                    param=param,
                                    payload=f"{original_value} → {test_val}",
                                    evidence=f"Original size: {len(orig_resp.text)}, Modified size: {len(r.text)}",
                                    remediation="Implement proper authorization checks. Use indirect references.",
                                    owasp_category="A01 - Broken Access Control",
                                    module="IDOR Scanner"
                                )
                                self.engine.add_vulnerability(vuln)
                                self.findings.append(vuln)
                                break
                        delay()

    def _test_path_idor(self):
        """Test path-based IDOR"""
        # Check for numeric values in URL path
        path_pattern = re.compile(r'/(\d+)(?:/|$)')
        matches = path_pattern.findall(self.target.url)

        if matches:
            for match in matches:
                original_id = int(match)
                test_ids = [original_id + 1, original_id - 1, 1]

                orig_resp = make_request(self.target.url)
                if not orig_resp:
                    continue

                for test_id in test_ids:
                    new_url = self.target.url.replace(f"/{match}", f"/{test_id}")
                    r = make_request(new_url)

                    if r and r.status_code == 200 and r.text != orig_resp.text:
                        if abs(len(r.text) - len(orig_resp.text)) > 50:
                            vuln = Vulnerability(
                                title="Potential Path-based IDOR",
                                severity="HIGH",
                                description=f"Changing path ID from {match} to {test_id} returned different data",
                                url=new_url,
                                payload=f"/{match} → /{test_id}",
                                evidence=f"HTTP {r.status_code} with different content",
                                remediation="Implement authorization checks for all direct object references.",
                                owasp_category="A01 - Broken Access Control",
                                module="IDOR Scanner"
                            )
                            self.engine.add_vulnerability(vuln)
                            self.findings.append(vuln)
                            break
                    delay()

        return self.findings
