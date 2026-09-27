#!/usr/bin/env python3
"""
WebHunter - CSRF Scanner
"""

import re
from core.logger import HunterLogger
from core.engine import Vulnerability
from core.utils import make_request, extract_forms, delay

log = HunterLogger("CSRF")


class CSRFScanner:
    """Cross-Site Request Forgery scanner"""

    def __init__(self, target, engine):
        self.target = target
        self.engine = engine
        self.findings = []

    def scan(self):
        """Run CSRF scan"""
        log.info(f"Testing CSRF on {self.target.url}")

        self._check_csrf_tokens()
        self._check_samesite_cookies()
        self._check_referer_validation()

        return self.findings

    def _check_csrf_tokens(self):
        """Check forms for CSRF tokens"""
        resp = make_request(self.target.url)
        if not resp:
            return

        forms = extract_forms(resp.text, self.target.url)
        csrf_token_names = [
            "csrf", "token", "_token", "csrf_token", "csrfmiddlewaretoken",
            "authenticity_token", "anti-csrf-token", "__RequestVerificationToken",
            "_csrf", "nonce", "csrf-token", "xsrf",
        ]

        for form in forms:
            if form["method"] == "POST":
                has_csrf = False
                for inp in form["inputs"]:
                    if any(name in inp["name"].lower() for name in csrf_token_names):
                        has_csrf = True
                        break

                if not has_csrf:
                    vuln = Vulnerability(
                        title="Missing CSRF Token in Form",
                        severity="MEDIUM",
                        description=f"POST form at {form['action']} lacks CSRF protection",
                        url=form["action"],
                        evidence=f"No CSRF token found in form inputs: {[i['name'] for i in form['inputs']]}",
                        remediation="Add CSRF tokens to all state-changing forms.",
                        owasp_category="A01 - Broken Access Control",
                        module="CSRF Scanner"
                    )
                    self.engine.add_vulnerability(vuln)
                    self.findings.append(vuln)

        # Also check pages linked from the main page
        from core.utils import extract_links
        links = extract_links(resp.text, self.target.url)
        for link in links[:10]:
            r = make_request(link)
            if r:
                link_forms = extract_forms(r.text, link)
                for form in link_forms:
                    if form["method"] == "POST":
                        has_csrf = any(
                            any(name in inp["name"].lower() for name in csrf_token_names)
                            for inp in form["inputs"]
                        )
                        if not has_csrf:
                            vuln = Vulnerability(
                                title="Missing CSRF Token",
                                severity="MEDIUM",
                                description=f"POST form at {form['action']} lacks CSRF protection",
                                url=form["action"],
                                evidence="No CSRF token in form",
                                remediation="Implement CSRF tokens for all state-changing operations.",
                                owasp_category="A01 - Broken Access Control",
                                module="CSRF Scanner"
                            )
                            self.engine.add_vulnerability(vuln)
                            self.findings.append(vuln)
                            break
            delay()

    def _check_samesite_cookies(self):
        """Check SameSite attribute on cookies"""
        r = make_request(self.target.url)
        if not r:
            return

        cookies = r.headers.get("Set-Cookie", "")
        if cookies and "samesite" not in cookies.lower():
            vuln = Vulnerability(
                title="Missing SameSite Cookie Attribute",
                severity="LOW",
                description="Cookies don't have SameSite attribute set",
                url=self.target.url,
                evidence=f"Set-Cookie: {cookies[:200]}",
                remediation="Set SameSite=Lax or SameSite=Strict on cookies.",
                owasp_category="A01 - Broken Access Control",
                module="CSRF Scanner"
            )
            self.engine.add_vulnerability(vuln)
            self.findings.append(vuln)

    def _check_referer_validation(self):
        """Check if server validates Referer header"""
        headers_with_fake_referer = {
            "Referer": "https://evil-attacker.com"
        }

        # Test on POST endpoints
        r = make_request(self.target.url)
        if not r:
            return

        forms = extract_forms(r.text, self.target.url)
        for form in forms:
            if form["method"] == "POST":
                form_data = {}
                for inp in form["inputs"]:
                    form_data[inp["name"]] = inp["value"] or "test"

                from core.utils import get_headers
                headers = get_headers(headers_with_fake_referer)
                resp = make_request(form["action"], method="POST",
                                    data=form_data, headers=headers)

                if resp and resp.status_code in [200, 302]:
                    # If request succeeds with fake referer, might be vulnerable
                    vuln = Vulnerability(
                        title="No Referer Validation",
                        severity="LOW",
                        description=f"Form at {form['action']} accepts requests with fake Referer header",
                        url=form["action"],
                        evidence="Request with evil Referer was not blocked",
                        remediation="Validate Referer/Origin headers for state-changing requests.",
                        owasp_category="A01 - Broken Access Control",
                        module="CSRF Scanner"
                    )
                    self.engine.add_vulnerability(vuln)
                    self.findings.append(vuln)
                    break
            delay()

        return self.findings
