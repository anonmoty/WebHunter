#!/usr/bin/env python3
"""
WebHunter - Cross-Site Scripting (XSS) Scanner Module
"""

import re
from urllib.parse import quote
from core.logger import HunterLogger
from core.engine import Vulnerability
from core.utils import make_request, inject_payload_in_params, extract_forms, extract_links, delay

log = HunterLogger("XSS")


class XSSScanner:
    """Cross-Site Scripting vulnerability scanner"""

    def __init__(self, target, engine):
        self.target = target
        self.engine = engine
        self.findings = []

        self.payloads = [
            '<script>alert("XSS")</script>',
            '<img src=x onerror=alert("XSS")>',
            '<svg onload=alert("XSS")>',
            '"><script>alert("XSS")</script>',
            "'-alert('XSS')-'",
            '<img src=x onerror=alert(1)>',
            '"><img src=x onerror=alert(1)>',
            "javascript:alert('XSS')",
            '<body onload=alert("XSS")>',
            '<iframe src="javascript:alert(1)">',
            '<details open ontoggle=alert(1)>',
            '<marquee onstart=alert(1)>',
            '{{7*7}}',  # Template injection
            '${7*7}',
            '<script>confirm(document.domain)</script>',
            '" onfocus=alert(1) autofocus="',
            "' onfocus=alert(1) autofocus='",
            '<input onfocus=alert(1) autofocus>',
            '<select autofocus onfocus=alert(1)>',
            '<textarea onfocus=alert(1) autofocus>',
            '<video><source onerror=alert(1)>',
            '<audio src=x onerror=alert(1)>',
            '<math><mtext><table><mglyph><svg><mtext><textarea><path id="</textarea><img onerror=alert(1) src=1>">',
        ]

        self.reflected_indicators = [
            '<script>alert("XSS")</script>',
            '<img src=x onerror=alert("XSS")>',
            '<svg onload=alert("XSS")>',
            'onerror=alert(1)',
            'onload=alert',
            'onfocus=alert(1)',
            'ontoggle=alert(1)',
            'onstart=alert(1)',
            'javascript:alert',
        ]

    def scan(self):
        """Run XSS scan"""
        log.info(f"Testing XSS on {self.target.url}")

        self._test_reflected_xss()
        self._test_dom_xss()
        self._test_form_xss()

        return self.findings

    def _test_reflected_xss(self):
        """Test for reflected XSS in URL parameters"""
        resp = make_request(self.target.url)
        if not resp:
            return

        links = extract_links(resp.text, self.target.url)
        param_urls = [l for l in links if "?" in l]

        test_urls = param_urls[:15]
        if "?" in self.target.url:
            test_urls.insert(0, self.target.url)

        for url in test_urls:
            for i, payload in enumerate(self.payloads):
                log.progress(i + 1, len(self.payloads), f"XSS: {payload[:30]}")
                injected = inject_payload_in_params(url, payload)

                for inj in injected:
                    r = make_request(inj["url"])
                    if r:
                        # Check if payload is reflected unescaped
                        if payload in r.text:
                            vuln = Vulnerability(
                                title="Reflected XSS",
                                severity="HIGH",
                                description=f"XSS payload reflected unescaped in parameter '{inj['param']}'",
                                url=inj["url"],
                                param=inj["param"],
                                payload=payload,
                                evidence=f"Payload reflected in response body",
                                remediation="Encode output. Use Content-Security-Policy header. Sanitize input.",
                                owasp_category="A03 - Injection",
                                module="XSS Scanner"
                            )
                            self.engine.add_vulnerability(vuln)
                            self.findings.append(vuln)
                            return  # Found one, skip rest for this URL
                    delay()

    def _test_dom_xss(self):
        """Check for potential DOM-based XSS sinks"""
        resp = make_request(self.target.url)
        if not resp:
            return

        dom_sinks = [
            r"document\.write\s*\(",
            r"document\.writeln\s*\(",
            r"\.innerHTML\s*=",
            r"\.outerHTML\s*=",
            r"\.insertAdjacentHTML\s*\(",
            r"eval\s*\(",
            r"setTimeout\s*\(\s*['\"]",
            r"setInterval\s*\(\s*['\"]",
            r"location\s*=",
            r"location\.href\s*=",
            r"location\.replace\s*\(",
            r"location\.assign\s*\(",
            r"window\.open\s*\(",
            r"document\.location\s*=",
        ]

        dom_sources = [
            r"location\.hash",
            r"location\.search",
            r"location\.href",
            r"document\.URL",
            r"document\.referrer",
            r"window\.name",
            r"document\.cookie",
        ]

        found_sinks = []
        found_sources = []

        for sink in dom_sinks:
            if re.search(sink, resp.text):
                found_sinks.append(sink)

        for source in dom_sources:
            if re.search(source, resp.text):
                found_sources.append(source)

        if found_sinks and found_sources:
            vuln = Vulnerability(
                title="Potential DOM-based XSS",
                severity="MEDIUM",
                description="Dangerous DOM sinks found with user-controllable sources",
                url=self.target.url,
                evidence=f"Sinks: {found_sinks[:3]}, Sources: {found_sources[:3]}",
                remediation="Avoid using dangerous DOM methods. Sanitize data before insertion.",
                owasp_category="A03 - Injection",
                module="XSS Scanner"
            )
            self.engine.add_vulnerability(vuln)
            self.findings.append(vuln)

    def _test_form_xss(self):
        """Test forms for XSS"""
        resp = make_request(self.target.url)
        if not resp:
            return

        forms = extract_forms(resp.text, self.target.url)
        log.info(f"Testing {len(forms)} form(s) for XSS")

        for form in forms:
            for payload in self.payloads[:8]:
                form_data = {}
                for inp in form["inputs"]:
                    if inp["type"] in ["text", "search", "email", "url", "textarea"]:
                        form_data[inp["name"]] = payload
                    elif inp["type"] == "hidden":
                        form_data[inp["name"]] = inp["value"]
                    else:
                        form_data[inp["name"]] = inp["value"] or "test"

                method = form.get("method", "GET")
                r = make_request(form["action"], method=method, data=form_data)

                if r and payload in r.text:
                    vuln = Vulnerability(
                        title="XSS in Form Input",
                        severity="HIGH",
                        description=f"XSS payload reflected from form at {form['action']}",
                        url=form["action"],
                        param=str(list(form_data.keys())),
                        payload=payload,
                        evidence="Payload reflected unescaped in response",
                        remediation="Sanitize and encode all form inputs. Use CSP headers.",
                        owasp_category="A03 - Injection",
                        module="XSS Scanner"
                    )
                    self.engine.add_vulnerability(vuln)
                    self.findings.append(vuln)
                    return
                delay()

        return self.findings
