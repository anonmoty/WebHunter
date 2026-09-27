#!/usr/bin/env python3
"""
WebHunter - Reconnaissance Module
"""

import socket
import requests
from core.logger import HunterLogger
from core.engine import Vulnerability
from core.utils import make_request, get_headers, extract_links, extract_forms

log = HunterLogger("Recon")


class ReconScanner:
    """Full reconnaissance of the target"""

    def __init__(self, target, engine):
        self.target = target
        self.engine = engine
        self.findings = []

    def scan(self):
        """Run full recon"""
        log.info(f"Starting reconnaissance on {self.target.url}")

        self._whois_lookup()
        self._port_scan()
        self._technology_fingerprint()
        self._crawl_target()
        self._check_robots_sitemap()
        self._check_common_files()

        return self.findings

    def _whois_lookup(self):
        """Basic WHOIS information"""
        try:
            ip = socket.gethostbyname(self.target.hostname)
            log.info(f"IP Address: {ip}")

            # Reverse DNS
            try:
                rdns = socket.gethostbyaddr(ip)
                log.info(f"Reverse DNS: {rdns[0]}")
            except socket.herror:
                pass
        except Exception as e:
            log.error(f"WHOIS lookup failed: {e}")

    def _port_scan(self):
        """Quick port scan on common ports"""
        common_ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 993, 995,
                        3306, 3389, 5432, 8080, 8443, 8888, 9090]
        open_ports = []

        log.info("Running quick port scan...")
        for i, port in enumerate(common_ports):
            log.progress(i + 1, len(common_ports), f"Port {port}")
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1.5)
                result = sock.connect_ex((self.target.hostname, port))
                if result == 0:
                    open_ports.append(port)
                    log.info(f"Open port found: {port}")
                sock.close()
            except Exception:
                pass

        if open_ports:
            vuln = Vulnerability(
                title="Open Ports Discovered",
                severity="INFO",
                description=f"Open ports found: {', '.join(map(str, open_ports))}",
                url=self.target.url,
                evidence=str(open_ports),
                remediation="Review open ports and close unnecessary services.",
                owasp_category="A05 - Security Misconfiguration",
                module="Recon"
            )
            self.engine.add_vulnerability(vuln)
            self.findings.append(vuln)

    def _technology_fingerprint(self):
        """Fingerprint web technologies"""
        resp = make_request(self.target.url)
        if resp:
            techs = self.target.technologies
            if techs:
                vuln = Vulnerability(
                    title="Technology Stack Identified",
                    severity="INFO",
                    description=f"Technologies detected: {', '.join(set(techs))}",
                    url=self.target.url,
                    evidence=str(set(techs)),
                    owasp_category="A06 - Vulnerable Components",
                    module="Recon"
                )
                self.engine.add_vulnerability(vuln)
                self.findings.append(vuln)

    def _crawl_target(self):
        """Crawl target for links and forms"""
        resp = make_request(self.target.url)
        if resp:
            links = extract_links(resp.text, self.target.url)
            forms = extract_forms(resp.text, self.target.url)
            log.info(f"Crawled {len(links)} links and {len(forms)} forms")

            if forms:
                vuln = Vulnerability(
                    title="Forms Discovered",
                    severity="INFO",
                    description=f"{len(forms)} form(s) found on the target",
                    url=self.target.url,
                    evidence=str([f.get("action") for f in forms]),
                    owasp_category="A03 - Injection",
                    module="Recon"
                )
                self.engine.add_vulnerability(vuln)
                self.findings.append(vuln)

    def _check_robots_sitemap(self):
        """Check robots.txt and sitemap.xml"""
        for file in ["robots.txt", "sitemap.xml"]:
            url = f"{self.target.url}/{file}"
            resp = make_request(url)
            if resp and resp.status_code == 200 and len(resp.text) > 10:
                log.success(f"Found: {url}")
                vuln = Vulnerability(
                    title=f"{file} Found",
                    severity="INFO",
                    description=f"{file} is accessible and may reveal hidden paths",
                    url=url,
                    evidence=resp.text[:500],
                    remediation=f"Review {file} for sensitive path disclosure",
                    owasp_category="A01 - Broken Access Control",
                    module="Recon"
                )
                self.engine.add_vulnerability(vuln)
                self.findings.append(vuln)

    def _check_common_files(self):
        """Check for common sensitive files"""
        sensitive_files = [
            ".env", ".git/HEAD", ".git/config", ".svn/entries",
            "wp-config.php.bak", "config.php.bak", ".htaccess",
            "web.config", "phpinfo.php", "info.php",
            "server-status", "server-info",
            ".DS_Store", "crossdomain.xml", "clientaccesspolicy.xml",
            "package.json", "composer.json",
            "backup.zip", "backup.sql", "db.sql",
            ".env.bak", ".env.local", ".env.production",
            "debug.log", "error.log", "access.log",
        ]

        log.info("Checking for sensitive files...")
        for i, file in enumerate(sensitive_files):
            log.progress(i + 1, len(sensitive_files), f"Checking {file}")
            url = f"{self.target.url}/{file}"
            resp = make_request(url)
            if resp and resp.status_code == 200:
                # Filter out custom 404 pages
                if len(resp.text) > 0 and resp.status_code != 404:
                    if "404" not in resp.text.lower()[:200] and "not found" not in resp.text.lower()[:200]:
                        log.success(f"Sensitive file found: {url}")
                        vuln = Vulnerability(
                            title=f"Sensitive File Exposed: {file}",
                            severity="HIGH" if file in [".env", ".git/HEAD", "backup.sql", "db.sql"] else "MEDIUM",
                            description=f"Sensitive file '{file}' is publicly accessible",
                            url=url,
                            evidence=resp.text[:300],
                            remediation=f"Restrict access to '{file}' using server configuration",
                            owasp_category="A01 - Broken Access Control",
                            module="Recon"
                        )
                        self.engine.add_vulnerability(vuln)
                        self.findings.append(vuln)

        return self.findings
