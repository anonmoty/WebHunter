#!/usr/bin/env python3
"""
WebHunter - Subdomain Enumeration Module
"""

import socket
import requests
from core.logger import HunterLogger
from core.engine import Vulnerability
from core.utils import delay

log = HunterLogger("SubdomainEnum")


class SubdomainEnumScanner:
    """Subdomain enumeration scanner"""

    def __init__(self, target, engine):
        self.target = target
        self.engine = engine
        self.findings = []
        self.found_subdomains = []

        self.common_subdomains = [
            "www", "mail", "ftp", "admin", "dev", "staging", "test",
            "api", "app", "blog", "cdn", "cloud", "cpanel", "dashboard",
            "db", "demo", "dns", "docs", "email", "git", "gitlab",
            "help", "imap", "jenkins", "jira", "lab", "ldap", "login",
            "m", "mobile", "monitor", "mx", "mysql", "new", "ns1",
            "ns2", "old", "panel", "pop", "portal", "proxy", "remote",
            "server", "shop", "smtp", "sql", "ssh", "ssl", "stage",
            "static", "store", "support", "svn", "vpn", "webmail",
            "wiki", "www2", "beta", "alpha", "internal", "intranet",
            "backup", "crm", "erp", "office", "owa", "exchange",
            "autodiscover", "sip", "preview", "sandbox", "secure",
        ]

    def scan(self):
        """Run subdomain enumeration"""
        log.info(f"Enumerating subdomains for {self.target.hostname}")

        self._bruteforce_subdomains()
        self._crtsh_lookup()

        if self.found_subdomains:
            vuln = Vulnerability(
                title=f"Subdomains Found: {len(self.found_subdomains)}",
                severity="INFO",
                description=f"Discovered {len(self.found_subdomains)} subdomains",
                url=self.target.url,
                evidence=", ".join(self.found_subdomains[:20]),
                remediation="Review all subdomains for security. Remove unused ones.",
                owasp_category="A05 - Security Misconfiguration",
                module="Subdomain Enum"
            )
            self.engine.add_vulnerability(vuln)
            self.findings.append(vuln)

        return self.findings

    def _bruteforce_subdomains(self):
        """Bruteforce subdomains"""
        domain = self.target.hostname
        # Remove 'www.' if present
        if domain.startswith("www."):
            domain = domain[4:]

        log.info(f"Bruteforcing subdomains for {domain}...")

        for i, sub in enumerate(self.common_subdomains):
            log.progress(i + 1, len(self.common_subdomains), f"Trying: {sub}.{domain}")
            subdomain = f"{sub}.{domain}"
            try:
                ip = socket.gethostbyname(subdomain)
                self.found_subdomains.append(subdomain)
                log.success(f"Found: {subdomain} → {ip}")
            except socket.gaierror:
                pass

    def _crtsh_lookup(self):
        """Look up subdomains via crt.sh"""
        domain = self.target.hostname
        if domain.startswith("www."):
            domain = domain[4:]

        log.info(f"Querying crt.sh for {domain}...")
        try:
            resp = requests.get(
                f"https://crt.sh/?q=%.{domain}&output=json",
                timeout=15
            )
            if resp.status_code == 200:
                data = resp.json()
                for entry in data:
                    name = entry.get("name_value", "")
                    for subdomain in name.split("\n"):
                        subdomain = subdomain.strip().lower()
                        if subdomain and subdomain not in self.found_subdomains:
                            if "*" not in subdomain:
                                self.found_subdomains.append(subdomain)

                log.info(f"crt.sh returned {len(data)} entries")
        except Exception as e:
            log.warning(f"crt.sh lookup failed: {e}")

        self.found_subdomains = list(set(self.found_subdomains))
        log.info(f"Total unique subdomains found: {len(self.found_subdomains)}")
        return self.findings
