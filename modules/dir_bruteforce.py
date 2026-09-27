#!/usr/bin/env python3
"""
WebHunter - Directory Bruteforce Module
"""

from core.logger import HunterLogger
from core.engine import Vulnerability
from core.utils import make_request, delay

log = HunterLogger("DirBrute")


class DirBruteforceScanner:
    """Directory bruteforce scanner"""

    def __init__(self, target, engine):
        self.target = target
        self.engine = engine
        self.findings = []
        self.found_dirs = []

        self.directories = [
            "admin", "login", "dashboard", "api", "backup", "config",
            "uploads", "upload", "images", "img", "static", "assets",
            "css", "js", "scripts", "fonts", "media", "files",
            "docs", "documentation", "doc", "test", "tests", "dev",
            "staging", "temp", "tmp", "old", "new", "archive",
            "private", "secret", "hidden", "internal", "data",
            "database", "db", "sql", "mysql", "phpmyadmin", "pma",
            "wp-admin", "wp-content", "wp-includes", "wordpress",
            "joomla", "drupal", "magento", "laravel",
            "cgi-bin", "bin", "includes", "include", "inc",
            "lib", "library", "vendor", "node_modules", "packages",
            "log", "logs", "error", "errors", "debug",
            "panel", "cpanel", "webmail", "mail",
            "server-status", "server-info", "status", "info",
            "xmlrpc.php", "wp-login.php", "administrator",
            ".well-known", "robots.txt", "sitemap.xml",
            "graphql", "swagger", "api-docs", "health",
            "console", "terminal", "shell", "cmd",
            "user", "users", "account", "accounts", "profile",
            "register", "signup", "signin", "auth",
            "payment", "checkout", "cart", "shop", "store",
            "search", "results", "download", "downloads",
            "export", "import", "report", "reports",
        ]

    def scan(self):
        """Run directory bruteforce"""
        log.info(f"Bruteforcing directories on {self.target.url}")

        total = len(self.directories)
        for i, directory in enumerate(self.directories):
            log.progress(i + 1, total, f"/{directory}")
            url = f"{self.target.url}/{directory}"
            r = make_request(url, allow_redirects=False)

            if r:
                if r.status_code == 200:
                    if "404" not in r.text.lower()[:100] and "not found" not in r.text.lower()[:100]:
                        self.found_dirs.append({"path": f"/{directory}",
                                                 "status": r.status_code,
                                                 "size": len(r.text)})
                        log.success(f"Found: /{directory} [HTTP {r.status_code}] [{len(r.text)} bytes]")

                elif r.status_code in [301, 302, 307]:
                    location = r.headers.get("Location", "")
                    self.found_dirs.append({"path": f"/{directory}",
                                             "status": r.status_code,
                                             "redirect": location})
                    log.info(f"Redirect: /{directory} → {location}")

                elif r.status_code == 403:
                    self.found_dirs.append({"path": f"/{directory}",
                                             "status": 403})
                    log.warning(f"Forbidden: /{directory} [HTTP 403]")
            delay()

        if self.found_dirs:
            vuln = Vulnerability(
                title=f"Directories Found: {len(self.found_dirs)}",
                severity="INFO",
                description=f"Discovered {len(self.found_dirs)} directories/files",
                url=self.target.url,
                evidence=str([d["path"] for d in self.found_dirs[:20]]),
                remediation="Review exposed directories. Remove unnecessary ones.",
                owasp_category="A01 - Broken Access Control",
                module="Dir Bruteforce"
            )
            self.engine.add_vulnerability(vuln)
            self.findings.append(vuln)

        return self.findings
