#!/usr/bin/env python3
"""
WebHunter - Authentication Bypass Scanner
"""

from core.logger import HunterLogger
from core.engine import Vulnerability
from core.utils import make_request, get_headers, delay

log = HunterLogger("AuthBypass")


class AuthBypassScanner:
    """Authentication bypass vulnerability scanner"""

    def __init__(self, target, engine):
        self.target = target
        self.engine = engine
        self.findings = []

        self.admin_paths = [
            "/admin", "/admin/", "/administrator", "/admin/login",
            "/admin/dashboard", "/wp-admin", "/wp-login.php",
            "/admin.php", "/login", "/signin", "/auth/login",
            "/panel", "/cpanel", "/dashboard", "/manage",
            "/manager", "/admin/index.php", "/admin/home",
            "/user/login", "/account/login", "/api/admin",
            "/backend", "/control", "/controlpanel",
            "/adminpanel", "/admin1", "/admin2",
            "/phpmyadmin", "/pma", "/dbadmin",
            "/console", "/jmx-console", "/web-console",
        ]

        self.bypass_headers = [
            {"X-Forwarded-For": "127.0.0.1"},
            {"X-Forwarded-Host": "127.0.0.1"},
            {"X-Original-URL": "/admin"},
            {"X-Rewrite-URL": "/admin"},
            {"X-Custom-IP-Authorization": "127.0.0.1"},
            {"X-Real-IP": "127.0.0.1"},
            {"X-Remote-IP": "127.0.0.1"},
            {"X-Client-IP": "127.0.0.1"},
            {"X-Host": "127.0.0.1"},
            {"X-Forwarded": "127.0.0.1"},
            {"Forwarded-For": "127.0.0.1"},
            {"X-ProxyUser-Ip": "127.0.0.1"},
            {"Client-IP": "127.0.0.1"},
            {"True-Client-IP": "127.0.0.1"},
            {"Cluster-Client-IP": "127.0.0.1"},
        ]

    def scan(self):
        """Run auth bypass scan"""
        log.info(f"Testing Authentication Bypass on {self.target.url}")

        self._test_admin_panels()
        self._test_header_bypass()
        self._test_method_bypass()
        self._test_default_credentials()

        return self.findings

    def _test_admin_panels(self):
        """Check for accessible admin panels"""
        log.info("Checking for accessible admin panels...")

        for i, path in enumerate(self.admin_paths):
            log.progress(i + 1, len(self.admin_paths), f"Checking {path}")
            url = f"{self.target.url}{path}"
            r = make_request(url, allow_redirects=False)

            if r:
                if r.status_code == 200:
                    # Check if it's actually an admin page
                    indicators = ["admin", "dashboard", "login", "password", "username",
                                  "sign in", "log in", "panel", "control"]
                    body_lower = r.text.lower()
                    if any(ind in body_lower for ind in indicators):
                        vuln = Vulnerability(
                            title=f"Admin Panel Accessible: {path}",
                            severity="MEDIUM",
                            description=f"Admin panel found at {url}",
                            url=url,
                            evidence=f"HTTP 200 - Admin page accessible",
                            remediation="Restrict admin panel access by IP. Use strong authentication.",
                            owasp_category="A07 - Authentication Failures",
                            module="Auth Bypass Scanner"
                        )
                        self.engine.add_vulnerability(vuln)
                        self.findings.append(vuln)

                elif r.status_code in [301, 302, 303, 307, 308]:
                    location = r.headers.get("Location", "")
                    if "login" not in location.lower() and "auth" not in location.lower():
                        log.info(f"Redirect found: {path} → {location}")
            delay()

    def _test_header_bypass(self):
        """Test header-based authentication bypass"""
        log.info("Testing header-based bypass techniques...")

        for path in ["/admin", "/admin/dashboard", "/api/admin"]:
            url = f"{self.target.url}{path}"

            # First check normal response
            normal_resp = make_request(url)
            if not normal_resp or normal_resp.status_code == 200:
                continue

            for bypass_header in self.bypass_headers:
                headers = get_headers(bypass_header)
                r = make_request(url, headers=headers)

                if r and r.status_code == 200 and normal_resp.status_code in [401, 403]:
                    header_name = list(bypass_header.keys())[0]
                    vuln = Vulnerability(
                        title="Authentication Bypass via Header",
                        severity="CRITICAL",
                        description=f"Auth bypass using header: {header_name}",
                        url=url,
                        payload=str(bypass_header),
                        evidence=f"Normal: HTTP {normal_resp.status_code}, Bypass: HTTP {r.status_code}",
                        remediation="Don't rely on HTTP headers for authentication. Fix server config.",
                        owasp_category="A07 - Authentication Failures",
                        module="Auth Bypass Scanner"
                    )
                    self.engine.add_vulnerability(vuln)
                    self.findings.append(vuln)
                delay()

    def _test_method_bypass(self):
        """Test HTTP method bypass"""
        log.info("Testing HTTP method bypass...")

        methods = ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD", "TRACE"]

        for path in ["/admin", "/admin/dashboard"]:
            url = f"{self.target.url}{path}"

            for method in methods:
                r = make_request(url, method=method)
                if r and r.status_code == 200:
                    # Check if other methods return 403
                    normal = make_request(url, method="GET")
                    if normal and normal.status_code in [401, 403]:
                        vuln = Vulnerability(
                            title=f"HTTP Method Bypass ({method})",
                            severity="HIGH",
                            description=f"Bypassed authentication using {method} method on {path}",
                            url=url,
                            payload=f"Method: {method}",
                            evidence=f"GET: HTTP {normal.status_code}, {method}: HTTP {r.status_code}",
                            remediation="Enforce authentication for all HTTP methods.",
                            owasp_category="A07 - Authentication Failures",
                            module="Auth Bypass Scanner"
                        )
                        self.engine.add_vulnerability(vuln)
                        self.findings.append(vuln)
                delay()

    def _test_default_credentials(self):
        """Test for default credentials on login forms"""
        default_creds = [
            ("admin", "admin"), ("admin", "password"), ("admin", "123456"),
            ("root", "root"), ("root", "toor"), ("admin", "admin123"),
            ("test", "test"), ("user", "user"), ("admin", ""),
            ("administrator", "administrator"),
        ]

        log.info("Testing default credentials...")

        from core.utils import extract_forms
        resp = make_request(self.target.url)
        if not resp:
            return

        # Find login forms
        for path in ["/login", "/admin/login", "/signin", "/auth/login", "/wp-login.php"]:
            url = f"{self.target.url}{path}"
            r = make_request(url)
            if not r or r.status_code != 200:
                continue

            forms = extract_forms(r.text, url)
            for form in forms:
                # Find username and password fields
                user_field = None
                pass_field = None
                for inp in form["inputs"]:
                    if inp["type"] in ["text", "email"] or "user" in inp["name"].lower() or "email" in inp["name"].lower() or "login" in inp["name"].lower():
                        user_field = inp["name"]
                    elif inp["type"] == "password" or "pass" in inp["name"].lower():
                        pass_field = inp["name"]

                if user_field and pass_field:
                    for username, password in default_creds[:5]:
                        form_data = {user_field: username, pass_field: password}
                        # Add other form fields
                        for inp in form["inputs"]:
                            if inp["name"] not in form_data:
                                form_data[inp["name"]] = inp["value"] or ""

                        login_resp = make_request(form["action"], method="POST",
                                                  data=form_data, allow_redirects=True)

                        if login_resp:
                            # Check for successful login indicators
                            fail_indicators = ["invalid", "incorrect", "failed", "wrong",
                                               "error", "denied", "try again"]
                            success_indicators = ["dashboard", "welcome", "logout",
                                                  "profile", "account", "home"]

                            body_lower = login_resp.text.lower()
                            is_failed = any(ind in body_lower for ind in fail_indicators)
                            is_success = any(ind in body_lower for ind in success_indicators)

                            if is_success and not is_failed:
                                vuln = Vulnerability(
                                    title="Default Credentials Working",
                                    severity="CRITICAL",
                                    description=f"Login successful with default credentials: {username}:{password}",
                                    url=form["action"],
                                    payload=f"Username: {username}, Password: {password}",
                                    evidence="Successful login detected",
                                    remediation="Change default credentials immediately. Enforce strong passwords.",
                                    owasp_category="A07 - Authentication Failures",
                                    module="Auth Bypass Scanner"
                                )
                                self.engine.add_vulnerability(vuln)
                                self.findings.append(vuln)
                                return
                        delay()

        return self.findings
