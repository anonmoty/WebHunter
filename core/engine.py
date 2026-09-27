#!/usr/bin/env python3
"""
WebHunter - Core Scan Engine
"""

import time
from datetime import datetime
from core.logger import HunterLogger
from core.config import Config
from core.target import Target
from core.banner import Banner

log = HunterLogger("ScanEngine")


class Vulnerability:
    """Represents a single vulnerability finding"""

    def __init__(self, title, severity, description, url, param="",
                 payload="", evidence="", remediation="", owasp_category="",
                 module=""):
        self.title = title
        self.severity = severity
        self.description = description
        self.url = url
        self.param = param
        self.payload = payload
        self.evidence = evidence
        self.remediation = remediation
        self.owasp_category = owasp_category
        self.module = module
        self.timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    def to_dict(self):
        return {
            "title": self.title,
            "severity": self.severity,
            "description": self.description,
            "url": self.url,
            "param": self.param,
            "payload": self.payload,
            "evidence": self.evidence,
            "remediation": self.remediation,
            "owasp_category": self.owasp_category,
            "module": self.module,
            "timestamp": self.timestamp,
        }


class ScanEngine:
    """Main scanning engine that orchestrates all modules"""

    def __init__(self, target_url):
        self.target = Target(target_url)
        self.vulnerabilities = []
        self.scan_start_time = None
        self.scan_end_time = None
        self.modules_run = []
        self.scan_info = {}

    def validate_target(self):
        """Validate the target before scanning"""
        log.info(f"Validating target: {self.target.url}")
        return self.target.validate()

    def add_vulnerability(self, vuln):
        """Add a vulnerability to findings"""
        if isinstance(vuln, Vulnerability):
            self.vulnerabilities.append(vuln)
            log.vuln(vuln.severity, f"{vuln.title} | {vuln.url}")
        elif isinstance(vuln, dict):
            v = Vulnerability(**vuln)
            self.vulnerabilities.append(v)
            log.vuln(v.severity, f"{v.title} | {v.url}")

    def run_module(self, module_class, module_name):
        """Run a single scan module"""
        Banner.show_scan_banner(module_name)
        log.scan_start(module_name)
        start = time.time()

        try:
            module = module_class(self.target, self)
            findings = module.scan()
            elapsed = round(time.time() - start, 2)
            log.scan_end(f"{module_name} ({elapsed}s)", len(findings) if findings else 0)
            self.modules_run.append({
                "name": module_name,
                "findings": len(findings) if findings else 0,
                "time": elapsed,
            })
            return findings
        except Exception as e:
            log.error(f"Module {module_name} error: {str(e)}")
            return []

    def get_summary(self):
        """Get scan summary"""
        summary = {
            "target": self.target.get_info(),
            "scan_time": {
                "start": self.scan_start_time,
                "end": self.scan_end_time,
            },
            "total_vulnerabilities": len(self.vulnerabilities),
            "severity_count": {
                "CRITICAL": len([v for v in self.vulnerabilities if v.severity == "CRITICAL"]),
                "HIGH": len([v for v in self.vulnerabilities if v.severity == "HIGH"]),
                "MEDIUM": len([v for v in self.vulnerabilities if v.severity == "MEDIUM"]),
                "LOW": len([v for v in self.vulnerabilities if v.severity == "LOW"]),
                "INFO": len([v for v in self.vulnerabilities if v.severity == "INFO"]),
            },
            "modules_run": self.modules_run,
            "vulnerabilities": [v.to_dict() for v in self.vulnerabilities],
        }
        return summary

    def start_timer(self):
        self.scan_start_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    def stop_timer(self):
        self.scan_end_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
