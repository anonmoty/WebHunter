#!/usr/bin/env python3
"""
WebHunter - Configuration Module
"""

import os
from datetime import datetime


class Config:
    """Global configuration for WebHunter"""

    # Framework Info
    APP_NAME = "WebHunter"
    VERSION = "2.0.0"
    AUTHOR = "WebHunter Team"

    # Directories
    BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    CORE_DIR = os.path.join(BASE_DIR, "core")
    MODULES_DIR = os.path.join(BASE_DIR, "modules")
    OUTPUT_DIR = os.path.join(BASE_DIR, "output")
    REPORTS_DIR = os.path.join(OUTPUT_DIR, "reports")
    TEMPLATES_DIR = os.path.join(OUTPUT_DIR, "templates")
    WORDLISTS_DIR = os.path.join(BASE_DIR, "wordlists")

    # Request Settings
    DEFAULT_TIMEOUT = 10
    MAX_RETRIES = 3
    DELAY_BETWEEN_REQUESTS = 0.5
    MAX_THREADS = 10

    # User Agents
    USER_AGENTS = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36",
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/119.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 Chrome/120.0.0.0",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:120.0) Gecko/20100101 Firefox/120.0",
        "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:119.0) Gecko/20100101 Firefox/119.0",
    ]

    # Severity Levels
    SEVERITY = {
        "CRITICAL": {"color": "\033[1;31m", "score": 9.0, "icon": "🔴"},
        "HIGH": {"color": "\033[0;31m", "score": 7.0, "icon": "🟠"},
        "MEDIUM": {"color": "\033[0;33m", "score": 5.0, "icon": "🟡"},
        "LOW": {"color": "\033[0;32m", "score": 3.0, "icon": "🟢"},
        "INFO": {"color": "\033[0;36m", "score": 1.0, "icon": "🔵"},
    }

    # OWASP Top 10 Mapping
    OWASP_MAP = {
        "A01": "Broken Access Control",
        "A02": "Cryptographic Failures",
        "A03": "Injection",
        "A04": "Insecure Design",
        "A05": "Security Misconfiguration",
        "A06": "Vulnerable and Outdated Components",
        "A07": "Identification and Authentication Failures",
        "A08": "Software and Data Integrity Failures",
        "A09": "Security Logging and Monitoring Failures",
        "A10": "Server-Side Request Forgery (SSRF)",
    }

    # Report Settings
    REPORT_FORMATS = ["html", "json", "txt"]

    @classmethod
    def ensure_dirs(cls):
        """Create necessary directories"""
        for d in [cls.REPORTS_DIR, cls.TEMPLATES_DIR, cls.WORDLISTS_DIR]:
            os.makedirs(d, exist_ok=True)

    @classmethod
    def get_report_filename(cls, target, fmt="html"):
        """Generate report filename"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        safe_target = target.replace("https://", "").replace("http://", "").replace("/", "_").replace(":", "_")
        return os.path.join(cls.REPORTS_DIR, f"webhunter_{safe_target}_{timestamp}.{fmt}")
