#!/usr/bin/env python3
"""
WebHunter - Target Handler Module
"""

import re
import socket
from urllib.parse import urlparse, urljoin
import requests
from core.logger import HunterLogger

log = HunterLogger("TargetHandler")


class Target:
    """Handle and validate target information"""

    def __init__(self, url):
        self.original_url = url
        self.url = self._normalize_url(url)
        self.parsed = urlparse(self.url)
        self.hostname = self.parsed.hostname
        self.scheme = self.parsed.scheme
        self.port = self.parsed.port
        self.path = self.parsed.path
        self.ip = None
        self.status_code = None
        self.server = None
        self.technologies = []
        self.is_alive = False

    def _normalize_url(self, url):
        """Normalize the URL"""
        url = url.strip()
        if not url.startswith(("http://", "https://")):
            url = "https://" + url
        if url.endswith("/"):
            url = url[:-1]
        return url

    def validate(self):
        """Validate if target is alive and reachable"""
        try:
            # DNS Resolution
            self.ip = socket.gethostbyname(self.hostname)
            log.info(f"DNS Resolved: {self.hostname} → {self.ip}")

            # HTTP Request
            response = requests.get(
                self.url,
                timeout=10,
                allow_redirects=True,
                verify=False,
                headers={"User-Agent": "WebHunter/2.0"}
            )

            self.status_code = response.status_code
            self.server = response.headers.get("Server", "Unknown")
            self.is_alive = True

            # Detect technologies from headers
            self._detect_tech(response)

            log.info(f"Target is alive! Status: {self.status_code} | Server: {self.server}")
            return True

        except socket.gaierror:
            log.error(f"DNS resolution failed for {self.hostname}")
            return False
        except requests.exceptions.ConnectionError:
            log.error(f"Connection refused: {self.url}")
            return False
        except requests.exceptions.Timeout:
            log.error(f"Connection timed out: {self.url}")
            return False
        except Exception as e:
            log.error(f"Validation error: {str(e)}")
            return False

    def _detect_tech(self, response):
        """Detect technologies from HTTP response"""
        headers = response.headers

        tech_headers = {
            "X-Powered-By": None,
            "X-AspNet-Version": "ASP.NET",
            "X-Generator": None,
            "Server": None,
        }

        for header, tech_name in tech_headers.items():
            if header in headers:
                val = headers[header]
                self.technologies.append(tech_name or val)

        # Check for common frameworks in body
        body = response.text.lower()
        frameworks = {
            "wp-content": "WordPress",
            "joomla": "Joomla",
            "drupal": "Drupal",
            "laravel": "Laravel",
            "django": "Django",
            "react": "React.js",
            "angular": "Angular",
            "vue.js": "Vue.js",
            "next.js": "Next.js",
        }

        for keyword, name in frameworks.items():
            if keyword in body:
                self.technologies.append(name)

        if self.technologies:
            log.info(f"Detected Technologies: {', '.join(set(self.technologies))}")

    def build_url(self, path=""):
        """Build a URL with the given path"""
        return urljoin(self.url, path)

    def get_info(self):
        """Return target information as dict"""
        return {
            "url": self.url,
            "hostname": self.hostname,
            "ip": self.ip,
            "scheme": self.scheme,
            "port": self.port,
            "status_code": self.status_code,
            "server": self.server,
            "technologies": list(set(self.technologies)),
            "is_alive": self.is_alive,
        }
