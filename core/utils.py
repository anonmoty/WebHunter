#!/usr/bin/env python3
"""
WebHunter - Utility Functions
"""

import os
import random
import time
import requests
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from core.config import Config

import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def get_random_ua():
    """Get random User-Agent"""
    return random.choice(Config.USER_AGENTS)


def get_headers(custom=None):
    """Generate request headers"""
    headers = {
        "User-Agent": get_random_ua(),
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.5",
        "Accept-Encoding": "gzip, deflate",
        "Connection": "close",
    }
    if custom:
        headers.update(custom)
    return headers


def make_request(url, method="GET", data=None, headers=None, cookies=None,
                 timeout=None, allow_redirects=True, proxies=None):
    """Make HTTP request with error handling"""
    if headers is None:
        headers = get_headers()
    if timeout is None:
        timeout = Config.DEFAULT_TIMEOUT

    try:
        if method.upper() == "GET":
            resp = requests.get(url, headers=headers, cookies=cookies,
                                timeout=timeout, verify=False,
                                allow_redirects=allow_redirects, proxies=proxies)
        elif method.upper() == "POST":
            resp = requests.post(url, data=data, headers=headers, cookies=cookies,
                                 timeout=timeout, verify=False,
                                 allow_redirects=allow_redirects, proxies=proxies)
        elif method.upper() == "PUT":
            resp = requests.put(url, data=data, headers=headers, cookies=cookies,
                                timeout=timeout, verify=False, proxies=proxies)
        elif method.upper() == "DELETE":
            resp = requests.delete(url, headers=headers, cookies=cookies,
                                   timeout=timeout, verify=False, proxies=proxies)
        elif method.upper() == "OPTIONS":
            resp = requests.options(url, headers=headers, timeout=timeout,
                                    verify=False, proxies=proxies)
        elif method.upper() == "HEAD":
            resp = requests.head(url, headers=headers, timeout=timeout,
                                 verify=False, proxies=proxies)
        else:
            return None
        return resp
    except requests.exceptions.RequestException:
        return None


def inject_payload_in_params(url, payload):
    """Inject payload into all URL parameters"""
    parsed = urlparse(url)
    params = parse_qs(parsed.query, keep_blank_values=True)
    results = []

    for param in params:
        modified_params = params.copy()
        modified_params[param] = [payload]
        new_query = urlencode(modified_params, doseq=True)
        new_url = urlunparse((
            parsed.scheme, parsed.netloc, parsed.path,
            parsed.params, new_query, parsed.fragment
        ))
        results.append({"url": new_url, "param": param, "payload": payload})

    return results


def extract_forms(html_content, base_url):
    """Extract forms from HTML"""
    from bs4 import BeautifulSoup
    soup = BeautifulSoup(html_content, "html.parser")
    forms = []

    for form in soup.find_all("form"):
        form_data = {
            "action": form.get("action", ""),
            "method": form.get("method", "GET").upper(),
            "inputs": [],
        }

        if form_data["action"] and not form_data["action"].startswith("http"):
            form_data["action"] = base_url.rstrip("/") + "/" + form_data["action"].lstrip("/")
        elif not form_data["action"]:
            form_data["action"] = base_url

        for inp in form.find_all(["input", "textarea", "select"]):
            input_data = {
                "name": inp.get("name", ""),
                "type": inp.get("type", "text"),
                "value": inp.get("value", ""),
            }
            if input_data["name"]:
                form_data["inputs"].append(input_data)

        forms.append(form_data)

    return forms


def extract_links(html_content, base_url):
    """Extract all links from HTML"""
    from bs4 import BeautifulSoup
    from urllib.parse import urljoin
    soup = BeautifulSoup(html_content, "html.parser")
    links = set()

    for tag in soup.find_all("a", href=True):
        href = tag["href"]
        full_url = urljoin(base_url, href)
        parsed = urlparse(full_url)
        base_parsed = urlparse(base_url)
        if parsed.hostname == base_parsed.hostname:
            links.add(full_url)

    return list(links)


def read_wordlist(filename):
    """Read wordlist file"""
    filepath = os.path.join(Config.WORDLISTS_DIR, filename)
    if os.path.exists(filepath):
        with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
            return [line.strip() for line in f if line.strip() and not line.startswith("#")]
    return []


def delay():
    """Add delay between requests"""
    time.sleep(Config.DELAY_BETWEEN_REQUESTS)
