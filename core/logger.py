#!/usr/bin/env python3
"""
WebHunter - Custom Logger Module
"""

import os
import logging
from datetime import datetime
from colorama import Fore, Style, init

init(autoreset=True)


class HunterLogger:
    """Custom colored logger for WebHunter"""

    def __init__(self, name="WebHunter", log_file=None):
        self.logger = logging.getLogger(name)
        self.logger.setLevel(logging.DEBUG)

        if log_file:
            os.makedirs(os.path.dirname(log_file), exist_ok=True)
            fh = logging.FileHandler(log_file)
            fh.setLevel(logging.DEBUG)
            formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
            fh.setFormatter(formatter)
            self.logger.addHandler(fh)

    @staticmethod
    def _timestamp():
        return datetime.now().strftime("%H:%M:%S")

    def info(self, msg):
        print(f"  {Fore.CYAN}[{self._timestamp()}]{Fore.GREEN} [INFO]{Style.RESET_ALL} {msg}")
        self.logger.info(msg)

    def warning(self, msg):
        print(f"  {Fore.CYAN}[{self._timestamp()}]{Fore.YELLOW} [WARN]{Style.RESET_ALL} {msg}")
        self.logger.warning(msg)

    def error(self, msg):
        print(f"  {Fore.CYAN}[{self._timestamp()}]{Fore.RED} [ERROR]{Style.RESET_ALL} {msg}")
        self.logger.error(msg)

    def critical(self, msg):
        print(f"  {Fore.CYAN}[{self._timestamp()}]{Fore.RED}{Style.BRIGHT} [CRITICAL]{Style.RESET_ALL} {Fore.RED}{msg}{Style.RESET_ALL}")
        self.logger.critical(msg)

    def success(self, msg):
        print(f"  {Fore.CYAN}[{self._timestamp()}]{Fore.GREEN}{Style.BRIGHT} [✓ FOUND]{Style.RESET_ALL} {Fore.GREEN}{msg}{Style.RESET_ALL}")

    def vuln(self, severity, msg):
        colors = {
            "CRITICAL": Fore.RED + Style.BRIGHT,
            "HIGH": Fore.RED,
            "MEDIUM": Fore.YELLOW,
            "LOW": Fore.GREEN,
            "INFO": Fore.CYAN,
        }
        c = colors.get(severity, Fore.WHITE)
        icons = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢", "INFO": "🔵"}
        icon = icons.get(severity, "⚪")
        print(f"  {Fore.CYAN}[{self._timestamp()}] {icon} {c}[{severity}]{Style.RESET_ALL} {msg}")

    def scan_start(self, module_name):
        print(f"\n  {Fore.CYAN}{'═' * 60}")
        print(f"  {Fore.YELLOW}🔍 Starting: {module_name}")
        print(f"  {Fore.CYAN}{'═' * 60}{Style.RESET_ALL}")

    def scan_end(self, module_name, found):
        print(f"  {Fore.CYAN}{'─' * 60}")
        if found > 0:
            print(f"  {Fore.RED}⚠  {module_name} - {found} issue(s) found!")
        else:
            print(f"  {Fore.GREEN}✅ {module_name} - No issues found")
        print(f"  {Fore.CYAN}{'═' * 60}{Style.RESET_ALL}\n")

    def progress(self, current, total, desc=""):
        percent = (current / total) * 100 if total > 0 else 0
        bar_len = 30
        filled = int(bar_len * current // total) if total > 0 else 0
        bar = f"{'█' * filled}{'░' * (bar_len - filled)}"
        print(f"\r  {Fore.CYAN}[{bar}] {percent:.1f}% {desc}{Style.RESET_ALL}", end="", flush=True)
        if current == total:
            print()
