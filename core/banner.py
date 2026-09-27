#!/usr/bin/env python3
"""
WebHunter - Professional Banner Module
"""

from colorama import Fore, Back, Style, init
from rich.console import Console
from rich.panel import Panel
from rich.text import Text
import random
import sys
import time

init(autoreset=True)
console = Console()


class Banner:
    """Professional banner display for WebHunter"""

    SKULL = f"""{Fore.RED}
                        ░██╗░░░░░░░██╗███████╗██████╗░
                        ░██║░░██╗░░██║██╔════╝██╔══██╗
                        ░╚██╗████╗██╔╝█████╗░░██████╦╝
                        ░░████╔═████║░██╔══╝░░██╔══██╗
                        ░░╚██╔╝░╚██╔╝░███████╗██████╦╝
                        ░░░╚═╝░░░╚═╝░░╚══════╝╚═════╝░
            {Fore.CYAN}
        ██╗░░██╗██╗░░░██╗███╗░░██╗████████╗███████╗██████╗░
        ██║░░██║██║░░░██║████╗░██║╚══██╔══╝██╔════╝██╔══██╗
        ███████║██║░░░██║██╔██╗██║░░░██║░░░█████╗░░██████╔╝
        ██╔══██║██║░░░██║██║╚████║░░░██║░░░██╔══╝░░██╔══██╗
        ██║░░██║╚██████╔╝██║░╚███║░░░██║░░░███████╗██║░░██║
        ╚═╝░░╚═╝░╚═════╝░╚═╝░░╚══╝░░░╚═╝░░░╚══════╝╚═╝░░╚═╝
    {Style.RESET_ALL}"""

    TAGLINE = f"""
    {Fore.YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    {Fore.WHITE}  ⚡ OWASP Top 10 Bug Bounty Hunter Framework ⚡
    {Fore.GREEN}  ┌─────────────────────────────────────────────────────────────┐
    {Fore.GREEN}  │  Developer : WebHunter Team        Version  : v2.0.0       │
    {Fore.GREEN}  │  Platform  : Termux / Linux        Language : Python 3     │
    {Fore.GREEN}  │  Purpose   : Bug Bounty Hunting    License  : MIT          │
    {Fore.GREEN}  └─────────────────────────────────────────────────────────────┘
    {Fore.YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    {Style.RESET_ALL}"""

    MODULES_INFO = f"""
    {Fore.CYAN}╔═══════════════════════════════════════════════════════════════════╗
    ║                    {Fore.WHITE}🔥 AVAILABLE MODULES 🔥{Fore.CYAN}                      ║
    ╠═══════════════════════════════════════════════════════════════════╣
    ║ {Fore.RED}[01]{Fore.WHITE} SQL Injection Scanner      {Fore.RED}[10]{Fore.WHITE} Open Redirect Scanner   {Fore.CYAN}   ║
    ║ {Fore.RED}[02]{Fore.WHITE} XSS Scanner                {Fore.RED}[11]{Fore.WHITE} Security Headers Check  {Fore.CYAN}   ║
    ║ {Fore.RED}[03]{Fore.WHITE} SSRF Scanner               {Fore.RED}[12]{Fore.WHITE} Subdomain Enumeration   {Fore.CYAN}   ║
    ║ {Fore.RED}[04]{Fore.WHITE} IDOR Scanner               {Fore.RED}[13]{Fore.WHITE} Directory Bruteforce    {Fore.CYAN}   ║
    ║ {Fore.RED}[05]{Fore.WHITE} Auth Bypass Scanner        {Fore.RED}[14]{Fore.WHITE} CORS Misconfiguration   {Fore.CYAN}   ║
    ║ {Fore.RED}[06]{Fore.WHITE} Security Misconfiguration  {Fore.RED}[15]{Fore.WHITE} CRLF Injection          {Fore.CYAN}   ║
    ║ {Fore.RED}[07]{Fore.WHITE} Sensitive Data Exposure    {Fore.RED}[16]{Fore.WHITE} LFI/RFI Scanner         {Fore.CYAN}   ║
    ║ {Fore.RED}[08]{Fore.WHITE} XXE Injection Scanner      {Fore.RED}[17]{Fore.WHITE} Full Recon Mode         {Fore.CYAN}   ║
    ║ {Fore.RED}[09]{Fore.WHITE} CSRF Scanner               {Fore.RED}[00]{Fore.WHITE} Run ALL Modules         {Fore.CYAN}   ║
    ╠═══════════════════════════════════════════════════════════════════╣
    ║ {Fore.YELLOW}[98]{Fore.WHITE} Generate Report            {Fore.YELLOW}[99]{Fore.WHITE} Exit Framework         {Fore.CYAN} ║
    ╚═══════════════════════════════════════════════════════════════════╝
    {Style.RESET_ALL}"""

    @staticmethod
    def typing_effect(text, delay=0.02):
        """Typing animation effect"""
        for char in text:
            sys.stdout.write(char)
            sys.stdout.flush()
            time.sleep(delay)
        print()

    @classmethod
    def show(cls):
        """Display the full banner"""
        print(cls.SKULL)
        print(cls.TAGLINE)

    @classmethod
    def show_modules(cls):
        """Display available modules"""
        print(cls.MODULES_INFO)

    @staticmethod
    def show_scan_banner(module_name):
        """Show scanning banner for a specific module"""
        console.print(Panel(
            f"[bold red]🎯 Scanning Module: {module_name}[/bold red]",
            border_style="cyan",
            padding=(1, 2)
        ))

    @staticmethod
    def show_result_banner(vuln_count, target):
        """Show result summary banner"""
        if vuln_count > 0:
            color = "red"
            status = "⚠️  VULNERABILITIES FOUND"
        else:
            color = "green"
            status = "✅ NO VULNERABILITIES FOUND"

        console.print(Panel(
            f"[bold {color}]{status}\n"
            f"Target: {target}\n"
            f"Total Findings: {vuln_count}[/bold {color}]",
            border_style=color,
            title="[bold white]Scan Results[/bold white]",
            padding=(1, 2)
        ))

    @staticmethod
    def loading_animation(text="Loading", duration=3):
        """Loading bar animation"""
        frames = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]
        end_time = time.time() + duration
        i = 0
        while time.time() < end_time:
            sys.stdout.write(f"\r{Fore.CYAN}{frames[i % len(frames)]} {text}...{Style.RESET_ALL}")
            sys.stdout.flush()
            time.sleep(0.1)
            i += 1
        print(f"\r{Fore.GREEN}✓ {text} Complete!{Style.RESET_ALL}")
