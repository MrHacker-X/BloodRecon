#!/usr/bin/env python3
"""
User-Agent Analyzer Module
Analyze and detect information from user-agent strings
Author : Alex Butler (@MrHacker-X)
Org    : Vritra Security Organization
"""

import re
from bloodrecon.modules.colors import Fore, Style

def analyze_useragent(user_agent):
    """Analyze user-agent string"""
    try:
        print(f"\n{Fore.CYAN}╔══════════════════════════════════════════════════════════════╗")
        print(f"║                   {Fore.YELLOW}USER-AGENT ANALYZER{Fore.CYAN}                        ║")
        print(f"╚══════════════════════════════════════════════════════════════╝{Style.RESET_ALL}")
        
        print(f"\n{Fore.GREEN}[+] User-Agent Analysis:{Style.RESET_ALL}")
        print(f"    {Fore.YELLOW}{user_agent}{Style.RESET_ALL}")
        
        # Detect browser
        browsers = {
            r'Chrome/(\d+)': 'Google Chrome',
            r'Firefox/(\d+)': 'Mozilla Firefox',
            r'Safari/(\d+)': 'Apple Safari',
            r'Edge/(\d+)': 'Microsoft Edge',
            r'OPR/(\d+)': 'Opera',
            r'Trident.*rv:(\d+)': 'Internet Explorer'
        }
        
        detected_browser = None
        browser_version = None
        
        for pattern, name in browsers.items():
            match = re.search(pattern, user_agent)
            if match:
                detected_browser = name
                browser_version = match.group(1)
                break
        
        if detected_browser:
            print(f"\n{Fore.GREEN}[+] Browser Information:{Style.RESET_ALL}")
            print(f"    Browser: {Fore.CYAN}{detected_browser}{Style.RESET_ALL}")
            print(f"    Version: {Fore.CYAN}{browser_version}{Style.RESET_ALL}")
        else:
            print(f"\n{Fore.YELLOW}[!] Browser: Unknown or custom user-agent{Style.RESET_ALL}")
        
        # Detect operating system
        os_patterns = {
            r'Windows NT (\d+\.\d+)': 'Windows',
            r'Mac OS X ([\d_]+)': 'macOS',
            r'Linux': 'Linux',
            r'Android (\d+)': 'Android',
            r'iPhone.*OS (\d+)': 'iOS',
            r'iPad.*OS (\d+)': 'iPadOS'
        }
        
        detected_os = None
        os_version = None
        
        for pattern, name in os_patterns.items():
            match = re.search(pattern, user_agent)
            if match:
                detected_os = name
                if match.groups():
                    os_version = match.group(1).replace('_', '.')
                break
        
        if detected_os:
            print(f"\n{Fore.GREEN}[+] Operating System:{Style.RESET_ALL}")
            print(f"    OS: {Fore.CYAN}{detected_os}{Style.RESET_ALL}")
            if os_version:
                print(f"    Version: {Fore.CYAN}{os_version}{Style.RESET_ALL}")
        
        # Detect device type
        device_type = "Desktop"
        if 'Mobile' in user_agent or 'Android' in user_agent:
            device_type = "Mobile"
        elif 'Tablet' in user_agent or 'iPad' in user_agent:
            device_type = "Tablet"
        
        print(f"    Device Type: {Fore.CYAN}{device_type}{Style.RESET_ALL}")
        
        # Detect bots/crawlers
        bot_patterns = [
            'Googlebot', 'Bingbot', 'Slurp', 'DuckDuckBot', 'Baiduspider',
            'YandexBot', 'facebookexternalhit', 'Twitterbot', 'WhatsApp',
            'Telegram', 'curl', 'wget', 'python-requests'
        ]
        
        detected_bots = [bot for bot in bot_patterns if bot.lower() in user_agent.lower()]
        
        if detected_bots:
            print(f"\n{Fore.GREEN}[+] Bot/Crawler Detection:{Style.RESET_ALL}")
            for bot in detected_bots:
                print(f"    {Fore.YELLOW}⚠️  Detected: {bot}{Style.RESET_ALL}")
        
        # Check for suspicious patterns
        suspicious_patterns = [
            'HeadlessChrome', 'PhantomJS', 'Selenium', 'WebDriver',
            'automation', 'scraper', 'crawler'
        ]
        
        suspicious_found = [pattern for pattern in suspicious_patterns 
                          if pattern.lower() in user_agent.lower()]
        
        if suspicious_found:
            print(f"\n{Fore.GREEN}[+] Automation Detection:{Style.RESET_ALL}")
            for pattern in suspicious_found:
                print(f"    {Fore.RED}🤖 Automation: {pattern}{Style.RESET_ALL}")
        
        # Security assessment
        print(f"\n{Fore.GREEN}[+] Security Assessment:{Style.RESET_ALL}")
        
        # Check for outdated browsers
        if browser_version and browser_version.isdigit():
            version_num = int(browser_version)
            if detected_browser == 'Google Chrome' and version_num < 90:
                print(f"    {Fore.RED}⚠️  Outdated Chrome version (security risk){Style.RESET_ALL}")
            elif detected_browser == 'Mozilla Firefox' and version_num < 85:
                print(f"    {Fore.RED}⚠️  Outdated Firefox version (security risk){Style.RESET_ALL}")
            elif detected_browser == 'Internet Explorer':
                print(f"    {Fore.RED}⚠️  Internet Explorer (deprecated, security risk){Style.RESET_ALL}")
            else:
                print(f"    {Fore.GREEN}✓ Browser version appears current{Style.RESET_ALL}")
        
        # Privacy assessment
        if 'Safari' in user_agent and 'Version' in user_agent:
            print(f"    Privacy: {Fore.GREEN}Safari has built-in tracking protection{Style.RESET_ALL}")
        elif 'Firefox' in user_agent:
            print(f"    Privacy: {Fore.GREEN}Firefox has enhanced tracking protection{Style.RESET_ALL}")
        elif 'Chrome' in user_agent:
            print(f"    Privacy: {Fore.YELLOW}Consider privacy-focused alternatives{Style.RESET_ALL}")
        
        # Additional information
        print(f"\n{Fore.GREEN}[+] Additional Details:{Style.RESET_ALL}")
        print(f"    Length: {Fore.CYAN}{len(user_agent)} characters{Style.RESET_ALL}")
        
        if len(user_agent) > 200:
            print(f"    {Fore.YELLOW}⚠️  Unusually long user-agent string{Style.RESET_ALL}")
        
    except Exception as e:
        print(f"{Fore.RED}[ERROR] Unexpected error in user-agent analysis: {str(e)}{Style.RESET_ALL}")
