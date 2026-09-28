#!/usr/bin/env python3
"""
URL Analyzer Module
Analyze URLs for security threats and reputation
Author : Alex Butler (@MrHacker-X)
Org    : Vritra Security Organization
"""

import requests
from urllib.parse import urlparse
from bloodrecon.modules.colors import Fore, Style

def analyze_url(url):
    """Analyze URL for threats and reputation"""
    try:
        print(f"\n{Fore.CYAN}╔══════════════════════════════════════════════════════════════╗")
        print(f"║                     {Fore.YELLOW}URL THREAT ANALYSIS{Fore.CYAN}                      ║")
        print(f"╚══════════════════════════════════════════════════════════════╝{Style.RESET_ALL}")
        
        # Ensure URL has proper format
        if not url.startswith(('http://', 'https://')):
            url = 'http://' + url
        
        parsed_url = urlparse(url)
        
        print(f"\n{Fore.GREEN}[+] URL Information:{Style.RESET_ALL}")
        print(f"    URL: {Fore.YELLOW}{url}{Style.RESET_ALL}")
        print(f"    Domain: {Fore.CYAN}{parsed_url.netloc}{Style.RESET_ALL}")
        print(f"    Path: {Fore.CYAN}{parsed_url.path or '/'}{Style.RESET_ALL}")
        print(f"    Scheme: {Fore.CYAN}{parsed_url.scheme}{Style.RESET_ALL}")
        
        # Basic safety checks
        print(f"\n{Fore.GREEN}[+] Security Assessment:{Style.RESET_ALL}")
        
        # Check for HTTPS
        if parsed_url.scheme == 'https':
            print(f"    HTTPS: {Fore.GREEN}✓ Secure connection{Style.RESET_ALL}")
        else:
            print(f"    HTTPS: {Fore.RED}✗ Insecure HTTP connection{Style.RESET_ALL}")
        
        # Check for suspicious patterns
        suspicious_patterns = [
            'bit.ly', 'tinyurl.com', 'short.link', 'goo.gl', 't.co',
            'login', 'secure', 'verify', 'update', 'confirm'
        ]
        
        suspicious_found = []
        for pattern in suspicious_patterns:
            if pattern in url.lower():
                suspicious_found.append(pattern)
        
        if suspicious_found:
            print(f"    Suspicious Patterns: {Fore.YELLOW}Found: {', '.join(suspicious_found)}{Style.RESET_ALL}")
        else:
            print(f"    Suspicious Patterns: {Fore.GREEN}None detected{Style.RESET_ALL}")
        
        # Try to get response
        try:
            response = requests.get(url, timeout=10, allow_redirects=True)
            print(f"    Response Code: {Fore.YELLOW}{response.status_code}{Style.RESET_ALL}")
            
            if response.url != url:
                print(f"    Redirected to: {Fore.CYAN}{response.url}{Style.RESET_ALL}")
            
            # Check content type
            content_type = response.headers.get('content-type', 'Unknown')
            print(f"    Content Type: {Fore.CYAN}{content_type}{Style.RESET_ALL}")
            
        except requests.RequestException as e:
            print(f"    Connection: {Fore.RED}Failed - {str(e)}{Style.RESET_ALL}")
        
        # Manual verification suggestions
        print(f"\n{Fore.GREEN}[+] Manual Verification:{Style.RESET_ALL}")
        print(f"    VirusTotal: {Fore.MAGENTA}https://www.virustotal.com/gui/url/{url}/detection{Style.RESET_ALL}")
        print(f"    URLVoid: {Fore.MAGENTA}https://www.urlvoid.com/scan/{parsed_url.netloc}/{Style.RESET_ALL}")
        print(f"    Sucuri SiteCheck: {Fore.MAGENTA}https://sitecheck.sucuri.net/results/{url}{Style.RESET_ALL}")
        
        print(f"\n{Fore.GREEN}[+] Recommendations:{Style.RESET_ALL}")
        print(f"    {Fore.CYAN}• Always verify URLs before clicking{Style.RESET_ALL}")
        print(f"    {Fore.CYAN}• Check for HTTPS encryption{Style.RESET_ALL}")
        print(f"    {Fore.CYAN}• Be cautious of URL shorteners{Style.RESET_ALL}")
        print(f"    {Fore.CYAN}• Verify sender authenticity{Style.RESET_ALL}")
        
    except Exception as e:
        print(f"{Fore.RED}[ERROR] Unexpected error in URL analysis: {str(e)}{Style.RESET_ALL}")
