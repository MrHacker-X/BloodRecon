#!/usr/bin/env python3
"""
HTTP Headers Analysis Module
Analyze HTTP headers for security and technology detection
Author : Alex Butler (@MrHacker-X)
Org    : Vritra Security Organization
"""

import requests
from bloodrecon.modules.colors import Fore, Style
from urllib.parse import urlparse

def get_headers(url):
    """Fetch and analyze HTTP headers"""
    try:
        print(f"\n{Fore.CYAN}╔══════════════════════════════════════════════════════════════╗")
        print(f"║                    {Fore.YELLOW}HTTP HEADERS ANALYSIS{Fore.CYAN}                     ║")
        print(f"╚══════════════════════════════════════════════════════════════╝{Style.RESET_ALL}")
        
        # Ensure URL has proper format
        if not url.startswith(('http://', 'https://')):
            url = 'http://' + url
        
        try:
            response = requests.get(url, timeout=10, allow_redirects=True)
            
            print(f"\n{Fore.GREEN}[+] Basic Information:{Style.RESET_ALL}")
            print(f"    URL: {Fore.YELLOW}{response.url}{Style.RESET_ALL}")
            print(f"    Status Code: {Fore.YELLOW}{response.status_code}{Style.RESET_ALL}")
            print(f"    Response Size: {Fore.YELLOW}{len(response.content)} bytes{Style.RESET_ALL}")
            
            # Server information
            print(f"\n{Fore.GREEN}[+] Server Information:{Style.RESET_ALL}")
            headers = response.headers
            
            if 'Server' in headers:
                print(f"    Server: {Fore.CYAN}{headers['Server']}{Style.RESET_ALL}")
            else:
                print(f"    Server: {Fore.RED}Not disclosed{Style.RESET_ALL}")
            
            if 'X-Powered-By' in headers:
                print(f"    Powered By: {Fore.CYAN}{headers['X-Powered-By']}{Style.RESET_ALL}")
            
            # Security headers analysis
            print(f"\n{Fore.GREEN}[+] Security Headers Analysis:{Style.RESET_ALL}")
            
            security_headers = {
                'Strict-Transport-Security': 'HSTS',
                'Content-Security-Policy': 'CSP',
                'X-Content-Type-Options': 'X-Content-Type-Options',
                'X-Frame-Options': 'X-Frame-Options',
                'X-XSS-Protection': 'XSS Protection',
                'Referrer-Policy': 'Referrer Policy'
            }
            
            for header, name in security_headers.items():
                if header in headers:
                    print(f"    {name}: {Fore.GREEN}✓ Present{Style.RESET_ALL}")
                    print(f"      Value: {Fore.CYAN}{headers[header]}{Style.RESET_ALL}")
                else:
                    print(f"    {name}: {Fore.RED}✗ Missing{Style.RESET_ALL}")
            
            # Content type and encoding
            print(f"\n{Fore.GREEN}[+] Content Information:{Style.RESET_ALL}")
            if 'Content-Type' in headers:
                print(f"    Content Type: {Fore.CYAN}{headers['Content-Type']}{Style.RESET_ALL}")
            if 'Content-Encoding' in headers:
                print(f"    Content Encoding: {Fore.CYAN}{headers['Content-Encoding']}{Style.RESET_ALL}")
            if 'Content-Length' in headers:
                print(f"    Content Length: {Fore.CYAN}{headers['Content-Length']}{Style.RESET_ALL}")
            
            # Cache information
            print(f"\n{Fore.GREEN}[+] Cache Information:{Style.RESET_ALL}")
            cache_headers = ['Cache-Control', 'Expires', 'ETag', 'Last-Modified']
            for header in cache_headers:
                if header in headers:
                    print(f"    {header}: {Fore.CYAN}{headers[header]}{Style.RESET_ALL}")
            
            # All headers
            print(f"\n{Fore.GREEN}[+] All HTTP Headers:{Style.RESET_ALL}")
            for header, value in headers.items():
                print(f"    {Fore.MAGENTA}{header}:{Style.RESET_ALL} {Fore.YELLOW}{value}{Style.RESET_ALL}")
                
        except requests.RequestException as e:
            print(f"{Fore.RED}[ERROR] Could not fetch headers: {str(e)}{Style.RESET_ALL}")
        
    except Exception as e:
        print(f"{Fore.RED}[ERROR] Unexpected error in headers analysis: {str(e)}{Style.RESET_ALL}")
