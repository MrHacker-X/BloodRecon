#!/usr/bin/env python3
"""
Robots.txt Scanner Module
Analyze robots.txt files for hidden directories and files
Author : Alex Butler (@MrHacker-X)
Org    : Vritra Security Organization
"""

import requests
from bloodrecon.modules.colors import Fore, Style
from urllib.parse import urljoin, urlparse

def scan_robots(url):
    """Scan robots.txt file for interesting paths"""
    try:
        print(f"\n{Fore.CYAN}╔══════════════════════════════════════════════════════════════╗")
        print(f"║                     {Fore.YELLOW}ROBOTS.TXT SCANNER{Fore.CYAN}                       ║")
        print(f"╚══════════════════════════════════════════════════════════════╝{Style.RESET_ALL}")
        
        # Ensure URL has proper format
        if not url.startswith(('http://', 'https://')):
            url = 'http://' + url
        
        # Parse URL to get base
        parsed = urlparse(url)
        base_url = f"{parsed.scheme}://{parsed.netloc}"
        robots_url = urljoin(base_url, '/robots.txt')
        
        try:
            response = requests.get(robots_url, timeout=10)
            
            print(f"\n{Fore.GREEN}[+] Robots.txt Information:{Style.RESET_ALL}")
            print(f"    URL: {Fore.YELLOW}{robots_url}{Style.RESET_ALL}")
            print(f"    Status Code: {Fore.YELLOW}{response.status_code}{Style.RESET_ALL}")
            
            if response.status_code == 200:
                content = response.text
                lines = content.split('\n')
                
                print(f"\n{Fore.GREEN}[+] Robots.txt Content:{Style.RESET_ALL}")
                
                # Parse robots.txt content
                user_agents = []
                disallowed_paths = []
                allowed_paths = []
                crawl_delays = []
                sitemaps = []
                
                current_user_agent = None
                
                for line in lines:
                    line = line.strip()
                    if not line or line.startswith('#'):
                        continue
                    
                    if line.lower().startswith('user-agent:'):
                        current_user_agent = line.split(':', 1)[1].strip()
                        user_agents.append(current_user_agent)
                        print(f"    {Fore.CYAN}User-Agent: {current_user_agent}{Style.RESET_ALL}")
                    
                    elif line.lower().startswith('disallow:'):
                        path = line.split(':', 1)[1].strip()
                        if path:
                            disallowed_paths.append(path)
                            print(f"    {Fore.RED}Disallow: {path}{Style.RESET_ALL}")
                    
                    elif line.lower().startswith('allow:'):
                        path = line.split(':', 1)[1].strip()
                        if path:
                            allowed_paths.append(path)
                            print(f"    {Fore.GREEN}Allow: {path}{Style.RESET_ALL}")
                    
                    elif line.lower().startswith('crawl-delay:'):
                        delay = line.split(':', 1)[1].strip()
                        crawl_delays.append(delay)
                        print(f"    {Fore.YELLOW}Crawl-Delay: {delay}{Style.RESET_ALL}")
                    
                    elif line.lower().startswith('sitemap:'):
                        sitemap = line.split(':', 1)[1].strip()
                        sitemaps.append(sitemap)
                        print(f"    {Fore.MAGENTA}Sitemap: {sitemap}{Style.RESET_ALL}")
                
                # Show interesting findings
                if disallowed_paths:
                    print(f"\n{Fore.GREEN}[+] Potentially Interesting Paths:{Style.RESET_ALL}")
                    interesting_keywords = ['admin', 'login', 'private', 'secret', 'hidden', 'backup', 'config', 'test', 'dev']
                    
                    for path in disallowed_paths:
                        for keyword in interesting_keywords:
                            if keyword in path.lower():
                                print(f"    {Fore.YELLOW}⚠️  {path} - Contains '{keyword}'{Style.RESET_ALL}")
                                break
                        else:
                            print(f"    {Fore.CYAN}{path}{Style.RESET_ALL}")
                
                if sitemaps:
                    print(f"\n{Fore.GREEN}[+] Discovered Sitemaps:{Style.RESET_ALL}")
                    for sitemap in sitemaps:
                        print(f"    {Fore.MAGENTA}{sitemap}{Style.RESET_ALL}")
                
                # Check if paths are accessible
                print(f"\n{Fore.GREEN}[+] Path Accessibility Check:{Style.RESET_ALL}")
                for path in disallowed_paths[:10]:  # Check first 10 paths
                    if path and path != '/':
                        check_url = urljoin(base_url, path)
                        try:
                            check_response = requests.head(check_url, timeout=5)
                            status_color = Fore.GREEN if check_response.status_code == 200 else Fore.YELLOW
                            print(f"    {check_url} - {status_color}{check_response.status_code}{Style.RESET_ALL}")
                        except:
                            print(f"    {check_url} - {Fore.RED}Unreachable{Style.RESET_ALL}")
                            
            elif response.status_code == 404:
                print(f"    {Fore.RED}robots.txt not found{Style.RESET_ALL}")
            else:
                print(f"    {Fore.YELLOW}Received status code {response.status_code}{Style.RESET_ALL}")
                
        except requests.RequestException as e:
            print(f"{Fore.RED}[ERROR] Could not fetch robots.txt: {str(e)}{Style.RESET_ALL}")
        
    except Exception as e:
        print(f"{Fore.RED}[ERROR] Unexpected error in robots.txt scanner: {str(e)}{Style.RESET_ALL}")
