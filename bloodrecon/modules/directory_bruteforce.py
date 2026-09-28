#!/usr/bin/env python3
"""
Directory Bruteforce Module
Discover hidden directories and files on web servers
Author : Alex Butler (@MrHacker-X)
Org    : Vritra Security Organization
"""

import requests
import threading
import time
from bloodrecon.modules.colors import Fore, Style
from urllib.parse import urljoin
import urllib3

# Suppress SSL warnings for unverified requests
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def bruteforce_directories(domain, wordlist_path):
    """Bruteforce directories and discover hidden content"""
    try:
        print(f"\n{Fore.CYAN}╔══════════════════════════════════════════════════════════════╗")
        print(f"║                   {Fore.YELLOW}DIRECTORY BRUTEFORCER{Fore.CYAN}                      ║")
        print(f"╚══════════════════════════════════════════════════════════════╝{Style.RESET_ALL}")
        
        # Ensure URL has protocol
        if not domain.startswith(('http://', 'https://')):
            domain = 'https://' + domain
        
        print(f"\n{Fore.GREEN}[+] Target: {Fore.YELLOW}{domain}{Style.RESET_ALL}")
        
        # Try to use wordlist or default
        wordlist = get_wordlist(wordlist_path)
        
        if not wordlist:
            print(f"    {Fore.YELLOW}Using built-in wordlist{Style.RESET_ALL}")
            wordlist = get_default_wordlist()
        else:
            print(f"    {Fore.GREEN}Using wordlist: {wordlist_path}{Style.RESET_ALL}")
        
        print(f"    {Fore.CYAN}Testing {len(wordlist)} paths...{Style.RESET_ALL}")
        
        found_dirs = []
        forbidden_dirs = []
        total_checked = 0
        
        for word in wordlist:
            if word.strip():
                total_checked += 1
                test_url = urljoin(domain, word.strip())
                result = test_directory(test_url)
                
                if result == 'found':
                    found_dirs.append(test_url)
                    print(f"    {Fore.GREEN}✓ Found: {Fore.CYAN}{test_url}{Style.RESET_ALL}")
                elif result == 'forbidden':
                    forbidden_dirs.append(test_url)
                    print(f"    {Fore.YELLOW}⚠ Forbidden: {Fore.CYAN}{test_url}{Style.RESET_ALL}")
                
                # Progress indicator
                if total_checked % 50 == 0:
                    print(f"    {Fore.BLUE}Progress: {total_checked}/{len(wordlist)} ({(total_checked/len(wordlist)*100):.1f}%){Style.RESET_ALL}")
            
        # Display results
        print(f"\n{Fore.GREEN}[+] Bruteforce Complete:{Style.RESET_ALL}")
        print(f"    {Fore.CYAN}Paths tested: {Fore.YELLOW}{total_checked}{Style.RESET_ALL}")
        print(f"    {Fore.CYAN}Accessible directories: {Fore.GREEN}{len(found_dirs)}{Style.RESET_ALL}")
        print(f"    {Fore.CYAN}Forbidden directories: {Fore.YELLOW}{len(forbidden_dirs)}{Style.RESET_ALL}")
        
        if found_dirs:
            print(f"\n{Fore.GREEN}[+] Accessible Paths:{Style.RESET_ALL}")
            for url in found_dirs:
                print(f"    {Fore.GREEN}• {url}{Style.RESET_ALL}")
        
        if forbidden_dirs:
            print(f"\n{Fore.YELLOW}[+] Forbidden Paths (may exist):{Style.RESET_ALL}")
            for url in forbidden_dirs[:10]:  # Show first 10
                print(f"    {Fore.YELLOW}• {url}{Style.RESET_ALL}")
            if len(forbidden_dirs) > 10:
                print(f"    {Fore.YELLOW}... and {len(forbidden_dirs) - 10} more forbidden paths{Style.RESET_ALL}")
        
    except Exception as e:
        print(f"{Fore.RED}[ERROR] Unexpected error in directory bruteforce: {str(e)}{Style.RESET_ALL}")

def get_wordlist(wordlist_path):
    """Load wordlist from file"""
    try:
        with open(wordlist_path, 'r') as f:
            return f.read().strip().split('\n')
    except FileNotFoundError:
        return None
    except Exception:
        return None

def get_default_wordlist():
    """Return a default wordlist if no file is available"""
    return [
        'admin', 'administrator', 'login', 'dashboard', 'panel', 'control',
        'test', 'demo', 'backup', 'old', 'new', 'tmp', 'temp',
        'api', 'v1', 'v2', 'api/v1', 'api/v2',
        'wp-admin', 'wp-content', 'wp-includes',
        'phpmyadmin', 'mysql', 'database',
        'config', 'conf', 'configuration',
        'uploads', 'files', 'documents', 'images', 'img',
        'css', 'js', 'scripts', 'static', 'assets',
        'includes', 'lib', 'libraries',
        'src', 'source', 'resources',
        'private', 'secret', 'hidden',
        'logs', 'log', 'debug',
        'install', 'setup', 'installer',
        'download', 'downloads',
        'user', 'users', 'account', 'accounts',
        'mail', 'email', 'webmail',
        'ftp', 'sftp', 'ssh',
        'stats', 'statistics', 'analytics',
        'help', 'support', 'docs', 'documentation',
        'search', 'blog', 'news', 'about', 'contact'
    ]

def test_directory(url):
    """Test if a directory/file exists"""
    try:
        response = requests.get(url, timeout=5, allow_redirects=False, verify=False)
        
        if response.status_code == 200:
            return 'found'
        elif response.status_code == 403:
            return 'forbidden'
        else:
            return 'not_found'
            
    except requests.RequestException:
        return 'error'
