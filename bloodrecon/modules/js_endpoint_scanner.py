#!/usr/bin/env python3
"""
JavaScript Endpoint Scanner Module
Extract API endpoints and sensitive data from JavaScript files
Author : Alex Butler (@MrHacker-X)
Org    : Vritra Security Organization
"""

import re
import requests
from urllib.parse import urljoin, urlparse
from bloodrecon.modules.colors import Fore, Style
import json
import urllib3
import concurrent.futures

# Suppress SSL warnings for unverified requests
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def scan_js_endpoints(target):
    """Scan JavaScript files for endpoints and sensitive data"""
    try:
        print(f"\n{Fore.CYAN}╔══════════════════════════════════════════════════════════════╗")
        print(f"║                  {Fore.YELLOW}JAVASCRIPT ENDPOINT SCANNER{Fore.CYAN}                 ║")
        print(f"╚══════════════════════════════════════════════════════════════╝{Style.RESET_ALL}")
        
        # Ensure URL has protocol
        if not target.startswith(('http://', 'https://')):
            target = 'https://' + target
        
        print(f"\n{Fore.GREEN}[+] Analyzing: {Fore.YELLOW}{target}{Style.RESET_ALL}")
        
        # Find JavaScript files
        js_files = find_js_files(target)
        
        # Analyze each JavaScript file
        all_endpoints = set()
        all_secrets = []
        all_comments = []
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            futures = {executor.submit(analyze_js_file, js_url): js_url for js_url in js_files}
            for future in concurrent.futures.as_completed(futures):
                js_url = futures[future]
                try:
                    endpoints, secrets, comments = future.result()
                    all_endpoints.update(endpoints)
                    all_secrets.extend(secrets)
                    all_comments.extend(comments)
                except Exception as e:
                    print(f"{Fore.RED}[ERROR] Error processing {js_url}: {str(e)}{Style.RESET_ALL}")
        
        # Display results
        display_results(all_endpoints, all_secrets, all_comments, len(js_files))
        
    except Exception as e:
        print(f"{Fore.RED}[ERROR] Unexpected error in JavaScript endpoint scanning: {str(e)}{Style.RESET_ALL}")

def find_js_files(target):
    """Find JavaScript files on the target website"""
    js_files = set()
    
    try:
        print(f"\n{Fore.GREEN}[+] Finding JavaScript files:{Style.RESET_ALL}")
        
        # Get main page
        response = requests.get(target, timeout=10, verify=False)
        if response.status_code == 200:
            # Find script tags
            script_pattern = r'<script[^>]*src=["\']([^"\'>]+)["\'][^>]*>'
            scripts = re.findall(script_pattern, response.text, re.IGNORECASE)
            
            for script_src in scripts:
                if script_src.endswith('.js'):
                    full_url = urljoin(target, script_src)
                    js_files.add(full_url)
                    print(f"    {Fore.CYAN}✓ Found: {script_src}{Style.RESET_ALL}")
        
        # Add common JavaScript file locations
        common_js_paths = [
            '/js/main.js',
            '/js/app.js',
            '/assets/js/main.js',
            '/static/js/main.js',
            '/js/config.js',
            '/js/api.js'
        ]
        
        for path in common_js_paths:
            test_url = urljoin(target, path)
            try:
                response = requests.head(test_url, timeout=5, verify=False)
                if response.status_code == 200:
                    js_files.add(test_url)
                    print(f"    {Fore.GREEN}✓ Found common file: {path}{Style.RESET_ALL}")
            except:
                continue
        
        print(f"    {Fore.YELLOW}Total JS files found: {len(js_files)}{Style.RESET_ALL}")
        
    except Exception as e:
        print(f"    {Fore.RED}✗ Error finding JS files: {str(e)}{Style.RESET_ALL}")
    
    return js_files

def analyze_js_file(js_url):
    """Analyze individual JavaScript file for endpoints and secrets"""
    endpoints = set()
    secrets = []
    comments = []
    
    try:
        print(f"\n{Fore.GREEN}[+] Analyzing: {Fore.CYAN}{js_url}{Style.RESET_ALL}")
        
        response = requests.get(js_url, timeout=5, verify=False)
        if response.status_code != 200:
            print(f"    {Fore.RED}✗ Could not fetch file (Status: {response.status_code}){Style.RESET_ALL}")
            return endpoints, secrets, comments
        
        js_content = response.text
        
        # Extract API endpoints
        endpoints = extract_endpoints(js_content)
        
        # Extract potential secrets
        secrets = extract_secrets(js_content)
        
        # Extract comments
        comments = extract_comments(js_content)
        
    except Exception as e:
        print(f"    {Fore.RED}✗ Error analyzing file: {str(e)}{Style.RESET_ALL}")
    
    return endpoints, secrets, comments

def extract_endpoints(js_content):
    """Extract API endpoints from JavaScript content"""
    endpoints = set()
    
    # Patterns for different endpoint formats
    patterns = [
        r'["\']([/\w\-._~:/?#\[\]@!$&\'()*+,;=]+/api/[\w\-._~:/?#\[\]@!$&\'()*+,;=]+)["\']',
        r'["\']([/\w\-._~:/?#\[\]@!$&\'()*+,;=]+/v\d+/[\w\-._~:/?#\[\]@!$&\'()*+,;=]+)["\']',
        r'["\']([/\w\-._~:/?#\[\]@!$&\'()*+,;=]+\.json[\w\-._~:/?#\[\]@!$&\'()*+,;=]*)["\']',
        r'["\']([/\w\-._~:/?#\[\]@!$&\'()*+,;=]+\.php[\w\-._~:/?#\[\]@!$&\'()*+,;=]*)["\']',
        r'["\']([/\w\-._~:/?#\[\]@!$&\'()*+,;=]+\.aspx?[\w\-._~:/?#\[\]@!$&\'()*+,;=]*)["\']',
        r'\b(https?://[\w\-._~:/?#\[\]@!$&\'()*+,;=]+)',
        r'["\']([/]\w+(?:/\w+)*/?)["\']',
    ]
    
    for pattern in patterns:
        matches = re.findall(pattern, js_content, re.IGNORECASE)
        for match in matches:
            if len(match) > 3 and not match.startswith('//'):  # Filter out short matches and comments
                endpoints.add(match)
    
    return endpoints

def extract_secrets(js_content):
    """Extract potential secrets and sensitive data"""
    secrets = []
    
    # Patterns for secrets
    secret_patterns = {
        'API Keys': r'["\']([a-zA-Z0-9]{32,})["\']',
        'AWS Keys': r'AKIA[0-9A-Z]{16}',
        'JWT Tokens': r'eyJ[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*',
        'Base64 Strings': r'["\']([A-Za-z0-9+/]{20,}={0,2})["\']',
        'Passwords': r'["\']password["\']\s*:\s*["\']([^"\'\\\n]+)["\']',
        'API Secrets': r'["\'](?:secret|key|token|password)["\']\s*:\s*["\']([^"\'\\\n]+)["\']',
    }
    
    for secret_type, pattern in secret_patterns.items():
        matches = re.findall(pattern, js_content, re.IGNORECASE)
        for match in matches:
            if isinstance(match, tuple):
                match = match[0] if match[0] else match[1]
            if len(match) > 8:  # Only consider longer strings
                secrets.append({
                    'type': secret_type,
                    'value': match[:50] + '...' if len(match) > 50 else match
                })
    
    return secrets

def extract_comments(js_content):
    """Extract comments from JavaScript content"""
    comments = []
    
    # Single line comments
    single_comments = re.findall(r'//\s*(.+)', js_content)
    for comment in single_comments:
        if len(comment.strip()) > 10:  # Only meaningful comments
            comments.append(comment.strip())
    
    # Multi-line comments
    multi_comments = re.findall(r'/\*([\s\S]*?)\*/', js_content)
    for comment in multi_comments:
        clean_comment = comment.strip()
        if len(clean_comment) > 10:
            comments.append(clean_comment[:100] + '...' if len(clean_comment) > 100 else clean_comment)
    
    return comments

def display_results(endpoints, secrets, comments, js_files_count):
    """Display scan results"""
    print(f"\n{Fore.GREEN}[+] Scan Results Summary:{Style.RESET_ALL}")
    print(f"    {Fore.CYAN}JavaScript files analyzed: {Fore.YELLOW}{js_files_count}{Style.RESET_ALL}")
    print(f"    {Fore.CYAN}Endpoints found: {Fore.YELLOW}{len(endpoints)}{Style.RESET_ALL}")
    print(f"    {Fore.CYAN}Potential secrets: {Fore.YELLOW}{len(secrets)}{Style.RESET_ALL}")
    print(f"    {Fore.CYAN}Comments extracted: {Fore.YELLOW}{len(comments)}{Style.RESET_ALL}")
    
    # Display endpoints
    if endpoints:
        print(f"\n{Fore.GREEN}[+] Discovered Endpoints:{Style.RESET_ALL}")
        for i, endpoint in enumerate(sorted(endpoints)[:20], 1):  # Show first 20
            print(f"    {Fore.CYAN}[{i:2d}] {endpoint}{Style.RESET_ALL}")
        
        if len(endpoints) > 20:
            print(f"    {Fore.YELLOW}... and {len(endpoints) - 20} more endpoints{Style.RESET_ALL}")
    
    # Display potential secrets
    if secrets:
        print(f"\n{Fore.GREEN}[+] Potential Secrets:{Style.RESET_ALL}")
        for i, secret in enumerate(secrets[:10], 1):  # Show first 10
            print(f"    {Fore.RED}[{i:2d}] {secret['type']}: {secret['value']}{Style.RESET_ALL}")
        
        if len(secrets) > 10:
            print(f"    {Fore.YELLOW}... and {len(secrets) - 10} more potential secrets{Style.RESET_ALL}")
    
    # Display interesting comments
    if comments:
        print(f"\n{Fore.GREEN}[+] Interesting Comments:{Style.RESET_ALL}")
        for i, comment in enumerate(comments[:5], 1):  # Show first 5
            print(f"    {Fore.MAGENTA}[{i}] {comment}{Style.RESET_ALL}")
        
        if len(comments) > 5:
            print(f"    {Fore.YELLOW}... and {len(comments) - 5} more comments{Style.RESET_ALL}")
    
    # Security recommendations
    print(f"\n{Fore.GREEN}[+] Security Recommendations:{Style.RESET_ALL}")
    print(f"    {Fore.CYAN}• Manually verify potential secrets and endpoints{Style.RESET_ALL}")
    print(f"    {Fore.CYAN}• Check for hardcoded credentials in the source code{Style.RESET_ALL}")
    print(f"    {Fore.CYAN}• Test discovered endpoints for unauthorized access{Style.RESET_ALL}")
    print(f"    {Fore.CYAN}• Consider using source maps for better analysis{Style.RESET_ALL}")
