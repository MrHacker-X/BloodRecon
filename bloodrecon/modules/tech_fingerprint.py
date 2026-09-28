#!/usr/bin/env python3
"""
Technology Fingerprinter Module
Identify technologies used by websites and web applications
Author : Alex Butler (@MrHacker-X)
Org    : Vritra Security Organization
"""

import requests
import re
from urllib.parse import urljoin, urlparse
from bloodrecon.modules.colors import Fore, Style

def fingerprint_technology(url):
    """Fingerprint technologies used by a website"""
    try:
        print(f"\n{Fore.CYAN}╔══════════════════════════════════════════════════════════════╗")
        print(f"║                   {Fore.YELLOW}TECHNOLOGY FINGERPRINTER{Fore.CYAN}                   ║")
        print(f"╚══════════════════════════════════════════════════════════════╝{Style.RESET_ALL}")
        
        # Ensure URL has protocol
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url
        
        print(f"\n{Fore.GREEN}[+] Analyzing: {Fore.YELLOW}{url}{Style.RESET_ALL}")
        
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        }
        
        try:
            response = requests.get(url, headers=headers, timeout=15, verify=False, allow_redirects=True)
            
            if response.status_code == 200:
                # Extract various fingerprints
                analyze_http_headers(response.headers)
                analyze_html_content(response.text, url)
                analyze_response_patterns(response)
                
                # Try to get additional resources
                analyze_common_files(url, headers)
            else:
                print(f"    {Fore.RED}✗ HTTP {response.status_code} response{Style.RESET_ALL}")
                # Still try to analyze headers even on error responses
                analyze_http_headers(response.headers)
            
        except requests.RequestException as e:
            print(f"    {Fore.RED}✗ Request failed: {str(e)}{Style.RESET_ALL}")
            return
        
        # Provide technology detection summary
        print(f"\n{Fore.GREEN}[+] Detection Summary:{Style.RESET_ALL}")
        print(f"    {Fore.CYAN}• Use online tools for comprehensive analysis{Style.RESET_ALL}")
        print(f"    {Fore.CYAN}• Check Wappalyzer, BuiltWith, or WhatRuns for detailed results{Style.RESET_ALL}")
        
    except Exception as e:
        print(f"{Fore.RED}[ERROR] Unexpected error in technology fingerprinting: {str(e)}{Style.RESET_ALL}")

def analyze_http_headers(headers):
    """Analyze HTTP headers for technology indicators"""
    print(f"\n{Fore.GREEN}[+] HTTP Header Analysis:{Style.RESET_ALL}")
    
    # Server header analysis
    server = headers.get('Server', '').lower()
    if server:
        print(f"    Server: {Fore.CYAN}{headers.get('Server')}{Style.RESET_ALL}")
        
        # Detect web servers
        if 'apache' in server:
            print(f"    Web Server: {Fore.YELLOW}Apache HTTP Server{Style.RESET_ALL}")
        elif 'nginx' in server:
            print(f"    Web Server: {Fore.YELLOW}Nginx{Style.RESET_ALL}")
        elif 'iis' in server:
            print(f"    Web Server: {Fore.YELLOW}Microsoft IIS{Style.RESET_ALL}")
        elif 'cloudflare' in server:
            print(f"    CDN/Proxy: {Fore.YELLOW}Cloudflare{Style.RESET_ALL}")
    
    # Technology-specific headers
    tech_headers = {
        'X-Powered-By': 'Backend Technology',
        'X-AspNet-Version': 'ASP.NET Version',
        'X-Generator': 'Content Generator',
        'X-Drupal-Cache': 'Drupal CMS',
        'X-Pingback': 'WordPress (XML-RPC)',
        'CF-Ray': 'Cloudflare CDN',
        'X-Amz-Cf-Id': 'Amazon CloudFront',
        'X-Served-By': 'Fastly CDN'
    }
    
    for header, description in tech_headers.items():
        if header in headers:
            print(f"    {description}: {Fore.CYAN}{headers[header]}{Style.RESET_ALL}")

def analyze_html_content(html_content, base_url):
    """Analyze HTML content for technology fingerprints"""
    print(f"\n{Fore.GREEN}[+] HTML Content Analysis:{Style.RESET_ALL}")
    
    if not html_content:
        print(f"    {Fore.YELLOW}No HTML content to analyze{Style.RESET_ALL}")
        return
    
    # Meta generator tags
    generator_match = re.search(r'<meta[^>]+name=["\']generator["\'][^>]*content=["\']([^"\']+)["\']', html_content, re.IGNORECASE)
    if generator_match:
        print(f"    Generator: {Fore.CYAN}{generator_match.group(1)}{Style.RESET_ALL}")
    
    # Framework detection patterns
    frameworks = {
        'WordPress': [r'wp-content/', r'wp-includes/', r'/wp-json/'],
        'Drupal': [r'sites/default/', r'drupal\.js', r'Drupal\.'],
        'Joomla': [r'/components/com_', r'joomla', r'option=com_'],
        'Django': [r'csrfmiddlewaretoken', r'Django'],
        'Laravel': [r'laravel_session', r'Laravel'],
        'React': [r'react', r'ReactDOM'],
        'Angular': [r'ng-app', r'angular', r'Angular'],
        'Vue.js': [r'vue\.js', r'Vue\.'],
        'jQuery': [r'jquery', r'jQuery'],
        'Bootstrap': [r'bootstrap', r'Bootstrap']
    }
    
    detected_frameworks = []
    for framework, patterns in frameworks.items():
        for pattern in patterns:
            if re.search(pattern, html_content, re.IGNORECASE):
                if framework not in detected_frameworks:
                    detected_frameworks.append(framework)
                    print(f"    Framework/CMS: {Fore.YELLOW}{framework}{Style.RESET_ALL}")
                break
    
    # JavaScript libraries detection
    js_libraries = {
        'Google Analytics': [r'google-analytics\.com', r'gtag\(', r'ga\('],
        'Google Tag Manager': [r'googletagmanager\.com'],
        'Facebook Pixel': [r'fbevents\.js', r'facebook\.net'],
        'jQuery': [r'jquery', r'jQuery'],
        'Modernizr': [r'modernizr'],
        'D3.js': [r'd3\.js', r'd3\.min\.js'],
        'Chart.js': [r'chart\.js']
    }
    
    for library, patterns in js_libraries.items():
        for pattern in patterns:
            if re.search(pattern, html_content, re.IGNORECASE):
                print(f"    JavaScript Library: {Fore.MAGENTA}{library}{Style.RESET_ALL}")
                break

def analyze_response_patterns(response):
    """Analyze response patterns for additional clues"""
    print(f"\n{Fore.GREEN}[+] Response Pattern Analysis:{Style.RESET_ALL}")
    
    # Analyze cookies
    cookies = response.cookies
    if cookies:
        print(f"    Cookies Found: {Fore.CYAN}{len(cookies)}{Style.RESET_ALL}")
        
        # Technology-specific cookies
        tech_cookies = {
            'PHPSESSID': 'PHP',
            'JSESSIONID': 'Java/JSP',
            'ASP.NET_SessionId': 'ASP.NET',
            'laravel_session': 'Laravel',
            'django_session': 'Django',
            'connect.sid': 'Node.js/Express'
        }
        
        for cookie in cookies:
            if cookie.name in tech_cookies:
                print(f"    Backend Technology: {Fore.YELLOW}{tech_cookies[cookie.name]}{Style.RESET_ALL}")
    
    # Response time analysis
    response_time = response.elapsed.total_seconds()
    print(f"    Response Time: {Fore.CYAN}{response_time:.2f} seconds{Style.RESET_ALL}")
    
    # Content encoding
    content_encoding = response.headers.get('Content-Encoding')
    if content_encoding:
        print(f"    Content Encoding: {Fore.CYAN}{content_encoding}{Style.RESET_ALL}")

def analyze_common_files(base_url, headers):
    """Try to access common files that reveal technology information"""
    print(f"\n{Fore.GREEN}[+] Common Files Analysis:{Style.RESET_ALL}")
    
    common_files = {
        '/robots.txt': 'Robots.txt',
        '/sitemap.xml': 'Sitemap',
        '/wp-admin/': 'WordPress Admin',
        '/admin/': 'Admin Panel',
        '/phpmyadmin/': 'phpMyAdmin',
        '/.well-known/security.txt': 'Security.txt',
        '/composer.json': 'Composer (PHP)',
        '/package.json': 'NPM Package',
        '/humans.txt': 'Humans.txt'
    }
    
    for path, description in common_files.items():
        try:
            test_url = urljoin(base_url, path)
            response = requests.head(test_url, headers=headers, timeout=5, verify=False)
            
            if response.status_code == 200:
                print(f"    {Fore.GREEN}✓ {description}: {Fore.CYAN}{test_url}{Style.RESET_ALL}")
            elif response.status_code == 403:
                print(f"    {Fore.YELLOW}⚠ {description}: {Fore.CYAN}Forbidden (exists){Style.RESET_ALL}")
                
        except requests.RequestException:
            continue
    
    # Check for common technology-specific paths
    tech_paths = {
        '/wp-json/wp/v2/': 'WordPress REST API',
        '/.git/': 'Git Repository',
        '/.svn/': 'SVN Repository',
        '/api/': 'API Endpoint',
        '/graphql': 'GraphQL Endpoint',
        '/_next/': 'Next.js',
        '/_nuxt/': 'Nuxt.js'
    }
    
    print(f"\n{Fore.GREEN}[+] Technology-Specific Paths:{Style.RESET_ALL}")
    for path, tech in tech_paths.items():
        try:
            test_url = urljoin(base_url, path)
            response = requests.head(test_url, headers=headers, timeout=5, verify=False)
            
            if response.status_code in [200, 403]:
                print(f"    {Fore.GREEN}✓ {tech}: {Fore.CYAN}Detected{Style.RESET_ALL}")
                
        except requests.RequestException:
            continue
