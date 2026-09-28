#!/usr/bin/env python3
"""
Google Dorking Module
Perform advanced Google searches using dork queries
Author : Alex Butler (@MrHacker-X)
Org    : Vritra Security Organization
"""

import requests
import re
from urllib.parse import quote
from bloodrecon.modules.colors import Fore, Style

def perform_dorking(query):
    """Perform Google dorking with advanced search operators"""
    try:
        print(f"\n{Fore.CYAN}╔══════════════════════════════════════════════════════════════╗")
        print(f"║                     {Fore.YELLOW}GOOGLE DORKING{Fore.CYAN}                           ║")
        print(f"╚══════════════════════════════════════════════════════════════╝{Style.RESET_ALL}")
        
        print(f"\n{Fore.GREEN}[+] Input Analysis:{Style.RESET_ALL}")
        print(f"    Query: {Fore.YELLOW}{query}{Style.RESET_ALL}")
        
        # Detect if input is a domain
        is_domain = detect_domain(query)
        if is_domain:
            print(f"    Type: {Fore.CYAN}Domain detected{Style.RESET_ALL}")
            domain = clean_domain(query)
            print(f"    Clean Domain: {Fore.YELLOW}{domain}{Style.RESET_ALL}")
        else:
            print(f"    Type: {Fore.CYAN}Keyword/Custom query{Style.RESET_ALL}")
        
        # Encode the original query for URL
        encoded_query = quote(query)
        google_search_url = f"https://www.google.com/search?q={encoded_query}"
        
        print(f"\n{Fore.GREEN}[+] Original Query Search:{Style.RESET_ALL}")
        print(f"    🔗 Google: {Fore.MAGENTA}https://www.google.com/search?q={encoded_query}{Style.RESET_ALL}")
        
        # Common Google dork operators
        dork_operators = {
            'site:': 'Search within a specific site',
            'filetype:': 'Search for specific file types',
            'intitle:': 'Search for terms in page titles',
            'inurl:': 'Search for terms in URLs',
            'intext:': 'Search for terms in page text',
            'cache:': 'View cached version of a page',
            'related:': 'Find related websites',
            'info:': 'Get information about a website',
            'define:': 'Get definition of a term',
            'stocks:': 'Get stock information',
            'weather:': 'Get weather information',
            'map:': 'Get map information',
            'movie:': 'Get movie information',
            'author:': 'Search by author (Google Groups)',
            'group:': 'Search in specific newsgroups',
            'msgid:': 'Search by message ID',
            'inanchor:': 'Search for terms in link anchor text',
            'allinanchor:': 'Search for all terms in link anchor text',
            'allintext:': 'Search for all terms in page text',
            'allintitle:': 'Search for all terms in page titles',
            'allinurl:': 'Search for all terms in URLs'
        }
        
        # Analyze the query for operators
        print(f"\n{Fore.GREEN}[+] Detected Operators:{Style.RESET_ALL}")
        found_operators = []
        
        for operator, description in dork_operators.items():
            if operator in query.lower():
                found_operators.append((operator, description))
                print(f"    {Fore.CYAN}{operator:<15} {Fore.YELLOW}{description}{Style.RESET_ALL}")
        
        if found_operators:
            print(f"    {Fore.GREEN}✓ Advanced operators detected in query{Style.RESET_ALL}")
        
        # Generate smart dork suggestions
        if is_domain:
            generate_domain_dorks(domain)
        else:
            generate_keyword_dorks(query)
        
        
        # Security considerations
        print(f"\n{Fore.GREEN}[+] Security Considerations:{Style.RESET_ALL}")
        
        # Check for potentially sensitive searches
        sensitive_terms = ['password', 'login', 'admin', 'secret', 'key', 'token', 'credential']
        found_sensitive = [term for term in sensitive_terms if term in query.lower()]
        
        if found_sensitive:
            print(f"    {Fore.RED}⚠️  Sensitive terms detected: {', '.join(found_sensitive)}{Style.RESET_ALL}")
            print(f"    {Fore.RED}⚠️  Use responsibly and only for authorized testing{Style.RESET_ALL}")
        
        # Rate limiting warning
        print(f"    {Fore.YELLOW}⚠️  Google may rate limit or block automated queries{Style.RESET_ALL}")
        print(f"    {Fore.YELLOW}⚠️  Consider using manual searches for best results{Style.RESET_ALL}")
        
        # Alternative search engines
        print(f"\n{Fore.GREEN}[+] Alternative Search Engines:{Style.RESET_ALL}")
        alt_engines = {
            'Bing': f"https://www.bing.com/search?q={encoded_query}",
            'DuckDuckGo': f"https://duckduckgo.com/?q={encoded_query}",
            'Yandex': f"https://yandex.com/search/?text={encoded_query}",
            'Baidu': f"https://www.baidu.com/s?wd={encoded_query}"
        }
        
        for engine, url in alt_engines.items():
            print(f"    {engine}: {Fore.CYAN}{url}{Style.RESET_ALL}")
        
        # Legal and ethical considerations
        print(f"\n{Fore.GREEN}[+] Legal and Ethical Guidelines:{Style.RESET_ALL}")
        print(f"    {Fore.RED}• Only use for authorized security testing{Style.RESET_ALL}")
        print(f"    {Fore.RED}• Respect robots.txt and website terms of service{Style.RESET_ALL}")
        print(f"    {Fore.RED}• Do not access unauthorized systems{Style.RESET_ALL}")
        print(f"    {Fore.RED}• Report vulnerabilities responsibly{Style.RESET_ALL}")
        print(f"    {Fore.RED}• Comply with local and international laws{Style.RESET_ALL}")
        
        # Manual execution recommendation
        print(f"\n{Fore.GREEN}[+] Recommended Next Steps:{Style.RESET_ALL}")
        print(f"    {Fore.CYAN}1. Copy the generated URL and paste it in your browser{Style.RESET_ALL}")
        print(f"    {Fore.CYAN}2. Review results manually for accuracy{Style.RESET_ALL}")
        print(f"    {Fore.CYAN}3. Use different search engines for comprehensive coverage{Style.RESET_ALL}")
        print(f"    {Fore.CYAN}4. Document findings for security reports{Style.RESET_ALL}")
        
    except Exception as e:
        print(f"{Fore.RED}[ERROR] Unexpected error in Google dorking: {str(e)}{Style.RESET_ALL}")

def detect_domain(query):
    """Detect if the query is a domain name"""
    # Clean the query first
    query = query.strip().lower()
    
    # Remove common prefixes
    if query.startswith(('http://', 'https://')):
        query = query.split('//')[1].split('/')[0]
    
    # Basic domain pattern check
    domain_pattern = r'^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    
    # Check if it matches domain pattern and doesn't contain Google operators
    google_operators = ['site:', 'filetype:', 'intitle:', 'inurl:', 'intext:', 'cache:', 'related:', 'info:']
    
    has_operators = any(op in query for op in google_operators)
    matches_domain = re.match(domain_pattern, query)
    
    return matches_domain and not has_operators

def clean_domain(query):
    """Clean and extract domain from query"""
    query = query.strip().lower()
    
    # Remove protocol if present
    if query.startswith(('http://', 'https://')):
        query = query.split('//')[1]
    
    # Remove path if present
    if '/' in query:
        query = query.split('/')[0]
    
    # Remove port if present
    if ':' in query and not query.count(':') > 1:  # Avoid IPv6
        query = query.split(':')[0]
    
    return query

def generate_domain_dorks(domain):
    """Generate smart dork queries for a domain"""
    print(f"\n{Fore.GREEN}[+] Smart Domain Dorks for {domain}:{Style.RESET_ALL}")
    
    domain_dorks = [
        {
            'name': 'PDF Files',
            'query': f'site:{domain} filetype:pdf',
            'description': 'Find PDF documents on the domain'
        },
        {
            'name': 'Admin Panels',
            'query': f'site:{domain} inurl:admin',
            'description': 'Look for admin login pages'
        },
        {
            'name': 'Directory Listings',
            'query': f'site:{domain} intitle:"index of"',
            'description': 'Find exposed directory listings'
        },
        {
            'name': 'Login Pages',
            'query': f'site:{domain} inurl:login',
            'description': 'Discover login interfaces'
        },
        {
            'name': 'Configuration Files',
            'query': f'site:{domain} filetype:conf OR filetype:config OR filetype:cfg',
            'description': 'Search for configuration files'
        },
        {
            'name': 'Database Files',
            'query': f'site:{domain} filetype:sql OR filetype:db OR filetype:dbf',
            'description': 'Find database files'
        },
        {
            'name': 'Log Files',
            'query': f'site:{domain} filetype:log',
            'description': 'Search for log files'
        },
        {
            'name': 'Excel/CSV Files',
            'query': f'site:{domain} filetype:xls OR filetype:xlsx OR filetype:csv',
            'description': 'Find spreadsheet files'
        },
        {
            'name': 'Backup Files',
            'query': f'site:{domain} inurl:backup OR inurl:bak OR filetype:bak',
            'description': 'Look for backup files'
        },
        {
            'name': 'Error Pages',
            'query': f'site:{domain} "error" OR "exception" OR "stack trace"',
            'description': 'Find error pages that may reveal information'
        },
        {
            'name': 'Development/Test Pages',
            'query': f'site:{domain} inurl:test OR inurl:dev OR inurl:staging',
            'description': 'Discover development and testing areas'
        },
        {
            'name': 'Email Addresses',
            'query': f'site:{domain} "@{domain}"',
            'description': 'Find email addresses on the domain'
        }
    ]
    
    for i, dork in enumerate(domain_dorks, 1):
        encoded_query = quote(dork['query'])
        print(f"\n    {Fore.YELLOW}[{i:2d}] {dork['name']}:{Style.RESET_ALL}")
        print(f"         Query: {Fore.CYAN}{dork['query']}{Style.RESET_ALL}")
        print(f"         Info:  {Fore.WHITE}{dork['description']}{Style.RESET_ALL}")
        print(f"         🔗 Search: {Fore.MAGENTA}https://www.google.com/search?q={encoded_query}{Style.RESET_ALL}")

def generate_keyword_dorks(query):
    """Generate smart dork queries for keywords"""
    print(f"\n{Fore.GREEN}[+] Smart Keyword Dorks for '{query}':{Style.RESET_ALL}")
    
    keyword_dorks = [
        {
            'name': 'In Page Titles',
            'query': f'intitle:"{query}"',
            'description': 'Search for the keyword in page titles'
        },
        {
            'name': 'In URLs',
            'query': f'inurl:{query}',
            'description': 'Find pages with keyword in the URL'
        },
        {
            'name': 'In Page Text',
            'query': f'intext:"{query}"',
            'description': 'Search for keyword in page content'
        },
        {
            'name': 'PDF Documents',
            'query': f'filetype:pdf "{query}"',
            'description': 'Find PDF files containing the keyword'
        },
        {
            'name': 'Excel Files',
            'query': f'filetype:xls OR filetype:xlsx "{query}"',
            'description': 'Search Excel files for the keyword'
        },
        {
            'name': 'PowerPoint Files',
            'query': f'filetype:ppt OR filetype:pptx "{query}"',
            'description': 'Find PowerPoint presentations'
        },
        {
            'name': 'Word Documents',
            'query': f'filetype:doc OR filetype:docx "{query}"',
            'description': 'Search Word documents'
        },
        {
            'name': 'On GitHub',
            'query': f'site:github.com "{query}"',
            'description': 'Search for keyword on GitHub'
        },
        {
            'name': 'On Pastebin',
            'query': f'site:pastebin.com "{query}"',
            'description': 'Look for keyword on Pastebin'
        },
        {
            'name': 'On Social Media',
            'query': f'site:twitter.com OR site:facebook.com OR site:linkedin.com "{query}"',
            'description': 'Search social media platforms'
        }
    ]
    
    # Add security-specific dorks if sensitive terms detected
    sensitive_terms = ['password', 'login', 'admin', 'secret', 'key', 'token', 'credential']
    if any(term in query.lower() for term in sensitive_terms):
        security_dorks = [
            {
                'name': 'Config Files with Keyword',
                'query': f'filetype:conf OR filetype:config OR filetype:env "{query}"',
                'description': 'Search configuration files (USE RESPONSIBLY)'
            },
            {
                'name': 'Log Files with Keyword',
                'query': f'filetype:log "{query}"',
                'description': 'Search log files (AUTHORIZED TESTING ONLY)'
            }
        ]
        keyword_dorks.extend(security_dorks)
    
    for i, dork in enumerate(keyword_dorks, 1):
        encoded_query = quote(dork['query'])
        print(f"\n    {Fore.YELLOW}[{i:2d}] {dork['name']}:{Style.RESET_ALL}")
        print(f"         Query: {Fore.CYAN}{dork['query']}{Style.RESET_ALL}")
        print(f"         Info:  {Fore.WHITE}{dork['description']}{Style.RESET_ALL}")
        print(f"         🔗 Search: {Fore.MAGENTA}https://www.google.com/search?q={encoded_query}{Style.RESET_ALL}")
