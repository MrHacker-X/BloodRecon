#!/usr/bin/env python3
"""
Sitemap Parser Module
Parse and analyze XML sitemaps to discover URLs and site structure
Author : Alex Butler (@MrHacker-X)
Org    : Vritra Security Organization
"""

import requests
import xml.etree.ElementTree as ET
from urllib.parse import urljoin, urlparse
from datetime import datetime
from bloodrecon.modules.colors import Fore, Style
import re
import urllib3
import concurrent.futures
import gzip
import io

# Suppress SSL warnings for unverified requests
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def parse_sitemap(target):
    """Parse sitemap.xml and extract URLs"""
    try:
        print(f"\n{Fore.CYAN}╔══════════════════════════════════════════════════════════════╗")
        print(f"║                       {Fore.YELLOW}SITEMAP PARSER{Fore.CYAN}                         ║")
        print(f"╚══════════════════════════════════════════════════════════════╝{Style.RESET_ALL}")
        
        # Ensure URL has protocol
        if not target.startswith(('http://', 'https://')):
            target = 'https://' + target
        
        print(f"\n{Fore.GREEN}[+] Analyzing sitemaps for: {Fore.YELLOW}{target}{Style.RESET_ALL}")
        
        # Find sitemap files
        sitemap_urls = find_sitemaps(target)
        
        all_urls = []
        sitemap_info = {}
        
        # Use concurrent requests to parse sitemaps
        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            futures = {executor.submit(parse_single_sitemap, sitemap_url): sitemap_url for sitemap_url in sitemap_urls}
            for future in concurrent.futures.as_completed(futures):
                sitemap_url = futures[future]
                try:
                    urls, info = future.result()
                    all_urls.extend(urls)
                    sitemap_info[sitemap_url] = info
                except Exception as e:
                    print(f"{Fore.RED}[ERROR] Error processing {sitemap_url}: {str(e)}{Style.RESET_ALL}")
        
        # Analyze and display results
        analyze_sitemap_data(all_urls, sitemap_info, target)
        
    except Exception as e:
        print(f"{Fore.RED}[ERROR] Unexpected error in sitemap parsing: {str(e)}{Style.RESET_ALL}")

def check_sitemap_url(args):
    """Check if a sitemap URL exists - helper function for concurrent execution"""
    target, path = args
    sitemap_url = urljoin(target, path)
    try:
        response = requests.head(sitemap_url, timeout=5, verify=False)
        if response.status_code == 200:
            content_type = response.headers.get('content-type', '').lower()
            if 'xml' in content_type or path.endswith('.xml'):
                return sitemap_url, path
    except:
        pass
    return None, None

def find_sitemaps(target):
    """Find sitemap files using concurrent requests"""
    sitemap_urls = []
    
    try:
        print(f"\n{Fore.GREEN}[+] Searching for sitemap files:{Style.RESET_ALL}")
        
        # Common sitemap locations
        sitemap_paths = [
            '/sitemap.xml',
            '/sitemap_index.xml',
            '/sitemaps.xml',
            '/sitemap1.xml',
            '/wp-sitemap.xml',
            '/post-sitemap.xml',
            '/page-sitemap.xml',
            '/category-sitemap.xml',
            '/product-sitemap.xml'
        ]
        
        # Use concurrent requests to check sitemap paths
        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            futures = [executor.submit(check_sitemap_url, (target, path)) for path in sitemap_paths]
            for future in concurrent.futures.as_completed(futures):
                try:
                    sitemap_url, path = future.result()
                    if sitemap_url:
                        sitemap_urls.append(sitemap_url)
                        print(f"    {Fore.GREEN}✓ Found: {path}{Style.RESET_ALL}")
                except Exception as e:
                    continue
        
        # Check robots.txt for sitemap declarations
        try:
            robots_url = urljoin(target, '/robots.txt')
            response = requests.get(robots_url, timeout=10, verify=False)
            if response.status_code == 200:
                # Look for Sitemap: declarations
                sitemap_pattern = r'Sitemap:\s*(https?://[^\s]+)'
                matches = re.findall(sitemap_pattern, response.text, re.IGNORECASE)
                for match in matches:
                    if match not in sitemap_urls:
                        sitemap_urls.append(match)
                        print(f"    {Fore.CYAN}✓ Found in robots.txt: {match}{Style.RESET_ALL}")
        except:
            pass
        
        if not sitemap_urls:
            print(f"    {Fore.YELLOW}No sitemap files found{Style.RESET_ALL}")
        else:
            print(f"    {Fore.YELLOW}Total sitemaps found: {len(sitemap_urls)}{Style.RESET_ALL}")
        
    except Exception as e:
        print(f"    {Fore.RED}✗ Error searching for sitemaps: {str(e)}{Style.RESET_ALL}")
    
    return sitemap_urls

def parse_single_sitemap(sitemap_url, depth=0):
    """Parse a single sitemap file or sitemap index recursively"""
    urls = []
    info = {
        'total_urls': 0,
        'last_modified': None,
        'languages': set(),
        'file_types': {},
        'errors': []
    }
    
    # Prevent infinite recursion
    if depth > 3:
        print(f"    {Fore.YELLOW}⚠ Maximum recursion depth reached for {sitemap_url}{Style.RESET_ALL}")
        return urls, info
    
    try:
        indent = "  " * depth
        print(f"\n{indent}{Fore.GREEN}[+] Parsing: {Fore.CYAN}{sitemap_url}{Style.RESET_ALL}")
        
        response = requests.get(sitemap_url, timeout=10, verify=False)
        if response.status_code != 200:
            print(f"    {indent}{Fore.RED}✗ Could not fetch sitemap (Status: {response.status_code}){Style.RESET_ALL}")
            return urls, info

        try:
            # Decompress gzipped sitemaps if necessary
            content = response.content
            content_type = response.headers.get('content-type', '').lower()
            if sitemap_url.lower().endswith('.gz') or 'gzip' in content_type:
                try:
                    with gzip.GzipFile(fileobj=io.BytesIO(content)) as gz:
                        content = gz.read()
                except Exception as e:
                    error_msg = f"Failed to decompress gzip sitemap: {str(e)}"
                    print(f"    {indent}{Fore.RED}✗ {error_msg}{Style.RESET_ALL}")
                    info['errors'].append(error_msg)
                    return urls, info

            # Parse XML
            root = ET.fromstring(content)

            # Determine if this is a sitemap index by checking the local name of the root element
            def local_name(tag):
                return tag.split('}', 1)[-1] if '}' in tag else tag

            if local_name(root.tag) == 'sitemapindex':
                print(f"    {indent}{Fore.CYAN}📁 This is a sitemap index{Style.RESET_ALL}")
                return parse_sitemap_index(root, depth)

            # Parse regular sitemap - look for URL entries using wildcard namespace matching
            url_elements = root.findall('.//{*}url')

            for url_elem in url_elements:
                url_data = extract_url_data(url_elem)
                if url_data:
                    urls.append(url_data)
                    analyze_url_info(url_data, info)

            info['total_urls'] = len(urls)
            print(f"    {indent}{Fore.GREEN}✓ Extracted {len(urls)} URLs{Style.RESET_ALL}")

        except ET.ParseError as e:
            error_msg = f"XML parsing error: {str(e)}"
            print(f"    {indent}{Fore.RED}✗ {error_msg}{Style.RESET_ALL}")
            info['errors'].append(error_msg)
            
    except Exception as e:
        error_msg = f"Error parsing sitemap: {str(e)}"
        print(f"    {indent}{Fore.RED}✗ {error_msg}{Style.RESET_ALL}")
        info['errors'].append(error_msg)
    
    return urls, info

def parse_sitemap_index(root, depth=0):
    """Parse sitemap index file using concurrent requests with proper recursion.

    The function uses wildcard namespace matching to find <sitemap> elements and
    extract their <loc> children.  It then spawns concurrent tasks to parse
    each referenced sitemap.
    """
    all_urls = []
    combined_info = {
        'total_urls': 0,
        'last_modified': None,
        'languages': set(),
        'file_types': {},
        'errors': []
    }
    
    indent = "  " * depth
    
    # Get all <sitemap> elements using wildcard namespace matching
    sitemap_refs = root.findall('.//{*}sitemap')

    print(f"    {indent}{Fore.CYAN}Found {len(sitemap_refs)} sitemap references in index{Style.RESET_ALL}")
    
    if not sitemap_refs:
        print(f"    {indent}{Fore.YELLOW}⚠ No sitemap references found in sitemap index{Style.RESET_ALL}")
        return all_urls, combined_info
    
    # Extract sitemap URLs from <sitemap><loc>...</loc></sitemap> entries
    sitemap_urls = []
    for sitemap_elem in sitemap_refs:
        # Use wildcard namespace for <loc>
        loc_elem = sitemap_elem.find('.//{*}loc')
        if loc_elem is not None and loc_elem.text:
            sitemap_urls.append(loc_elem.text.strip())
            print(f"    {indent}  {Fore.BLUE}→ Found sitemap: {loc_elem.text.strip()}{Style.RESET_ALL}")
    
    if not sitemap_urls:
        print(f"    {indent}{Fore.YELLOW}⚠ No valid sitemap URLs found in sitemap references{Style.RESET_ALL}")
        return all_urls, combined_info
    
    print(f"    {indent}{Fore.GREEN}Parsing {len(sitemap_urls)} child sitemaps...{Style.RESET_ALL}")
    
    # Use concurrent requests to parse child sitemaps recursively
    with concurrent.futures.ThreadPoolExecutor(max_workers=15) as executor:
        futures = {executor.submit(parse_single_sitemap, sitemap_url, depth + 1): sitemap_url for sitemap_url in sitemap_urls}
        for future in concurrent.futures.as_completed(futures):
            sitemap_url = futures[future]
            try:
                urls, info = future.result()
                all_urls.extend(urls)
                
                # Combine info
                combined_info['total_urls'] += info['total_urls']
                combined_info['languages'].update(info['languages'])
                combined_info['errors'].extend(info['errors'])
                
                for file_type, count in info['file_types'].items():
                    combined_info['file_types'][file_type] = combined_info['file_types'].get(file_type, 0) + count
                    
                print(f"    {indent}  {Fore.GREEN}✓ Processed {sitemap_url}: {info['total_urls']} URLs{Style.RESET_ALL}")
                
            except Exception as e:
                error_msg = f"Error processing sitemap from index {sitemap_url}: {str(e)}"
                combined_info['errors'].append(error_msg)
                print(f"    {indent}  {Fore.RED}✗ Error processing {sitemap_url}: {str(e)}{Style.RESET_ALL}")
    
    print(f"    {indent}{Fore.GREEN}✓ Index parsing complete: {combined_info['total_urls']} total URLs discovered{Style.RESET_ALL}")
    return all_urls, combined_info

def extract_url_data(url_elem):
    """Extract data from a <url> element.

    This helper uses wildcard namespace matching so it works regardless of the
    specific namespace used in the sitemap.
    """
    url_data = {}

    # Extract location (required)
    loc_elem = url_elem.find('.//{*}loc')
    if loc_elem is None or not loc_elem.text:
        return None
    url_data['loc'] = loc_elem.text.strip()

    # Extract last modification date
    lastmod_elem = url_elem.find('.//{*}lastmod')
    if lastmod_elem is not None and lastmod_elem.text:
        url_data['lastmod'] = lastmod_elem.text.strip()

    # Extract change frequency
    changefreq_elem = url_elem.find('.//{*}changefreq')
    if changefreq_elem is not None and changefreq_elem.text:
        url_data['changefreq'] = changefreq_elem.text.strip()

    # Extract priority
    priority_elem = url_elem.find('.//{*}priority')
    if priority_elem is not None and priority_elem.text:
        url_data['priority'] = priority_elem.text.strip()

    return url_data

def analyze_url_info(url_data, info):
    """Analyze URL data and update info statistics"""
    url = url_data['loc']
    parsed_url = urlparse(url)
    
    # Detect file type
    path = parsed_url.path.lower()
    if '.' in path:
        extension = path.split('.')[-1]
        if extension in ['html', 'htm', 'php', 'asp', 'aspx', 'jsp', 'pdf', 'xml', 'json']:
            info['file_types'][extension] = info['file_types'].get(extension, 0) + 1
    else:
        info['file_types']['page'] = info['file_types'].get('page', 0) + 1
    
    # Detect language (simple heuristic)
    if '/en/' in path or path.startswith('/en'):
        info['languages'].add('en')
    elif '/es/' in path or path.startswith('/es'):
        info['languages'].add('es')
    elif '/fr/' in path or path.startswith('/fr'):
        info['languages'].add('fr')
    elif '/de/' in path or path.startswith('/de'):
        info['languages'].add('de')

def analyze_sitemap_data(all_urls, sitemap_info, target):
    """Analyze and display sitemap data"""
    print(f"\n{Fore.GREEN}[+] Sitemap Analysis Results:{Style.RESET_ALL}")
    
    total_urls = len(all_urls)
    print(f"    {Fore.CYAN}Total URLs discovered: {Fore.YELLOW}{total_urls}{Style.RESET_ALL}")
    print(f"    {Fore.CYAN}Sitemaps analyzed: {Fore.YELLOW}{len(sitemap_info)}{Style.RESET_ALL}")
    
    if not all_urls:
        print(f"    {Fore.YELLOW}No URLs found in sitemaps{Style.RESET_ALL}")
        return
    
    # Analyze URL patterns
    url_patterns = analyze_url_patterns(all_urls)
    
    # Display file type distribution
    print(f"\n{Fore.GREEN}[+] Content Type Distribution:{Style.RESET_ALL}")
    all_file_types = {}
    for info in sitemap_info.values():
        for file_type, count in info['file_types'].items():
            all_file_types[file_type] = all_file_types.get(file_type, 0) + count
    
    for file_type, count in sorted(all_file_types.items(), key=lambda x: x[1], reverse=True):
        percentage = (count / total_urls) * 100
        print(f"    {Fore.CYAN}{file_type.upper()}: {Fore.YELLOW}{count} ({percentage:.1f}%){Style.RESET_ALL}")
    
    # Display language detection
    all_languages = set()
    for info in sitemap_info.values():
        all_languages.update(info['languages'])
    
    if all_languages:
        print(f"\n{Fore.GREEN}[+] Detected Languages:{Style.RESET_ALL}")
        for lang in sorted(all_languages):
            print(f"    {Fore.CYAN}• {lang.upper()}{Style.RESET_ALL}")
    
    # Display URL patterns
    print(f"\n{Fore.GREEN}[+] URL Patterns Found:{Style.RESET_ALL}")
    for pattern, count in sorted(url_patterns.items(), key=lambda x: x[1], reverse=True)[:10]:
        print(f"    {Fore.CYAN}{pattern}: {Fore.YELLOW}{count} URLs{Style.RESET_ALL}")
    
    # Show sample URLs
    print(f"\n{Fore.GREEN}[+] Sample URLs:{Style.RESET_ALL}")
    for i, url_data in enumerate(all_urls[:10], 1):
        url = url_data['loc']
        lastmod = url_data.get('lastmod', 'Unknown')
        priority = url_data.get('priority', 'N/A')
        
        print(f"    {Fore.CYAN}[{i:2d}] {url}{Style.RESET_ALL}")
        if lastmod != 'Unknown' or priority != 'N/A':
            print(f"         {Fore.YELLOW}Modified: {lastmod} | Priority: {priority}{Style.RESET_ALL}")
    
    if len(all_urls) > 10:
        print(f"    {Fore.YELLOW}... and {len(all_urls) - 10} more URLs{Style.RESET_ALL}")
    
    # Security insights
    print(f"\n{Fore.GREEN}[+] Security Insights:{Style.RESET_ALL}")
    admin_urls = [url['loc'] for url in all_urls if any(keyword in url['loc'].lower() for keyword in ['admin', 'login', 'dashboard', 'panel'])]
    if admin_urls:
        print(f"    {Fore.RED}⚠ Found {len(admin_urls)} potential admin URLs{Style.RESET_ALL}")
        for admin_url in admin_urls[:3]:
            print(f"      {Fore.RED}• {admin_url}{Style.RESET_ALL}")
    
    api_urls = [url['loc'] for url in all_urls if '/api/' in url['loc'].lower()]
    if api_urls:
        print(f"    {Fore.YELLOW}ℹ Found {len(api_urls)} potential API endpoints{Style.RESET_ALL}")
    
    # Recommendations
    print(f"\n{Fore.GREEN}[+] Recommendations:{Style.RESET_ALL}")
    print(f"    {Fore.CYAN}• Test discovered URLs for access control issues{Style.RESET_ALL}")
    print(f"    {Fore.CYAN}• Check for sensitive information in URL parameters{Style.RESET_ALL}")
    print(f"    {Fore.CYAN}• Analyze URL patterns for potential vulnerabilities{Style.RESET_ALL}")
    print(f"    {Fore.CYAN}• Cross-reference with directory bruteforce results{Style.RESET_ALL}")

def analyze_url_patterns(all_urls):
    """Analyze URL patterns to find common structures"""
    patterns = {}
    
    for url_data in all_urls:
        url = url_data['loc']
        parsed_url = urlparse(url)
        path = parsed_url.path
        
        # Extract pattern (first two path segments)
        path_parts = [part for part in path.split('/') if part]
        if len(path_parts) >= 2:
            pattern = f"/{path_parts[0]}/{path_parts[1]}/"
        elif len(path_parts) == 1:
            pattern = f"/{path_parts[0]}/"
        else:
            pattern = "/"
        
        patterns[pattern] = patterns.get(pattern, 0) + 1
    
    return patterns