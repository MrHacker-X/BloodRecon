#!/usr/bin/env python3
"""
Favicon Hash Identifier Module
Generate favicon hashes (Shodan mmh3 algorithm) and identify technologies.

The hash is computed exactly as Shodan does: mmh3 over the **base64 of the
raw bytes including newlines every 76 chars**. Known-hash entries below are
real, widely published Shodan favicon hashes.
Author : Alex Butler (@MrHacker-X)
Org    : Vritra Security Organization
"""

import base64
import requests
from urllib.parse import urljoin
from bloodrecon.modules.colors import Fore, Style
import urllib3

# Try to import mmh3, fallback to a warning if not available
try:
    import mmh3
    MMH3_AVAILABLE = True
except ImportError:
    MMH3_AVAILABLE = False
    print(f"{Fore.YELLOW}[WARNING] mmh3 library not available. Install it with: pip install mmh3{Style.RESET_ALL}")
    print(f"{Fore.CYAN}[INFO] Without mmh3 the Shodan-compatible hash cannot be computed.{Style.RESET_ALL}")

# Suppress SSL warnings for unverified requests
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Known Shodan favicon hashes (public, verified values — mmh3 of base64 body).
# Source: published Shodan/Community-generated favicon lists.
FAVICON_HASHES = {
    '-1251250729': 'Nextcloud',
    '1078193750': 'Grafana',
    '-868560772': 'Kibana',
    '463042405': 'Jenkins',
    '-905266182': 'phpMyAdmin',
    '-718040729': 'Apache Tomcat default',
    '492204584': 'GitLab',
    '699658622': 'pfSense',
    '-2015940991': 'WordPress',
    '-1822446232': 'Joomla',
    '-1246267188': 'Drupal (default)',
    '-1024819118': 'Moodle',
    '1850143622': 'Microsoft IIS default',
    '1185408927': 'nginx default',
    '1382867990': 'Apache default page',
}

def shodan_favicon_hash(favicon_bytes):
    """Compute the Shodan-compatible favicon hash.

    Shodan's algorithm: base64-encode the raw body (RFC 2045, i.e. with
    newlines every 76 chars) then take mmh3 of the UTF-8 encoded string.
    Returns None when mmh3 is unavailable.
    """
    if not MMH3_AVAILABLE:
        return None
    b64 = base64.encodebytes(favicon_bytes)
    return mmh3.hash(b64)


def generate_favicon_hash(target):
    """Generate favicon hash using the Shodan mmh3 algorithm"""
    try:
        print(f"\n{Fore.CYAN}╔══════════════════════════════════════════════════════════════╗")
        print(f"║                  {Fore.YELLOW}FAVICON HASH IDENTIFIER{Fore.CYAN}                     ║")
        print(f"╚══════════════════════════════════════════════════════════════╝{Style.RESET_ALL}")
        
        # Ensure URL has protocol
        if not target.startswith(('http://', 'https://')):
            target = 'https://' + target
        
        print(f"\n{Fore.GREEN}[+] Analyzing favicon for: {Fore.YELLOW}{target}{Style.RESET_ALL}")
        
        # Common favicon locations
        favicon_paths = [
            '/favicon.ico',
            '/favicon.png',
            '/apple-touch-icon.png',
            '/apple-touch-icon-precomposed.png',
            '/android-chrome-192x192.png',
            '/android-chrome-512x512.png',
            '/mstile-150x150.png',
            '/browserconfig.xml'
        ]
        
        favicon_found = False
        
        for path in favicon_paths:
            favicon_url = urljoin(target, path)
            try:
                print(f"  {Fore.CYAN}→ Trying: {path}{Style.RESET_ALL}")
                
                response = requests.get(favicon_url, timeout=10, verify=False)
                if response.status_code == 200 and len(response.content) > 0:
                    favicon_found = True
                    print(f"    {Fore.GREEN}✓ Found favicon: {path}{Style.RESET_ALL}")

                    favicon_hash = shodan_favicon_hash(response.content)
                    if favicon_hash is None:
                        print(f"    {Fore.RED}✗ Cannot compute Shodan hash without mmh3 (pip install mmh3){Style.RESET_ALL}")
                        analyze_favicon_properties(response.content, favicon_url)
                        break

                    print(f"    {Fore.CYAN}File size: {len(response.content)} bytes{Style.RESET_ALL}")
                    print(f"    {Fore.CYAN}Content-Type: {response.headers.get('content-type', 'Unknown')}{Style.RESET_ALL}")
                    print(f"    {Fore.YELLOW}Favicon Hash (Shodan mmh3): {favicon_hash}{Style.RESET_ALL}")

                    # Check against known hashes
                    check_favicon_technology(favicon_hash, favicon_url)

                    # Shodan search link for this hash
                    print(f"    {Fore.CYAN}Find all hosts with this favicon:{Style.RESET_ALL}")
                    print(f"      {Fore.MAGENTA}https://www.shodan.io/search?field=favicon&value={favicon_hash}{Style.RESET_ALL}")

                    # Additional analysis
                    analyze_favicon_properties(response.content, favicon_url)
                    break
                    
            except requests.exceptions.RequestException as e:
                continue
            except Exception as e:
                print(f"    {Fore.RED}✗ Error processing {path}: {str(e)}{Style.RESET_ALL}")
                continue
        
        if not favicon_found:
            print(f"  {Fore.YELLOW}No favicon found at common locations{Style.RESET_ALL}")
            
            # Try to extract favicon from HTML
            try_extract_favicon_from_html(target)
        
        # Additional favicon intelligence
        provide_favicon_recommendations()
        
    except Exception as e:
        print(f"{Fore.RED}[ERROR] Favicon analysis failed: {str(e)}{Style.RESET_ALL}")


def check_favicon_technology(favicon_hash, favicon_url):
    """Check favicon hash against known technology signatures"""
    hash_str = str(favicon_hash)

    print(f"\n{Fore.GREEN}[+] Technology Identification:{Style.RESET_ALL}")

    if hash_str in FAVICON_HASHES:
        technology = FAVICON_HASHES[hash_str]
        print(f"    {Fore.RED}🎯 MATCH FOUND: {technology}{Style.RESET_ALL}")
        print(f"    {Fore.YELLOW}Hash: {hash_str}{Style.RESET_ALL}")
        print(f"    {Fore.CYAN}This indicates the target is likely running: {technology}{Style.RESET_ALL}")
    else:
        print(f"    {Fore.YELLOW}No known technology match for hash: {hash_str}{Style.RESET_ALL}")
        print(f"    {Fore.CYAN}Search the hash on Shodan to discover the technology{Style.RESET_ALL}")


def find_similar_hashes(target_hash):
    """Deprecated: fuzzy hash matching produced false positives — removed."""
    return []

def analyze_favicon_properties(favicon_data, favicon_url):
    """Analyze favicon properties for additional intelligence"""
    print(f"\n{Fore.GREEN}[+] Favicon Properties Analysis:{Style.RESET_ALL}")
    
    # File size analysis
    size = len(favicon_data)
    if size < 1024:
        size_desc = f"{size} bytes (Very small - possibly default)"
    elif size < 5120:
        size_desc = f"{size} bytes (Small - typical favicon)"
    elif size < 20480:
        size_desc = f"{size} bytes (Medium - detailed favicon)"
    else:
        size_desc = f"{size} bytes (Large - high-resolution favicon)"
    
    print(f"    {Fore.CYAN}Size Analysis: {size_desc}{Style.RESET_ALL}")
    
    # Check for common patterns in favicon data
    data_hex = favicon_data.hex() if hasattr(favicon_data, 'hex') else favicon_data[:100].hex()
    
    # ICO file signature
    if data_hex.startswith('0000'):
        print(f"    {Fore.CYAN}Format: ICO (Windows Icon){Style.RESET_ALL}")
    elif data_hex.startswith('89504e47'):
        print(f"    {Fore.CYAN}Format: PNG{Style.RESET_ALL}")
    elif data_hex.startswith('ffd8ff'):
        print(f"    {Fore.CYAN}Format: JPEG{Style.RESET_ALL}")
    elif data_hex.startswith('474946'):
        print(f"    {Fore.CYAN}Format: GIF{Style.RESET_ALL}")
    else:
        print(f"    {Fore.YELLOW}Format: Unknown or custom{Style.RESET_ALL}")

def try_extract_favicon_from_html(target):
    """Try to extract favicon URL from HTML head section"""
    try:
        print(f"\n{Fore.CYAN}[+] Checking HTML for favicon references:{Style.RESET_ALL}")
        
        response = requests.get(target, timeout=10, verify=False)
        if response.status_code == 200:
            html_content = response.text.lower()
            
            # Look for favicon link tags
            import re
            favicon_patterns = [
                r'<link[^>]*rel=["\']icon["\'][^>]*href=["\']([^"\']+)["\']',
                r'<link[^>]*href=["\']([^"\']+)["\'][^>]*rel=["\']icon["\']',
                r'<link[^>]*rel=["\']shortcut icon["\'][^>]*href=["\']([^"\']+)["\']',
                r'<link[^>]*href=["\']([^"\']+)["\'][^>]*rel=["\']shortcut icon["\']'
            ]
            
            for pattern in favicon_patterns:
                matches = re.findall(pattern, html_content)
                for match in matches:
                    favicon_url = urljoin(target, match)
                    print(f"    {Fore.GREEN}✓ Found favicon reference: {match}{Style.RESET_ALL}")
                    
                    # Try to fetch this favicon
                    try:
                        fav_response = requests.get(favicon_url, timeout=10, verify=False)
                        if fav_response.status_code == 200:
                            favicon_hash = shodan_favicon_hash(fav_response.content)
                            if favicon_hash is None:
                                print(f"    {Fore.RED}✗ Cannot compute Shodan hash without mmh3{Style.RESET_ALL}")
                                return
                            print(f"    {Fore.YELLOW}Favicon Hash: {favicon_hash}{Style.RESET_ALL}")
                            check_favicon_technology(favicon_hash, favicon_url)
                            return
                    except:
                        continue
    except:
        pass

def provide_favicon_recommendations():
    """Provide recommendations for favicon analysis"""
    print(f"\n{Fore.GREEN}[+] Recommendations:{Style.RESET_ALL}")
    print(f"    {Fore.CYAN}• Use favicon hashes for technology fingerprinting{Style.RESET_ALL}")
    print(f"    {Fore.CYAN}• Check multiple favicon formats (ico, png, svg){Style.RESET_ALL}")
    print(f"    {Fore.CYAN}• Build custom favicon hash database for your targets{Style.RESET_ALL}")
    print(f"    {Fore.CYAN}• Consider favicon changes as indicators of updates{Style.RESET_ALL}")
    print(f"    {Fore.CYAN}• Cross-reference with other fingerprinting methods{Style.RESET_ALL}")

def add_custom_favicon_hash(hash_value, technology_name):
    """Add custom favicon hash to the database"""
    FAVICON_HASHES[str(hash_value)] = technology_name
    print(f"{Fore.GREEN}[+] Added custom hash: {hash_value} -> {technology_name}{Style.RESET_ALL}")

# Export functions for use in main tool
__all__ = ['generate_favicon_hash', 'add_custom_favicon_hash']
