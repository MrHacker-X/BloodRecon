#!/usr/bin/env python3
"""
Shodan Integration Module
Query Shodan API for host information, vulnerabilities, and network intelligence
Author : Alex Butler (@MrHacker-X)
Org    : Vritra Security Organization
"""

import requests
import json
import os
import importlib.util
from bloodrecon.modules.colors import Fore, Style
import socket
from urllib.parse import urlparse

# Default Shodan API endpoint
SHODAN_API_BASE = "https://api.shodan.io"

class ShodanLookup:
    def __init__(self, api_key: str = None) -> None:
        """
        Initialise the Shodan client with an API key.
        """
        self.session = requests.Session()
        # Path to the JSON API key configuration file
        config_dir = os.path.expanduser('~/.config-vritrasecz')
        self.config_file = os.path.join(config_dir, 'bloodrecon-shodan.json')
        
        # Create config directory if it doesn't exist
        os.makedirs(config_dir, exist_ok=True)
        
        # Determine the API key
        if api_key:
            self.api_key = api_key.strip()
            # Persist the provided key for future reuse
            self.save_api_key(self.api_key)
        else:
            self.api_key = self.load_api_key()
        
    def load_api_key(self) -> str:
        """
        Load the Shodan API key from a variety of sources.

        The lookup order is:

        1. `SHODAN_API_KEY` environment variable.
        2. A `config.py` under `~/.config-vritrasecz/` (or a legacy in-tree copy)
           defining `SHODAN_API_KEY`.
        3. A JSON config file stored in `~/.config-vritrasecz/bloodrecon-shodan.json`.
        4. Interactive prompt requesting a new API key.  The new key is stored
           in the JSON config file so that future runs will not prompt again.
        """
        # 1. Environment variable override
        env_key = os.getenv('SHODAN_API_KEY')
        if env_key:
            return env_key.strip()

        # 2. Look for API key defined in config.py
        config_py_key = self.load_api_key_from_config_py()
        if config_py_key:
            # Display masked key and ask if user wants to replace it
            masked = self.mask_key(config_py_key)
            config_path = self.get_config_py_path()
            print(f"{Fore.GREEN}[+] API loaded from {config_path}: {masked}{Style.RESET_ALL}")
            new_key = input(
                f"{Fore.YELLOW}[INPUT] Press Enter to keep this key or enter a new key to replace it: {Style.RESET_ALL}"
            ).strip()
            if new_key:
                # Save and return the new key
                self.save_api_key(new_key)
                return new_key
            return config_py_key.strip()

        # 3. Load from JSON config file (~/.config-vritrasecz/bloodrecon-shodan.json)
        if os.path.exists(self.config_file):
            try:
                with open(self.config_file, 'r', encoding='utf-8') as file:
                    config = json.load(file)
                    api_key = config.get('api_key')
                    if api_key:
                        return api_key.strip()
            except (json.JSONDecodeError, IOError):
                # Ignore and prompt user
                pass

        # 4. Prompt the user for a new key
        api_key = input(f"{Fore.YELLOW}[INPUT] Enter Shodan API key: {Style.RESET_ALL}").strip()
        if api_key:
            self.save_api_key(api_key)
        return api_key

    def mask_key(self, key: str) -> str:
        """Return a masked representation of an API key (first 4 and last 4 characters)."""
        if not key or len(key) < 8:
            return key
        return f"{key[:4]}...{key[-4:]}"

    def get_config_py_path(self) -> str:
        """Return path for an optional config.py under ~/.config-vritrasecz/."""
        return os.path.join(os.path.expanduser('~/.config-vritrasecz'), 'config.py')

    def _legacy_config_py_paths(self):
        """Old in-tree locations (read-only fallback; never write here)."""
        here = os.path.dirname(os.path.abspath(__file__))
        return [
            os.path.join(here, 'config.py'),
            # pre-package layout
            os.path.join(os.path.dirname(os.path.dirname(here)), 'modules', 'config.py'),
        ]

    def load_api_key_from_config_py(self) -> str:
        """
        Load `SHODAN_API_KEY` from config.py if present.

        Prefers ~/.config-vritrasecz/config.py; falls back to legacy in-tree
        paths for older installs (those paths are never written to).
        """
        candidates = [self.get_config_py_path()] + self._legacy_config_py_paths()
        for config_path in candidates:
            if not os.path.exists(config_path):
                continue
            try:
                spec = importlib.util.spec_from_file_location('shodan_config', config_path)
                if spec and spec.loader:
                    module = importlib.util.module_from_spec(spec)
                    spec.loader.exec_module(module)
                    key = getattr(module, 'SHODAN_API_KEY', None)
                    if key:
                        return str(key)
            except Exception:
                pass
        return None

    def save_api_key_to_config_py(self, api_key: str) -> None:
        """
        Save the API key to ~/.config-vritrasecz/config.py (outside the package tree).
        """
        config_path = self.get_config_py_path()
        try:
            os.makedirs(os.path.dirname(config_path), exist_ok=True)
            with open(config_path, 'w', encoding='utf-8') as f:
                f.write(f"SHODAN_API_KEY = '{api_key}'\n")
        except IOError as e:
            print(f"{Fore.YELLOW}[WARNING] Could not save API key to config.py: {e}{Style.RESET_ALL}")

    def save_api_key(self, api_key):
        """Save Shodan API key to config file"""
        try:
            with open(self.config_file, 'w') as file:
                json.dump({'api_key': api_key}, file)
        except IOError as e:
            print(f"{Fore.YELLOW}[WARNING] Could not save API key to config file: {e}{Style.RESET_ALL}")
        
    def search_shodan(self, target, query_type="host"):
        """Main Shodan search function"""
        try:
            print(f"\n{Fore.CYAN}╔══════════════════════════════════════════════════════════════╗")
            print(f"║                      {Fore.YELLOW}SHODAN INTEGRATION{Fore.CYAN}                      ║")
            print(f"╚══════════════════════════════════════════════════════════════╝{Style.RESET_ALL}")
            
            if not self.api_key:
                print(f"\n{Fore.RED}[ERROR] No Shodan API key provided{Style.RESET_ALL}")
                print(f"{Fore.CYAN}[INFO] Get your free API key at: https://account.shodan.io/register{Style.RESET_ALL}")
                return
            
            print(f"\n{Fore.GREEN}[+] Querying Shodan for: {Fore.YELLOW}{target}{Style.RESET_ALL}")
            
            # Extract IP or hostname
            if target.startswith(('http://', 'https://')):
                parsed = urlparse(target)
                target = parsed.hostname
            
            # Try to resolve hostname to IP if needed
            try:
                ip_address = socket.gethostbyname(target)
                print(f"    {Fore.CYAN}Resolved {target} to {ip_address}{Style.RESET_ALL}")
                target = ip_address
            except socket.gaierror:
                # Target might already be an IP
                pass
            
            if query_type == "host":
                self.host_lookup(target)
            elif query_type == "search":
                self.search_query(target)
            else:
                self.host_lookup(target)
                
        except Exception as e:
            print(f"{Fore.RED}[ERROR] Shodan lookup failed: {str(e)}{Style.RESET_ALL}")
    
    def host_lookup(self, ip_address):
        """Lookup specific host information"""
        try:
            print(f"\n{Fore.GREEN}[+] Host Information Lookup:{Style.RESET_ALL}")
            
            url = f"{SHODAN_API_BASE}/shodan/host/{ip_address}"
            params = {'key': self.api_key}
            
            response = self.session.get(url, params=params, timeout=15)
            
            if response.status_code == 200:
                data = response.json()
                self.parse_host_data(data)
            elif response.status_code == 404:
                print(f"    {Fore.YELLOW}No information found for {ip_address}{Style.RESET_ALL}")
            elif response.status_code == 401:
                print(f"    {Fore.RED}Invalid API key{Style.RESET_ALL}")
            else:
                print(f"    {Fore.RED}API request failed (Status: {response.status_code}){Style.RESET_ALL}")
                
        except requests.exceptions.RequestException as e:
            print(f"    {Fore.RED}Network error: {str(e)}{Style.RESET_ALL}")
        except Exception as e:
            print(f"    {Fore.RED}Error processing host data: {str(e)}{Style.RESET_ALL}")
    
    def parse_host_data(self, data):
        """Parse and display host data from Shodan"""
        try:
            # Basic host information
            print(f"    {Fore.CYAN}IP Address: {data.get('ip_str', 'Unknown')}{Style.RESET_ALL}")
            print(f"    {Fore.CYAN}Organization: {data.get('org', 'Unknown')}{Style.RESET_ALL}")
            print(f"    {Fore.CYAN}ISP: {data.get('isp', 'Unknown')}{Style.RESET_ALL}")
            print(f"    {Fore.CYAN}Country: {data.get('country_name', 'Unknown')} ({data.get('country_code', 'XX')}){Style.RESET_ALL}")
            print(f"    {Fore.CYAN}City: {data.get('city', 'Unknown')}{Style.RESET_ALL}")
            print(f"    {Fore.CYAN}Region: {data.get('region_code', 'Unknown')}{Style.RESET_ALL}")
            print(f"    {Fore.CYAN}Postal Code: {data.get('postal_code', 'Unknown')}{Style.RESET_ALL}")
            print(f"    {Fore.CYAN}Latitude: {data.get('latitude', 'Unknown')}{Style.RESET_ALL}")
            print(f"    {Fore.CYAN}Longitude: {data.get('longitude', 'Unknown')}{Style.RESET_ALL}")
            
            # ASN information
            if 'asn' in data:
                print(f"    {Fore.CYAN}ASN: AS{data.get('asn', 'Unknown')}{Style.RESET_ALL}")
            
            # Last update
            if 'last_update' in data:
                print(f"    {Fore.CYAN}Last Updated: {data['last_update']}{Style.RESET_ALL}")
            
            # Operating System
            if 'os' in data:
                print(f"    {Fore.CYAN}Operating System: {data['os']}{Style.RESET_ALL}")
            
            # Hostnames
            hostnames = data.get('hostnames', [])
            if hostnames:
                print(f"\n{Fore.GREEN}[+] Hostnames ({len(hostnames)}):{Style.RESET_ALL}")
                for hostname in hostnames[:10]:  # Show first 10
                    print(f"    {Fore.YELLOW}• {hostname}{Style.RESET_ALL}")
            
            # Domains
            domains = data.get('domains', [])
            if domains:
                print(f"\n{Fore.GREEN}[+] Domains ({len(domains)}):{Style.RESET_ALL}")
                for domain in domains[:10]:  # Show first 10
                    print(f"    {Fore.YELLOW}• {domain}{Style.RESET_ALL}")
            
            # Services/Ports
            services = data.get('data', [])
            if services:
                print(f"\n{Fore.GREEN}[+] Open Services ({len(services)}):{Style.RESET_ALL}")
                self.parse_services(services)
            
            # Vulnerabilities
            vulns = data.get('vulns', [])
            if vulns:
                print(f"\n{Fore.RED}[!] Vulnerabilities Found ({len(vulns)}):{Style.RESET_ALL}")
                for vuln in vulns[:10]:  # Show first 10
                    print(f"    {Fore.RED}• {vuln}{Style.RESET_ALL}")
            
            # Tags
            tags = data.get('tags', [])
            if tags:
                print(f"\n{Fore.GREEN}[+] Tags:{Style.RESET_ALL}")
                for tag in tags:
                    print(f"    {Fore.CYAN}• {tag}{Style.RESET_ALL}")
                    
        except Exception as e:
            print(f"    {Fore.RED}Error parsing host data: {str(e)}{Style.RESET_ALL}")
    
    def parse_services(self, services):
        """Parse and display service information"""
        try:
            for i, service in enumerate(services[:20], 1):  # Show first 20 services
                port = service.get('port', 'Unknown')
                protocol = service.get('transport', 'Unknown')
                product = service.get('product', 'Unknown')
                version = service.get('version', '')
                banner = service.get('data', '').strip()
                
                print(f"    {Fore.YELLOW}[{i:2d}] Port {port}/{protocol.upper()}{Style.RESET_ALL}")
                
                if product != 'Unknown':
                    version_str = f" {version}" if version else ""
                    print(f"         {Fore.CYAN}Service: {product}{version_str}{Style.RESET_ALL}")
                
                # Show banner (first line only)
                if banner:
                    banner_line = banner.split('\n')[0][:100]
                    print(f"         {Fore.GREEN}Banner: {banner_line}...{Style.RESET_ALL}")
                
                # Check for SSL/TLS
                if 'ssl' in service:
                    ssl_info = service['ssl']
                    if 'cert' in ssl_info:
                        cert = ssl_info['cert']
                        subject = cert.get('subject', {})
                        if 'CN' in subject:
                            print(f"         {Fore.MAGENTA}SSL CN: {subject['CN']}{Style.RESET_ALL}")
                
                # Check for HTTP information
                if 'http' in service:
                    http_info = service['http']
                    if 'title' in http_info:
                        print(f"         {Fore.CYAN}HTTP Title: {http_info['title'][:50]}...{Style.RESET_ALL}")
                    if 'server' in http_info:
                        print(f"         {Fore.CYAN}Server: {http_info['server']}{Style.RESET_ALL}")
                
                print()  # Empty line for readability
                
        except Exception as e:
            print(f"    {Fore.RED}Error parsing services: {str(e)}{Style.RESET_ALL}")
    
    def search_query(self, query):
        """Perform a search query on Shodan"""
        try:
            print(f"\n{Fore.GREEN}[+] Search Query: {Fore.YELLOW}{query}{Style.RESET_ALL}")
            
            url = f"{SHODAN_API_BASE}/shodan/host/search"
            params = {
                'key': self.api_key,
                'query': query,
                'limit': 100  # Limit results
            }
            
            response = self.session.get(url, params=params, timeout=30)
            
            if response.status_code == 200:
                data = response.json()
                self.parse_search_results(data)
            elif response.status_code == 401:
                print(f"    {Fore.RED}Invalid API key{Style.RESET_ALL}")
            else:
                print(f"    {Fore.RED}Search failed (Status: {response.status_code}){Style.RESET_ALL}")
                
        except requests.exceptions.RequestException as e:
            print(f"    {Fore.RED}Network error: {str(e)}{Style.RESET_ALL}")
        except Exception as e:
            print(f"    {Fore.RED}Error processing search results: {str(e)}{Style.RESET_ALL}")
    
    def parse_search_results(self, data):
        """Parse and display search results"""
        try:
            total = data.get('total', 0)
            matches = data.get('matches', [])
            
            print(f"    {Fore.CYAN}Total results: {total:,}{Style.RESET_ALL}")
            print(f"    {Fore.CYAN}Showing: {len(matches)} results{Style.RESET_ALL}")
            
            if not matches:
                print(f"    {Fore.YELLOW}No results found{Style.RESET_ALL}")
                return
            
            print(f"\n{Fore.GREEN}[+] Search Results:{Style.RESET_ALL}")
            
            for i, match in enumerate(matches[:50], 1):  # Show first 50
                ip = match.get('ip_str', 'Unknown')
                port = match.get('port', 'Unknown')
                org = match.get('org', 'Unknown')
                location = f"{match.get('city', 'Unknown')}, {match.get('country_code', 'XX')}"
                
                print(f"    {Fore.YELLOW}[{i:2d}] {ip}:{port} - {org} ({location}){Style.RESET_ALL}")
                
                # Show banner if available
                banner = match.get('data', '').strip()
                if banner:
                    banner_line = banner.split('\n')[0][:80]
                    print(f"         {Fore.GREEN}{banner_line}...{Style.RESET_ALL}")
                
                print()  # Empty line for readability
                
        except Exception as e:
            print(f"    {Fore.RED}Error parsing search results: {str(e)}{Style.RESET_ALL}")
    
    def get_api_info(self):
        """Get API information and usage statistics"""
        try:
            print(f"\n{Fore.GREEN}[+] API Information:{Style.RESET_ALL}")
            
            url = f"{SHODAN_API_BASE}/api-info"
            params = {'key': self.api_key}
            
            response = self.session.get(url, params=params, timeout=10)
            
            if response.status_code == 200:
                data = response.json()
                print(f"    {Fore.CYAN}Plan: {data.get('plan', 'Unknown')}{Style.RESET_ALL}")
                print(f"    {Fore.CYAN}Query Credits: {data.get('query_credits', 0)}{Style.RESET_ALL}")
                print(f"    {Fore.CYAN}Scan Credits: {data.get('scan_credits', 0)}{Style.RESET_ALL}")
            else:
                print(f"    {Fore.RED}Failed to get API info (Status: {response.status_code}){Style.RESET_ALL}")
                
        except Exception as e:
            print(f"    {Fore.RED}Error getting API info: {str(e)}{Style.RESET_ALL}")

def search_shodan_host(target, api_key=None):
    """Convenience function for host lookup"""
    shodan = ShodanLookup(api_key)
    shodan.search_shodan(target, "host")

def search_shodan_query(query, api_key=None):
    """Convenience function for search query"""
    shodan = ShodanLookup(api_key)
    shodan.search_shodan(query, "search")

def set_shodan_api_key(api_key):
    """Set Shodan API key directly without interactive mode"""
    try:
        if not api_key or not api_key.strip():
            print(f"{Fore.RED}[ERROR] API key cannot be empty{Style.RESET_ALL}")
            return False
            
        # Create config directory if it doesn't exist
        config_dir = os.path.expanduser('~/.config-vritrasecz')
        os.makedirs(config_dir, exist_ok=True)
        
        config_file = os.path.join(config_dir, 'bloodrecon-shodan.json')
        
        # Save the API key (will replace existing one if it exists)
        with open(config_file, 'w') as file:
            json.dump({'api_key': api_key.strip()}, file)
            
        print(f"\n{Fore.GREEN}[+] Shodan API key saved successfully!{Style.RESET_ALL}")
        print(f"    {Fore.CYAN}Config location: {config_file}{Style.RESET_ALL}")
            
        return True
        
    except Exception as e:
        print(f"{Fore.RED}[ERROR] Failed to save API key: {str(e)}{Style.RESET_ALL}")
        return False

def provide_shodan_recommendations():
    """Provide recommendations for Shodan usage"""
    print(f"\n{Fore.GREEN}[+] Shodan Recommendations:{Style.RESET_ALL}")
    print(f"    {Fore.CYAN}• Use specific search queries for better results{Style.RESET_ALL}")
    print(f"    {Fore.CYAN}• Check for exposed services and misconfigurations{Style.RESET_ALL}")
    print(f"    {Fore.CYAN}• Monitor your organization's exposure over time{Style.RESET_ALL}")
    print(f"    {Fore.CYAN}• Correlate with other OSINT sources{Style.RESET_ALL}")
    print(f"    {Fore.CYAN}• Use vulnerability data for risk assessment{Style.RESET_ALL}")
    print(f"    {Fore.CYAN}• Analyze geographic distribution of assets{Style.RESET_ALL}")
    
    print(f"\n{Fore.GREEN}[+] Useful Shodan Search Queries:{Style.RESET_ALL}")
    print(f"    {Fore.YELLOW}• org:\"Company Name\" - Find assets by organization{Style.RESET_ALL}")
    print(f"    {Fore.YELLOW}• net:192.168.1.0/24 - Search specific IP ranges{Style.RESET_ALL}")
    print(f"    {Fore.YELLOW}• hostname:example.com - Search by hostname{Style.RESET_ALL}")
    print(f"    {Fore.YELLOW}• port:22 country:US - SSH servers in US{Style.RESET_ALL}")
    print(f"    {Fore.YELLOW}• product:apache version:2.4 - Specific software versions{Style.RESET_ALL}")
    print(f"    {Fore.YELLOW}• vuln:CVE-2021-44228 - Hosts with specific vulnerabilities{Style.RESET_ALL}")

# Export functions for use in main tool
__all__ = ['ShodanLookup', 'search_shodan_host', 'search_shodan_query', 'set_shodan_api_key', 'provide_shodan_recommendations']
