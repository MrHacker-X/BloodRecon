#!/usr/bin/env python3
"""
IP to ISP Tracker Module
Track IP addresses to their ISP, geolocation, and network information
Author : Alex Butler (@MrHacker-X)
Org    : Vritra Security Organization
"""

import requests
import json
import socket
from bloodrecon.modules.colors import Fore, Style
from urllib.parse import urlparse
import subprocess
import re

def track_ip_to_isp(target):
    """Main function to track IP to ISP and gather network information"""
    try:
        print(f"\n{Fore.CYAN}╔══════════════════════════════════════════════════════════════╗")
        print(f"║                      {Fore.YELLOW}IP TO ISP TRACKER{Fore.CYAN}                       ║")
        print(f"╚══════════════════════════════════════════════════════════════╝{Style.RESET_ALL}")
        
        # Extract IP from URL if provided
        if target.startswith(('http://', 'https://')):
            parsed = urlparse(target)
            target = parsed.hostname
        
        # Resolve hostname to IP if needed
        try:
            ip_address = socket.gethostbyname(target)
            if target != ip_address:
                print(f"\n{Fore.GREEN}[+] Resolved {target} to {ip_address}{Style.RESET_ALL}")
            target = ip_address
        except socket.gaierror:
            # Target might already be an IP
            pass
        
        print(f"\n{Fore.GREEN}[+] Tracking IP: {Fore.YELLOW}{target}{Style.RESET_ALL}")
        
        # Get information from multiple sources
        get_ipinfo_data(target)
        get_ipapi_data(target)
        get_whois_data(target)
        get_maxmind_data(target)
        
        # Additional analysis
        perform_network_analysis(target)
        provide_isp_recommendations()
        
    except Exception as e:
        print(f"{Fore.RED}[ERROR] IP tracking failed: {str(e)}{Style.RESET_ALL}")

def get_ipinfo_data(ip_address):
    """Get IP information from ipinfo.io"""
    try:
        print(f"\n{Fore.GREEN}[+] Querying ipinfo.io:{Style.RESET_ALL}")
        
        url = f"http://ipinfo.io/{ip_address}/json"
        response = requests.get(url, timeout=10)
        
        if response.status_code == 200:
            data = response.json()
            
            print(f"    {Fore.CYAN}IP: {data.get('ip', 'Unknown')}{Style.RESET_ALL}")
            print(f"    {Fore.CYAN}Hostname: {data.get('hostname', 'No reverse DNS')}{Style.RESET_ALL}")
            print(f"    {Fore.CYAN}City: {data.get('city', 'Unknown')}{Style.RESET_ALL}")
            print(f"    {Fore.CYAN}Region: {data.get('region', 'Unknown')}{Style.RESET_ALL}")
            print(f"    {Fore.CYAN}Country: {data.get('country', 'Unknown')}{Style.RESET_ALL}")
            print(f"    {Fore.CYAN}Location: {data.get('loc', 'Unknown')}{Style.RESET_ALL}")
            print(f"    {Fore.CYAN}Organization: {data.get('org', 'Unknown')}{Style.RESET_ALL}")
            print(f"    {Fore.CYAN}Postal Code: {data.get('postal', 'Unknown')}{Style.RESET_ALL}")
            print(f"    {Fore.CYAN}Timezone: {data.get('timezone', 'Unknown')}{Style.RESET_ALL}")
            
            # Parse organization for ASN and ISP
            org = data.get('org', '')
            if org:
                asn_match = re.match(r'AS(\d+)\s+(.+)', org)
                if asn_match:
                    asn_number = asn_match.group(1)
                    isp_name = asn_match.group(2)
                    print(f"    {Fore.YELLOW}ASN: AS{asn_number}{Style.RESET_ALL}")
                    print(f"    {Fore.YELLOW}ISP: {isp_name}{Style.RESET_ALL}")
        
        else:
            print(f"    {Fore.RED}✗ ipinfo.io request failed (Status: {response.status_code}){Style.RESET_ALL}")
            
    except requests.exceptions.RequestException as e:
        print(f"    {Fore.RED}✗ Network error accessing ipinfo.io: {str(e)}{Style.RESET_ALL}")
    except Exception as e:
        print(f"    {Fore.RED}✗ Error processing ipinfo.io data: {str(e)}{Style.RESET_ALL}")

def get_ipapi_data(ip_address):
    """Get IP information from ip-api.com"""
    try:
        print(f"\n{Fore.GREEN}[+] Querying ip-api.com:{Style.RESET_ALL}")
        
        url = f"http://ip-api.com/json/{ip_address}"
        response = requests.get(url, timeout=10)
        
        if response.status_code == 200:
            data = response.json()
            
            if data.get('status') == 'success':
                print(f"    {Fore.CYAN}Query: {data.get('query', 'Unknown')}{Style.RESET_ALL}")
                print(f"    {Fore.CYAN}Country: {data.get('country', 'Unknown')} ({data.get('countryCode', 'XX')}){Style.RESET_ALL}")
                print(f"    {Fore.CYAN}Region: {data.get('regionName', 'Unknown')} ({data.get('region', 'XX')}){Style.RESET_ALL}")
                print(f"    {Fore.CYAN}City: {data.get('city', 'Unknown')}{Style.RESET_ALL}")
                print(f"    {Fore.CYAN}ZIP Code: {data.get('zip', 'Unknown')}{Style.RESET_ALL}")
                print(f"    {Fore.CYAN}Latitude: {data.get('lat', 'Unknown')}{Style.RESET_ALL}")
                print(f"    {Fore.CYAN}Longitude: {data.get('lon', 'Unknown')}{Style.RESET_ALL}")
                print(f"    {Fore.CYAN}Timezone: {data.get('timezone', 'Unknown')}{Style.RESET_ALL}")
                print(f"    {Fore.CYAN}ISP: {data.get('isp', 'Unknown')}{Style.RESET_ALL}")
                print(f"    {Fore.CYAN}Organization: {data.get('org', 'Unknown')}{Style.RESET_ALL}")
                print(f"    {Fore.CYAN}AS: {data.get('as', 'Unknown')}{Style.RESET_ALL}")
                
                # Check if it's a mobile connection
                if data.get('mobile'):
                    print(f"    {Fore.YELLOW}Connection Type: Mobile{Style.RESET_ALL}")
                
                # Check if it's a proxy/VPN
                if data.get('proxy'):
                    print(f"    {Fore.RED}⚠ Proxy/VPN detected{Style.RESET_ALL}")
                
                # Check if it's hosting/datacenter
                if data.get('hosting'):
                    print(f"    {Fore.YELLOW}⚠ Hosting/Datacenter IP{Style.RESET_ALL}")
            
            else:
                print(f"    {Fore.RED}✗ Query failed: {data.get('message', 'Unknown error')}{Style.RESET_ALL}")
        
        else:
            print(f"    {Fore.RED}✗ ip-api.com request failed (Status: {response.status_code}){Style.RESET_ALL}")
            
    except requests.exceptions.RequestException as e:
        print(f"    {Fore.RED}✗ Network error accessing ip-api.com: {str(e)}{Style.RESET_ALL}")
    except Exception as e:
        print(f"    {Fore.RED}✗ Error processing ip-api.com data: {str(e)}{Style.RESET_ALL}")

def get_whois_data(ip_address):
    """Get WHOIS information for IP address"""
    try:
        print(f"\n{Fore.GREEN}[+] Performing WHOIS lookup:{Style.RESET_ALL}")
        
        # Use subprocess to call whois command
        try:
            result = subprocess.run(
                ['whois', ip_address],
                capture_output=True,
                text=True,
                timeout=15
            )
            
            if result.returncode == 0 and result.stdout:
                whois_data = result.stdout
                parse_whois_ip_data(whois_data)
            else:
                print(f"    {Fore.YELLOW}No WHOIS data available{Style.RESET_ALL}")
                
        except subprocess.TimeoutExpired:
            print(f"    {Fore.RED}WHOIS lookup timeout{Style.RESET_ALL}")
        except FileNotFoundError:
            print(f"    {Fore.RED}whois command not found{Style.RESET_ALL}")
            
    except Exception as e:
        print(f"    {Fore.RED}✗ WHOIS lookup failed: {str(e)}{Style.RESET_ALL}")

def parse_whois_ip_data(whois_data):
    """Parse WHOIS data and extract relevant IP information"""
    try:
        lines = whois_data.split('\n')
        
        relevant_fields = {
            'netname': 'Network Name',
            'descr': 'Description',
            'country': 'Country',
            'org': 'Organization',
            'orgname': 'Organization Name',
            'inetnum': 'IP Range',
            'cidr': 'CIDR',
            'netrange': 'Network Range',
            'nettype': 'Network Type',
            'regdate': 'Registration Date',
            'updated': 'Last Updated',
            'ref': 'Reference',
            'originas': 'Origin AS',
            'asname': 'AS Name',
            'ashandle': 'AS Handle'
        }
        
        print(f"    {Fore.GREEN}✓ WHOIS data received:{Style.RESET_ALL}")
        
        found_info = False
        for line in lines:
            line = line.strip()
            if not line or line.startswith('%') or line.startswith('#'):
                continue
                
            for field, display_name in relevant_fields.items():
                if ':' in line:
                    field_name, field_value = line.split(':', 1)
                    field_name = field_name.strip().lower()
                    field_value = field_value.strip()
                    
                    if field_name == field.lower() and field_value:
                        print(f"      {Fore.CYAN}{display_name}: {field_value}{Style.RESET_ALL}")
                        found_info = True
                        break
        
        if not found_info:
            print(f"      {Fore.YELLOW}No relevant information found{Style.RESET_ALL}")
            
    except Exception as e:
        print(f"    {Fore.RED}Error parsing WHOIS data: {str(e)}{Style.RESET_ALL}")

def get_maxmind_data(ip_address):
    """Get MaxMind GeoLite2 data (if available)"""
    try:
        print(f"\n{Fore.GREEN}[+] Attempting MaxMind GeoIP lookup:{Style.RESET_ALL}")
        
        # Try to use geoiplookup command if available
        try:
            result = subprocess.run(
                ['geoiplookup', ip_address],
                capture_output=True,
                text=True,
                timeout=10
            )
            
            if result.returncode == 0 and result.stdout:
                lines = result.stdout.strip().split('\n')
                for line in lines:
                    if line.strip():
                        print(f"    {Fore.CYAN}{line.strip()}{Style.RESET_ALL}")
            else:
                print(f"    {Fore.YELLOW}No MaxMind data available{Style.RESET_ALL}")
                
        except FileNotFoundError:
            print(f"    {Fore.YELLOW}geoiplookup tool not installed{Style.RESET_ALL}")
        except subprocess.TimeoutExpired:
            print(f"    {Fore.RED}MaxMind lookup timeout{Style.RESET_ALL}")
            
    except Exception as e:
        print(f"    {Fore.RED}✗ MaxMind lookup failed: {str(e)}{Style.RESET_ALL}")

def perform_network_analysis(ip_address):
    """Perform additional network analysis"""
    try:
        print(f"\n{Fore.GREEN}[+] Network Analysis:{Style.RESET_ALL}")
        
        # Check if IP is private
        import ipaddress
        ip_obj = ipaddress.ip_address(ip_address)
        
        if ip_obj.is_private:
            print(f"    {Fore.YELLOW}⚠ Private IP address{Style.RESET_ALL}")
        elif ip_obj.is_loopback:
            print(f"    {Fore.YELLOW}⚠ Loopback address{Style.RESET_ALL}")
        elif ip_obj.is_multicast:
            print(f"    {Fore.YELLOW}⚠ Multicast address{Style.RESET_ALL}")
        elif ip_obj.is_reserved:
            print(f"    {Fore.YELLOW}⚠ Reserved address{Style.RESET_ALL}")
        else:
            print(f"    {Fore.GREEN}✓ Public IP address{Style.RESET_ALL}")
        
        # Determine IP version
        if ip_obj.version == 4:
            print(f"    {Fore.CYAN}IP Version: IPv4{Style.RESET_ALL}")
            analyze_ipv4_class(ip_address)
        else:
            print(f"    {Fore.CYAN}IP Version: IPv6{Style.RESET_ALL}")
        
        # Try traceroute for network path analysis
        perform_traceroute(ip_address)
        
    except Exception as e:
        print(f"    {Fore.RED}✗ Network analysis failed: {str(e)}{Style.RESET_ALL}")

def analyze_ipv4_class(ip_address):
    """Analyze IPv4 address class"""
    try:
        first_octet = int(ip_address.split('.')[0])
        
        if 1 <= first_octet <= 126:
            ip_class = "A"
            default_subnet = "/8"
        elif 128 <= first_octet <= 191:
            ip_class = "B"
            default_subnet = "/16"
        elif 192 <= first_octet <= 223:
            ip_class = "C"
            default_subnet = "/24"
        elif 224 <= first_octet <= 239:
            ip_class = "D (Multicast)"
            default_subnet = "N/A"
        elif 240 <= first_octet <= 255:
            ip_class = "E (Reserved)"
            default_subnet = "N/A"
        else:
            ip_class = "Unknown"
            default_subnet = "N/A"
        
        print(f"    {Fore.CYAN}IPv4 Class: {ip_class}{Style.RESET_ALL}")
        if default_subnet != "N/A":
            print(f"    {Fore.CYAN}Default Subnet: {default_subnet}{Style.RESET_ALL}")
            
    except Exception as e:
        print(f"    {Fore.RED}Error analyzing IPv4 class: {str(e)}{Style.RESET_ALL}")

def perform_traceroute(ip_address):
    """Perform traceroute to analyze network path"""
    try:
        print(f"\n{Fore.GREEN}[+] Traceroute Analysis (first 5 hops):{Style.RESET_ALL}")
        
        # Use traceroute command
        try:
            result = subprocess.run(
                ['traceroute', '-m', '5', ip_address],
                capture_output=True,
                text=True,
                timeout=30
            )
            
            if result.returncode == 0 and result.stdout:
                lines = result.stdout.strip().split('\n')[1:]  # Skip header
                for i, line in enumerate(lines[:5], 1):  # Show first 5 hops
                    if line.strip():
                        print(f"    {Fore.YELLOW}[{i}] {line.strip()}{Style.RESET_ALL}")
            else:
                print(f"    {Fore.YELLOW}Traceroute not available{Style.RESET_ALL}")
                
        except FileNotFoundError:
            print(f"    {Fore.YELLOW}traceroute command not found{Style.RESET_ALL}")
        except subprocess.TimeoutExpired:
            print(f"    {Fore.RED}Traceroute timeout{Style.RESET_ALL}")
            
    except Exception as e:
        print(f"    {Fore.RED}✗ Traceroute failed: {str(e)}{Style.RESET_ALL}")

def get_abuse_contacts(ip_address):
    """Get abuse contact information for IP"""
    try:
        print(f"\n{Fore.GREEN}[+] Abuse Contact Information:{Style.RESET_ALL}")
        
        # Try whois lookup for abuse contacts
        try:
            result = subprocess.run(
                ['whois', ip_address],
                capture_output=True,
                text=True,
                timeout=15
            )
            
            if result.returncode == 0 and result.stdout:
                whois_data = result.stdout.lower()
                
                # Look for abuse contacts
                abuse_patterns = [
                    r'abuse[^:]*:\s*([^\s\n]+)',
                    r'abuse-mailbox:\s*([^\s\n]+)',
                    r'orgabuseemail:\s*([^\s\n]+)',
                    r'abuse-c:\s*([^\s\n]+)'
                ]
                
                contacts_found = set()
                for pattern in abuse_patterns:
                    matches = re.findall(pattern, whois_data)
                    for match in matches:
                        if '@' in match or match.startswith('http'):
                            contacts_found.add(match)
                
                if contacts_found:
                    print(f"    {Fore.GREEN}✓ Abuse contacts found:{Style.RESET_ALL}")
                    for contact in sorted(contacts_found):
                        print(f"      {Fore.CYAN}• {contact}{Style.RESET_ALL}")
                else:
                    print(f"    {Fore.YELLOW}No abuse contacts found{Style.RESET_ALL}")
            
        except Exception as e:
            print(f"    {Fore.RED}Error getting abuse contacts: {str(e)}{Style.RESET_ALL}")
            
    except Exception as e:
        print(f"    {Fore.RED}✗ Abuse contact lookup failed: {str(e)}{Style.RESET_ALL}")

def provide_isp_recommendations():
    """Provide recommendations for ISP tracking"""
    print(f"\n{Fore.GREEN}[+] ISP Tracking Recommendations:{Style.RESET_ALL}")
    print(f"    {Fore.CYAN}• Use multiple sources for accurate geolocation{Style.RESET_ALL}")
    print(f"    {Fore.CYAN}• Cross-reference ISP information with ASN data{Style.RESET_ALL}")
    print(f"    {Fore.CYAN}• Check for VPN/proxy indicators{Style.RESET_ALL}")
    print(f"    {Fore.CYAN}• Monitor IP reputation and threat intelligence{Style.RESET_ALL}")
    print(f"    {Fore.CYAN}• Use traceroute for network path analysis{Style.RESET_ALL}")
    print(f"    {Fore.CYAN}• Consider privacy laws when collecting IP data{Style.RESET_ALL}")
    
    print(f"\n{Fore.GREEN}[+] Common ISP Types:{Style.RESET_ALL}")
    print(f"    {Fore.YELLOW}• Residential ISP - Home internet connections{Style.RESET_ALL}")
    print(f"    {Fore.YELLOW}• Business ISP - Corporate internet services{Style.RESET_ALL}")
    print(f"    {Fore.YELLOW}• Mobile ISP - Cellular data providers{Style.RESET_ALL}")
    print(f"    {Fore.YELLOW}• Hosting Provider - Datacenter/cloud services{Style.RESET_ALL}")
    print(f"    {Fore.YELLOW}• VPN/Proxy - Anonymization services{Style.RESET_ALL}")
    print(f"    {Fore.YELLOW}• CDN - Content delivery networks{Style.RESET_ALL}")

# Export functions for use in main tool
__all__ = ['track_ip_to_isp', 'get_abuse_contacts']
