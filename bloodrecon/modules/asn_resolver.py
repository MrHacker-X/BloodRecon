#!/usr/bin/env python3
"""
ASN to IP Range Resolver Module
Resolve ASN numbers to IP ranges and gather organization information
Author : Alex Butler (@MrHacker-X)
Org    : Vritra Security Organization
"""

import requests
import json
import ipaddress
from bloodrecon.modules.colors import Fore, Style
import socket
import subprocess
import re

def resolve_asn_to_ranges(asn_number):
    """Resolve ASN number to IP ranges"""
    try:
        print(f"\n{Fore.CYAN}╔══════════════════════════════════════════════════════════════╗")
        print(f"║                  {Fore.YELLOW}ASN TO IP RANGE RESOLVER{Fore.CYAN}                    ║")
        print(f"╚══════════════════════════════════════════════════════════════╝{Style.RESET_ALL}")
        
        # Remove 'AS' prefix if present  
        if str(asn_number).upper().startswith('AS'):
            asn_number = str(asn_number)[2:]
        
        print(f"\n{Fore.GREEN}[+] Resolving ASN: {Fore.YELLOW}AS{asn_number}{Style.RESET_ALL}")
        
        # Get ASN information from multiple sources
        get_asn_info_from_bgpview(asn_number)
        get_asn_info_from_ripe(asn_number)
        get_asn_info_from_whois(asn_number)
        
        # Additional analysis
        provide_asn_recommendations()
        
    except Exception as e:
        print(f"{Fore.RED}[ERROR] ASN resolution failed: {str(e)}{Style.RESET_ALL}")

def get_asn_info_from_bgpview(asn_number):
    """Get ASN information from BGPView API"""
    try:
        print(f"\n{Fore.GREEN}[+] Querying BGPView API:{Style.RESET_ALL}")
        
        # Get ASN basic info
        url = f"https://api.bgpview.io/asn/{asn_number}"
        response = requests.get(url, timeout=15)
        
        if response.status_code == 200:
            data = response.json()
            asn_data = data.get('data', {})
            
            print(f"    {Fore.CYAN}ASN: AS{asn_data.get('asn', 'Unknown')}{Style.RESET_ALL}")
            print(f"    {Fore.CYAN}Name: {asn_data.get('name', 'Unknown')}{Style.RESET_ALL}")
            print(f"    {Fore.CYAN}Description: {asn_data.get('description_short', 'Unknown')}{Style.RESET_ALL}")
            print(f"    {Fore.CYAN}Country: {asn_data.get('country_code', 'Unknown')}{Style.RESET_ALL}")
            print(f"    {Fore.CYAN}Website: {asn_data.get('website', 'Not available')}{Style.RESET_ALL}")
            
            # Get prefixes
            prefixes_url = f"https://api.bgpview.io/asn/{asn_number}/prefixes"
            prefixes_response = requests.get(prefixes_url, timeout=15)
            
            if prefixes_response.status_code == 200:
                prefixes_data = prefixes_response.json()
                ipv4_prefixes = prefixes_data.get('data', {}).get('ipv4_prefixes', [])
                ipv6_prefixes = prefixes_data.get('data', {}).get('ipv6_prefixes', [])
                
                print(f"\n{Fore.GREEN}[+] IPv4 Prefixes ({len(ipv4_prefixes)} found):{Style.RESET_ALL}")
                for i, prefix in enumerate(ipv4_prefixes[:20], 1):  # Limit to first 20
                    ip_range = prefix.get('prefix')
                    name = prefix.get('name', 'No description')
                    country = prefix.get('country_code', 'Unknown')
                    print(f"    {Fore.YELLOW}[{i:2d}] {ip_range} ({country}) - {name}{Style.RESET_ALL}")
                
                if len(ipv4_prefixes) > 20:
                    print(f"    {Fore.CYAN}... and {len(ipv4_prefixes) - 20} more IPv4 prefixes{Style.RESET_ALL}")
                
                if ipv6_prefixes:
                    print(f"\n{Fore.GREEN}[+] IPv6 Prefixes ({len(ipv6_prefixes)} found):{Style.RESET_ALL}")
                    for i, prefix in enumerate(ipv6_prefixes[:10], 1):  # Limit to first 10
                        ip_range = prefix.get('prefix')
                        name = prefix.get('name', 'No description')
                        country = prefix.get('country_code', 'Unknown')
                        print(f"    {Fore.YELLOW}[{i:2d}] {ip_range} ({country}) - {name}{Style.RESET_ALL}")
                
                # Analyze IP ranges
                analyze_ip_ranges(ipv4_prefixes, ipv6_prefixes)
                
        else:
            print(f"    {Fore.RED}✗ BGPView API request failed (Status: {response.status_code}){Style.RESET_ALL}")
            
    except requests.exceptions.RequestException as e:
        print(f"    {Fore.RED}✗ Network error accessing BGPView: {str(e)}{Style.RESET_ALL}")
    except Exception as e:
        print(f"    {Fore.RED}✗ Error processing BGPView data: {str(e)}{Style.RESET_ALL}")

def get_asn_info_from_ripe(asn_number):
    """Get ASN information from RIPE NCC"""
    try:
        print(f"\n{Fore.GREEN}[+] Querying RIPE NCC API:{Style.RESET_ALL}")
        
        url = f"https://stat.ripe.net/data/as-overview/data.json?resource=AS{asn_number}"
        response = requests.get(url, timeout=15)
        
        if response.status_code == 200:
            data = response.json()
            asn_data = data.get('data', {})
            
            print(f"    {Fore.CYAN}ASN: AS{asn_data.get('asn', 'Unknown')}{Style.RESET_ALL}")
            print(f"    {Fore.CYAN}Holder: {asn_data.get('holder', 'Unknown')}{Style.RESET_ALL}")
            print(f"    {Fore.CYAN}Type: {asn_data.get('type', 'Unknown')}{Style.RESET_ALL}")
            
            # Get announced prefixes
            announced = asn_data.get('announced', False)
            if announced:
                print(f"    {Fore.GREEN}Status: Currently announcing prefixes{Style.RESET_ALL}")
            else:
                print(f"    {Fore.YELLOW}Status: Not currently announcing prefixes{Style.RESET_ALL}")
            
            # Get block information
            block = asn_data.get('block', {})
            if block:
                print(f"    {Fore.CYAN}Block Range: AS{block.get('resource', 'Unknown')}{Style.RESET_ALL}")
                print(f"    {Fore.CYAN}Block Name: {block.get('name', 'Unknown')}{Style.RESET_ALL}")
                print(f"    {Fore.CYAN}Block Description: {block.get('desc', 'Unknown')}{Style.RESET_ALL}")
        
        else:
            print(f"    {Fore.RED}✗ RIPE NCC API request failed (Status: {response.status_code}){Style.RESET_ALL}")
            
    except requests.exceptions.RequestException as e:
        print(f"    {Fore.RED}✗ Network error accessing RIPE NCC: {str(e)}{Style.RESET_ALL}")
    except Exception as e:
        print(f"    {Fore.RED}✗ Error processing RIPE NCC data: {str(e)}{Style.RESET_ALL}")

def get_asn_info_from_whois(asn_number):
    """Get ASN information using whois"""
    try:
        print(f"\n{Fore.GREEN}[+] Performing WHOIS lookup:{Style.RESET_ALL}")
        
        # Try different whois servers
        whois_servers = [
            'whois.radb.net',
            'whois.ripe.net',
            'whois.arin.net'
        ]
        
        for server in whois_servers:
            try:
                print(f"    {Fore.CYAN}→ Querying {server}:{Style.RESET_ALL}")
                
                # Use subprocess to call whois command
                result = subprocess.run(
                    ['whois', '-h', server, f'AS{asn_number}'],
                    capture_output=True,
                    text=True,
                    timeout=10
                )
                
                if result.returncode == 0 and result.stdout:
                    whois_data = result.stdout
                    parse_whois_data(whois_data, server)
                    break
                else:
                    print(f"      {Fore.YELLOW}No data from {server}{Style.RESET_ALL}")
                    
            except subprocess.TimeoutExpired:
                print(f"      {Fore.RED}Timeout querying {server}{Style.RESET_ALL}")
                continue
            except FileNotFoundError:
                print(f"      {Fore.RED}whois command not found{Style.RESET_ALL}")
                break
            except Exception as e:
                print(f"      {Fore.RED}Error querying {server}: {str(e)}{Style.RESET_ALL}")
                continue
                
    except Exception as e:
        print(f"    {Fore.RED}✗ WHOIS lookup failed: {str(e)}{Style.RESET_ALL}")

def parse_whois_data(whois_data, server):
    """Parse WHOIS data and extract relevant information"""
    try:
        lines = whois_data.split('\n')
        
        relevant_fields = {
            'as-name': 'AS Name',
            'descr': 'Description',
            'country': 'Country',
            'org': 'Organization',
            'admin-c': 'Admin Contact',
            'tech-c': 'Tech Contact',
            'mnt-by': 'Maintained By',
            'changed': 'Last Changed',
            'source': 'Source',
            'route': 'Route',
            'origin': 'Origin AS'
        }
        
        print(f"      {Fore.GREEN}✓ Data received from {server}:{Style.RESET_ALL}")
        
        found_info = False
        for line in lines:
            line = line.strip()
            if not line or line.startswith('%') or line.startswith('#'):
                continue
                
            for field, display_name in relevant_fields.items():
                if line.lower().startswith(field.lower() + ':'):
                    value = line.split(':', 1)[1].strip()
                    if value:
                        print(f"        {Fore.CYAN}{display_name}: {value}{Style.RESET_ALL}")
                        found_info = True
                        break
        
        if not found_info:
            print(f"        {Fore.YELLOW}No relevant information found{Style.RESET_ALL}")
            
    except Exception as e:
        print(f"      {Fore.RED}Error parsing WHOIS data: {str(e)}{Style.RESET_ALL}")

def analyze_ip_ranges(ipv4_prefixes, ipv6_prefixes):
    """Analyze IP ranges and provide statistics"""
    try:
        print(f"\n{Fore.GREEN}[+] IP Range Analysis:{Style.RESET_ALL}")
        
        if ipv4_prefixes:
            total_ipv4_addresses = 0
            countries = set()
            
            for prefix in ipv4_prefixes:
                try:
                    network = ipaddress.IPv4Network(prefix.get('prefix'))
                    total_ipv4_addresses += network.num_addresses
                    if prefix.get('country_code'):
                        countries.add(prefix.get('country_code'))
                except:
                    continue
            
            print(f"    {Fore.CYAN}Total IPv4 addresses: {total_ipv4_addresses:,}{Style.RESET_ALL}")
            print(f"    {Fore.CYAN}Countries involved: {', '.join(sorted(countries))}{Style.RESET_ALL}")
            
            # Find largest subnets
            largest_subnets = sorted(ipv4_prefixes, 
                                   key=lambda x: ipaddress.IPv4Network(x.get('prefix', '0.0.0.0/32')).num_addresses, 
                                   reverse=True)[:5]
            
            print(f"    {Fore.CYAN}Largest subnets:{Style.RESET_ALL}")
            for i, subnet in enumerate(largest_subnets, 1):
                try:
                    network = ipaddress.IPv4Network(subnet.get('prefix'))
                    print(f"      {Fore.YELLOW}[{i}] {subnet.get('prefix')} ({network.num_addresses:,} addresses){Style.RESET_ALL}")
                except:
                    continue
        
        if ipv6_prefixes:
            print(f"    {Fore.CYAN}IPv6 prefixes: {len(ipv6_prefixes)} blocks{Style.RESET_ALL}")
            
    except Exception as e:
        print(f"    {Fore.RED}✗ Error analyzing IP ranges: {str(e)}{Style.RESET_ALL}")

def resolve_ip_to_asn(ip_address):
    """Resolve IP address to ASN"""
    try:
        print(f"\n{Fore.GREEN}[+] Resolving IP to ASN: {Fore.YELLOW}{ip_address}{Style.RESET_ALL}")
        
        # Use BGPView API
        url = f"https://api.bgpview.io/ip/{ip_address}"
        response = requests.get(url, timeout=15)
        
        if response.status_code == 200:
            data = response.json()
            ip_data = data.get('data', {})
            
            # Get RIR allocation
            rir_allocation = ip_data.get('rir_allocation', {})
            if rir_allocation:
                print(f"    {Fore.CYAN}RIR: {rir_allocation.get('rir_name', 'Unknown')}{Style.RESET_ALL}")
                print(f"    {Fore.CYAN}Country: {rir_allocation.get('country_code', 'Unknown')}{Style.RESET_ALL}")
                print(f"    {Fore.CYAN}Date Allocated: {rir_allocation.get('date_allocated', 'Unknown')}{Style.RESET_ALL}")
            
            # Get prefixes
            prefixes = ip_data.get('prefixes', [])
            if prefixes:
                print(f"    {Fore.GREEN}Found in {len(prefixes)} prefix(es):{Style.RESET_ALL}")
                for prefix in prefixes[:5]:  # Show first 5
                    asn = prefix.get('asn', {})
                    print(f"      {Fore.YELLOW}• {prefix.get('prefix')} (AS{asn.get('asn')}) - {asn.get('name', 'Unknown')}{Style.RESET_ALL}")
        
        else:
            print(f"    {Fore.RED}✗ Failed to resolve IP to ASN (Status: {response.status_code}){Style.RESET_ALL}")
            
    except Exception as e:
        print(f"    {Fore.RED}✗ Error resolving IP to ASN: {str(e)}{Style.RESET_ALL}")

def provide_asn_recommendations():
    """Provide recommendations for ASN analysis"""
    print(f"\n{Fore.GREEN}[+] Recommendations:{Style.RESET_ALL}")
    print(f"    {Fore.CYAN}• Use ASN information for network reconnaissance{Style.RESET_ALL}")
    print(f"    {Fore.CYAN}• Monitor ASN changes for infrastructure tracking{Style.RESET_ALL}")
    print(f"    {Fore.CYAN}• Cross-reference with BGP routing information{Style.RESET_ALL}")
    print(f"    {Fore.CYAN}• Check for related ASNs owned by same organization{Style.RESET_ALL}")
    print(f"    {Fore.CYAN}• Use IP ranges for comprehensive security scanning{Style.RESET_ALL}")
    print(f"    {Fore.CYAN}• Analyze geographical distribution of IP blocks{Style.RESET_ALL}")

# Export functions for use in main tool
__all__ = ['resolve_asn_to_ranges', 'resolve_ip_to_asn']
