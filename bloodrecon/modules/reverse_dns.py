#!/usr/bin/env python3
"""
Reverse DNS Lookup Module
Perform reverse DNS resolution for IP addresses
Author : Alex Butler (@MrHacker-X)
Org    : Vritra Security Organization
"""

import socket
import re
import requests
from bloodrecon.modules.colors import Fore, Style

def reverse_lookup(ip_address):
    """Perform reverse DNS lookup on IP address"""
    try:
        print(f"\n{Fore.CYAN}╔══════════════════════════════════════════════════════════════╗")
        print(f"║                    {Fore.YELLOW}REVERSE DNS LOOKUP{Fore.CYAN}                        ║")
        print(f"╚══════════════════════════════════════════════════════════════╝{Style.RESET_ALL}")
        
        # Validate IP address format
        if not is_valid_ip(ip_address):
            print(f"{Fore.RED}[ERROR] Invalid IP address format: {ip_address}{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}[INFO] Please provide a valid IPv4 or IPv6 address{Style.RESET_ALL}")
            return
        
        print(f"\n{Fore.GREEN}[+] Reverse DNS Information:{Style.RESET_ALL}")
        print(f"    IP Address: {Fore.YELLOW}{ip_address}{Style.RESET_ALL}")
        print(f"    IP Type: {Fore.CYAN}{get_ip_type(ip_address)}{Style.RESET_ALL}")
        
        # Try standard reverse DNS lookup
        hostname_found = False
        try:
            print(f"\n{Fore.GREEN}[+] Standard Reverse DNS Query:{Style.RESET_ALL}")
            hostname = socket.gethostbyaddr(ip_address)
            hostname_found = True
            
            print(f"    Primary Hostname: {Fore.GREEN}{hostname[0]}{Style.RESET_ALL}")
            
            # Show all aliases if any
            if hostname[1]:
                print(f"    Aliases: {Fore.CYAN}{', '.join(hostname[1])}{Style.RESET_ALL}")
            else:
                print(f"    Aliases: {Fore.YELLOW}None{Style.RESET_ALL}")
            
            # Show all addresses
            print(f"    All Addresses: {Fore.CYAN}{', '.join(hostname[2])}{Style.RESET_ALL}")
            
            # Try to resolve hostname back to IP (forward lookup verification)
            print(f"\n{Fore.GREEN}[+] Forward Lookup Verification:{Style.RESET_ALL}")
            try:
                forward_lookup = socket.gethostbyname(hostname[0])
                if forward_lookup == ip_address:
                    print(f"    Forward Resolution: {Fore.GREEN}✓ Matches original IP{Style.RESET_ALL}")
                    print(f"    Consistency: {Fore.GREEN}✓ DNS records are consistent{Style.RESET_ALL}")
                else:
                    print(f"    Forward Resolution: {Fore.YELLOW}{forward_lookup}{Style.RESET_ALL}")
                    print(f"    Consistency: {Fore.YELLOW}⚠ Different IP returned (load balancing/CDN?){Style.RESET_ALL}")
            except Exception as e:
                print(f"    Forward Resolution: {Fore.RED}✗ Failed ({str(e)}){Style.RESET_ALL}")
                print(f"    Consistency: {Fore.RED}✗ Cannot verify DNS consistency{Style.RESET_ALL}")
                
        except socket.herror as e:
            print(f"    Result: {Fore.RED}✗ No hostname found (NXDOMAIN){Style.RESET_ALL}")
            print(f"    Details: {Fore.YELLOW}No PTR record exists for this IP{Style.RESET_ALL}")
        except socket.gaierror as e:
            print(f"    Result: {Fore.RED}✗ Address resolution failed{Style.RESET_ALL}")
            print(f"    Error: {Fore.YELLOW}{str(e)}{Style.RESET_ALL}")
        except Exception as e:
            print(f"    Result: {Fore.RED}✗ Lookup failed{Style.RESET_ALL}")
            print(f"    Error: {Fore.YELLOW}{str(e)}{Style.RESET_ALL}")
        
        # If standard lookup failed, try alternative methods
        if not hostname_found:
            print(f"\n{Fore.YELLOW}[!] Standard reverse DNS failed. Trying alternative methods...{Style.RESET_ALL}")
            
            # Try online reverse DNS services
            try_online_reverse_dns(ip_address)
            
            # Provide fallback information
            print(f"\n{Fore.GREEN}[+] Fallback Information:{Style.RESET_ALL}")
            
            # Check if it's a private IP
            if is_private_ip(ip_address):
                print(f"    IP Type: {Fore.CYAN}Private/Internal IP Address{Style.RESET_ALL}")
                print(f"    Reason: {Fore.YELLOW}Private IPs typically don't have public PTR records{Style.RESET_ALL}")
                print(f"    Suggestion: {Fore.CYAN}Check your local DNS server or router configuration{Style.RESET_ALL}")
            else:
                print(f"    IP Type: {Fore.CYAN}Public IP Address{Style.RESET_ALL}")
                print(f"    Reason: {Fore.YELLOW}The IP owner hasn't configured a PTR record{Style.RESET_ALL}")
                print(f"    Suggestion: {Fore.CYAN}Some organizations don't set up reverse DNS for security reasons{Style.RESET_ALL}")
        
        # Additional information and suggestions
        print(f"\n{Fore.GREEN}[+] Additional Tools & Resources:{Style.RESET_ALL}")
        print(f"    Online Tools:{Style.RESET_ALL}")
        print(f"      • MXToolbox: {Fore.MAGENTA}https://mxtoolbox.com/SuperTool.aspx?action=ptr&run=toolpage&ip={ip_address}{Style.RESET_ALL}")
        print(f"      • DNSChecker: {Fore.MAGENTA}https://dnschecker.org/reverse-dns.php?ip={ip_address}{Style.RESET_ALL}")
        print(f"      • WhatsMyDNS: {Fore.MAGENTA}https://whatsmydns.net/#{ip_address}/PTR{Style.RESET_ALL}")
        
        print(f"\n    Command Line Tools:{Style.RESET_ALL}")
        print(f"      • nslookup: {Fore.CYAN}nslookup {ip_address}{Style.RESET_ALL}")
        print(f"      • dig: {Fore.CYAN}dig -x {ip_address}{Style.RESET_ALL}")
        print(f"      • host: {Fore.CYAN}host {ip_address}{Style.RESET_ALL}")
        
        # IP information context
        print(f"\n{Fore.GREEN}[+] Understanding Reverse DNS:{Style.RESET_ALL}")
        print(f"    {Fore.CYAN}• PTR records map IP addresses to hostnames{Style.RESET_ALL}")
        print(f"    {Fore.CYAN}• Not all IP addresses have reverse DNS configured{Style.RESET_ALL}")
        print(f"    {Fore.CYAN}• Reverse DNS is often used for email server verification{Style.RESET_ALL}")
        print(f"    {Fore.CYAN}• Some organizations intentionally omit reverse DNS for security{Style.RESET_ALL}")
        
    except Exception as e:
        print(f"{Fore.RED}[ERROR] Unexpected error in reverse DNS lookup: {str(e)}{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}[INFO] This might be due to network connectivity or DNS server issues{Style.RESET_ALL}")

def is_valid_ip(ip):
    """Validate IP address format"""
    try:
        # Try IPv4
        socket.inet_aton(ip)
        return True
    except socket.error:
        try:
            # Try IPv6
            socket.inet_pton(socket.AF_INET6, ip)
            return True
        except socket.error:
            return False

def get_ip_type(ip):
    """Determine IP address type"""
    try:
        # Check if IPv4
        socket.inet_aton(ip)
        return "IPv4"
    except socket.error:
        try:
            # Check if IPv6
            socket.inet_pton(socket.AF_INET6, ip)
            return "IPv6"
        except socket.error:
            return "Unknown"

def is_private_ip(ip):
    """Check if IP address is private/internal"""
    try:
        # IPv4 private ranges
        if '.' in ip:
            parts = ip.split('.')
            if len(parts) == 4:
                first = int(parts[0])
                second = int(parts[1])
                
                # 10.0.0.0/8
                if first == 10:
                    return True
                # 172.16.0.0/12
                elif first == 172 and 16 <= second <= 31:
                    return True
                # 192.168.0.0/16
                elif first == 192 and second == 168:
                    return True
                # 127.0.0.0/8 (loopback)
                elif first == 127:
                    return True
        
        # IPv6 private ranges (simplified check)
        elif ':' in ip:
            if ip.startswith('::1') or ip.startswith('fc') or ip.startswith('fd'):
                return True
    
        return False
    except:
        return False

def try_online_reverse_dns(ip_address):
    """Try online reverse DNS services as fallback"""
    try:
        print(f"\n{Fore.GREEN}[+] Trying Online Reverse DNS Services:{Style.RESET_ALL}")
        
        # Try a simple API-based reverse DNS lookup
        try:
            # Using a free IP geolocation API that sometimes includes hostname
            url = f"http://ip-api.com/json/{ip_address}?fields=query,org,isp,reverse"
            response = requests.get(url, timeout=5)
            
            if response.status_code == 200:
                data = response.json()
                if data.get('reverse'):
                    print(f"    Online Service Result: {Fore.GREEN}{data['reverse']}{Style.RESET_ALL}")
                    print(f"    Organization: {Fore.CYAN}{data.get('org', 'Unknown')}{Style.RESET_ALL}")
                    print(f"    ISP: {Fore.CYAN}{data.get('isp', 'Unknown')}{Style.RESET_ALL}")
                    return True
                else:
                    print(f"    Online Service: {Fore.YELLOW}No reverse DNS found{Style.RESET_ALL}")
            else:
                print(f"    Online Service: {Fore.RED}Service unavailable{Style.RESET_ALL}")
        except Exception as e:
            print(f"    Online Service: {Fore.RED}Failed to connect ({str(e)}){Style.RESET_ALL}")
        
        return False
    except:
        return False
