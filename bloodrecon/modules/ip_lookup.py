#!/usr/bin/env python3
"""
IP Address Intelligence Module
Provides comprehensive IP analysis including geolocation, ISP, ASN, and security info
Author : Alex Butler (@MrHacker-X)
Org    : Vritra Security Organization
"""

import requests
import socket
import json
from bloodrecon.modules.colors import Fore, Style
import ipaddress

def analyze_ip(ip_address):
    """Analyze IP address for comprehensive intelligence"""
    try:
        # Validate IP address
        try:
            ipaddress.ip_address(ip_address)
        except ValueError:
            print(f"{Fore.RED}[ERROR] Invalid IP address format: {ip_address}{Style.RESET_ALL}")
            return
        
        print(f"\n{Fore.CYAN}╔══════════════════════════════════════════════════════════════╗")
        print(f"║                   {Fore.YELLOW}IP INTELLIGENCE ANALYSIS{Fore.CYAN}                   ║")
        print(f"╚══════════════════════════════════════════════════════════════╝{Style.RESET_ALL}")
        
        # Primary IP geolocation service
        try:
            response = requests.get(f'http://ip-api.com/json/{ip_address}', timeout=10).json()
            
            if response['status'] == 'success':
                print(f"\n{Fore.GREEN}[+] Basic Information:{Style.RESET_ALL}")
                print(f"    IP Address: {Fore.YELLOW}{response.get('query', 'N/A')}{Style.RESET_ALL}")
                print(f"    Country: {Fore.CYAN}{response.get('country', 'N/A')} ({response.get('countryCode', 'N/A')}){Style.RESET_ALL}")
                print(f"    Region: {Fore.CYAN}{response.get('regionName', 'N/A')} ({response.get('region', 'N/A')}){Style.RESET_ALL}")
                print(f"    City: {Fore.CYAN}{response.get('city', 'N/A')}{Style.RESET_ALL}")
                print(f"    ZIP Code: {Fore.CYAN}{response.get('zip', 'N/A')}{Style.RESET_ALL}")
                print(f"    Timezone: {Fore.CYAN}{response.get('timezone', 'N/A')}{Style.RESET_ALL}")
                print(f"    Coordinates: {Fore.CYAN}{response.get('lat', 'N/A')}, {response.get('lon', 'N/A')}{Style.RESET_ALL}")
                
                print(f"\n{Fore.GREEN}[+] Network Information:{Style.RESET_ALL}")
                print(f"    ISP: {Fore.YELLOW}{response.get('isp', 'N/A')}{Style.RESET_ALL}")
                print(f"    Organization: {Fore.YELLOW}{response.get('org', 'N/A')}{Style.RESET_ALL}")
                print(f"    ASN: {Fore.YELLOW}{response.get('as', 'N/A')}{Style.RESET_ALL}")
                
                # Reverse DNS lookup
                try:
                    hostname = socket.gethostbyaddr(ip_address)[0]
                    print(f"    Reverse DNS: {Fore.YELLOW}{hostname}{Style.RESET_ALL}")
                except:
                    print(f"    Reverse DNS: {Fore.RED}Not available{Style.RESET_ALL}")
                
                # Check if it's a mobile connection
                if response.get('mobile', False):
                    print(f"    Connection Type: {Fore.MAGENTA}Mobile{Style.RESET_ALL}")
                else:
                    print(f"    Connection Type: {Fore.CYAN}Fixed/Broadband{Style.RESET_ALL}")
                
                # Check if it's a proxy/VPN
                if response.get('proxy', False):
                    print(f"    Proxy/VPN: {Fore.RED}Detected{Style.RESET_ALL}")
                else:
                    print(f"    Proxy/VPN: {Fore.GREEN}Not detected{Style.RESET_ALL}")
                    
            else:
                print(f"{Fore.RED}[ERROR] Could not retrieve IP information: {response.get('message', 'Unknown error')}{Style.RESET_ALL}")
                
        except requests.RequestException as e:
            print(f"{Fore.RED}[ERROR] Network error: {str(e)}{Style.RESET_ALL}")
        
        # Additional IP reputation check
        check_ip_reputation(ip_address)
        
    except Exception as e:
        print(f"{Fore.RED}[ERROR] Unexpected error in IP analysis: {str(e)}{Style.RESET_ALL}")

def check_ip_reputation(ip_address):
    """Check IP reputation using public databases"""
    try:
        print(f"\n{Fore.GREEN}[+] Security Assessment:{Style.RESET_ALL}")
        
        # Check if IP is in private ranges
        try:
            ip_obj = ipaddress.ip_address(ip_address)
            if ip_obj.is_private:
                print(f"    IP Type: {Fore.YELLOW}Private/Internal{Style.RESET_ALL}")
            elif ip_obj.is_loopback:
                print(f"    IP Type: {Fore.YELLOW}Loopback{Style.RESET_ALL}")
            elif ip_obj.is_multicast:
                print(f"    IP Type: {Fore.YELLOW}Multicast{Style.RESET_ALL}")
            else:
                print(f"    IP Type: {Fore.GREEN}Public{Style.RESET_ALL}")
        except:
            pass
        
        # Basic port check on common ports (concurrent — serial probing took
        # up to 11 s of timeouts on firewalled hosts)
        from concurrent.futures import ThreadPoolExecutor

        common_ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 993, 995]

        def probe(port):
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            try:
                return port if sock.connect_ex((ip_address, port)) == 0 else None
            finally:
                sock.close()

        print(f"    {Fore.CYAN}Scanning common ports...{Style.RESET_ALL}")
        with ThreadPoolExecutor(max_workers=len(common_ports)) as pool:
            open_ports = [p for p in pool.map(probe, common_ports) if p]

        if open_ports:
            print(f"    Open Ports: {Fore.YELLOW}{', '.join(map(str, open_ports))}{Style.RESET_ALL}")
        else:
            print(f"    Open Ports: {Fore.GREEN}None detected (common ports){Style.RESET_ALL}")
            
    except Exception as e:
        print(f"    {Fore.RED}Security check failed: {str(e)}{Style.RESET_ALL}")
