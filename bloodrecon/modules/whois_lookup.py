#!/usr/bin/env python3
"""
WHOIS Domain Lookup Module
Provides comprehensive WHOIS information for domains
Author : Alex Butler (@MrHacker-X)
Org    : Vritra Security Organization
"""

import whois
import requests
from bloodrecon.modules.colors import Fore, Style
from datetime import datetime

def get_whois_info(domain):
    """Get comprehensive WHOIS information for a domain"""
    try:
        print(f"\n{Fore.CYAN}╔══════════════════════════════════════════════════════════════╗")
        print(f"║                     {Fore.YELLOW}WHOIS DOMAIN LOOKUP{Fore.CYAN}                      ║")
        print(f"╚══════════════════════════════════════════════════════════════╝{Style.RESET_ALL}")
        
        # Clean domain input
        domain = domain.lower().strip()
        if domain.startswith('http://') or domain.startswith('https://'):
            domain = domain.split('//')[1].split('/')[0]
        
        try:
            # Get WHOIS information
            w = whois.whois(domain)
            
            print(f"\n{Fore.GREEN}[+] Domain Information:{Style.RESET_ALL}")
            print(f"    Domain: {Fore.YELLOW}{domain}{Style.RESET_ALL}")
            
            # Domain registrar info
            if w.registrar:
                print(f"    Registrar: {Fore.CYAN}{w.registrar}{Style.RESET_ALL}")
            
            # Registration dates
            if w.creation_date:
                if isinstance(w.creation_date, list):
                    creation = w.creation_date[0]
                else:
                    creation = w.creation_date
                print(f"    Created: {Fore.YELLOW}{creation.strftime('%Y-%m-%d %H:%M:%S')}{Style.RESET_ALL}")
            
            if w.expiration_date:
                if isinstance(w.expiration_date, list):
                    expiration = w.expiration_date[0]
                else:
                    expiration = w.expiration_date
                print(f"    Expires: {Fore.YELLOW}{expiration.strftime('%Y-%m-%d %H:%M:%S')}{Style.RESET_ALL}")
                
                # Check if domain is expiring soon
                days_until_expiry = (expiration - datetime.now()).days
                if days_until_expiry < 30:
                    print(f"    Status: {Fore.RED}Expiring in {days_until_expiry} days!{Style.RESET_ALL}")
                else:
                    print(f"    Status: {Fore.GREEN}Active ({days_until_expiry} days remaining){Style.RESET_ALL}")
            
            if w.updated_date:
                if isinstance(w.updated_date, list):
                    updated = w.updated_date[0]
                else:
                    updated = w.updated_date
                print(f"    Updated: {Fore.YELLOW}{updated.strftime('%Y-%m-%d %H:%M:%S')}{Style.RESET_ALL}")
            
            # Name servers
            if w.name_servers:
                print(f"\n{Fore.GREEN}[+] Name Servers:{Style.RESET_ALL}")
                for ns in w.name_servers:
                    print(f"    {Fore.CYAN}{ns.lower()}{Style.RESET_ALL}")
            
            # Contact information
            print(f"\n{Fore.GREEN}[+] Contact Information:{Style.RESET_ALL}")
            
            # Registrant info
            if w.name:
                print(f"    Registrant: {Fore.YELLOW}{w.name}{Style.RESET_ALL}")
            if w.org:
                print(f"    Organization: {Fore.YELLOW}{w.org}{Style.RESET_ALL}")
            if w.emails:
                if isinstance(w.emails, list):
                    for email in w.emails:
                        print(f"    Email: {Fore.CYAN}{email}{Style.RESET_ALL}")
                else:
                    print(f"    Email: {Fore.CYAN}{w.emails}{Style.RESET_ALL}")
            
            # Address information
            if w.address:
                print(f"    Address: {Fore.CYAN}{w.address}{Style.RESET_ALL}")
            if w.city:
                print(f"    City: {Fore.CYAN}{w.city}{Style.RESET_ALL}")
            if w.state:
                print(f"    State: {Fore.CYAN}{w.state}{Style.RESET_ALL}")
            if w.zipcode:
                print(f"    ZIP: {Fore.CYAN}{w.zipcode}{Style.RESET_ALL}")
            if w.country:
                print(f"    Country: {Fore.CYAN}{w.country}{Style.RESET_ALL}")
            
            # Domain status
            if w.status:
                print(f"\n{Fore.GREEN}[+] Domain Status:{Style.RESET_ALL}")
                if isinstance(w.status, list):
                    for status in w.status:
                        print(f"    {Fore.MAGENTA}{status}{Style.RESET_ALL}")
                else:
                    print(f"    {Fore.MAGENTA}{w.status}{Style.RESET_ALL}")
                    
        except Exception as e:
            print(f"{Fore.RED}[ERROR] python-whois lookup failed: {str(e)}{Style.RESET_ALL}")
            # Fall back to RDAP (free, keyless, IANA-standard bootstrap service)
            rdap_ok = rdap_lookup(domain)
            if not rdap_ok:
                print(f"{Fore.RED}[ERROR] All WHOIS lookup methods failed{Style.RESET_ALL}")

    except Exception as e:
        print(f"{Fore.RED}[ERROR] Unexpected error in WHOIS lookup: {str(e)}{Style.RESET_ALL}")


def rdap_lookup(domain):
    """Query the IANA RDAP bootstrap service for domain registration data.

    Returns True when data was found and displayed.
    """
    try:
        print(f"\n{Fore.GREEN}[+] Trying RDAP fallback:{Style.RESET_ALL}")

        # 1. Discover the authoritative RDAP server for this TLD
        boot = requests.get('https://data.iana.org/rdap/dns.json', timeout=10)
        if boot.status_code != 200:
            print(f"    {Fore.RED}✗ RDAP bootstrap unavailable{Style.RESET_ALL}")
            return False

        tld = domain.rsplit('.', 1)[-1]
        rdap_base = None
        for entry in boot.json().get('services', []):
            if tld in entry[0]:
                rdap_base = entry[1][0]
                break
        if not rdap_base:
            print(f"    {Fore.YELLOW}No RDAP server for .{tld}{Style.RESET_ALL}")
            return False

        # 2. Query the domain at the authoritative RDAP server
        resp = requests.get(f"{rdap_base}domain/{domain}", timeout=15,
                            headers={'Accept': 'application/rdap+json',
                                     'User-Agent': 'BloodRecon-OSINT/1.0'})
        if resp.status_code != 200:
            print(f"    {Fore.RED}✗ RDAP lookup failed (status {resp.status_code}){Style.RESET_ALL}")
            return False

        data = resp.json()
        print(f"\n{Fore.GREEN}[+] RDAP Domain Data:{Style.RESET_ALL}")
        print(f"    Domain: {Fore.YELLOW}{data.get('ldhName', domain)}{Style.RESET_ALL}")

        for event in data.get('events', []):
            action = event.get('eventAction', '')
            date = event.get('eventDate', '')[:10]
            if action in ('registration', 'expiration', 'last changed'):
                label = {'registration': 'Created',
                         'expiration': 'Expires',
                         'last changed': 'Updated'}.get(action, action)
                print(f"    {label}: {Fore.YELLOW}{date}{Style.RESET_ALL}")

        for ent in data.get('entities', []):
            roles = ent.get('roles', [])
            if 'registrar' in roles:
                vcard_name = ''
                for item in (ent.get('vcardArray') or [None, []])[1]:
                    if item and item[0] == 'fn':
                        vcard_name = item[3]
                        break
                print(f"    Registrar: {Fore.CYAN}{vcard_name or ent.get('handle', 'Unknown')}{Style.RESET_ALL}")

        nameservers = [ns.get('ldhName', '').lower()
                       for ns in data.get('nameservers', [])]
        if nameservers:
            print(f"\n{Fore.GREEN}[+] Name Servers:{Style.RESET_ALL}")
            for ns in nameservers[:10]:
                print(f"    {Fore.CYAN}{ns}{Style.RESET_ALL}")

        statuses = data.get('status', [])
        if statuses:
            print(f"\n{Fore.GREEN}[+] Domain Status:{Style.RESET_ALL}")
            for st in statuses[:8]:
                print(f"    {Fore.MAGENTA}{st}{Style.RESET_ALL}")

        return True

    except requests.RequestException as e:
        print(f"    {Fore.RED}✗ RDAP network error: {str(e)}{Style.RESET_ALL}")
    except ValueError:
        print(f"    {Fore.RED}✗ RDAP returned invalid JSON{Style.RESET_ALL}")
    return False
