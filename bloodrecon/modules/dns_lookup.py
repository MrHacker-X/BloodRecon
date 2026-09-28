#!/usr/bin/env python3
"""
DNS Records Analysis Module
Fetch and analyze DNS records such as A, MX, TXT, and NS
Author : Alex Butler (@MrHacker-X)
Org    : Vritra Security Organization
"""

import dns.resolver
from bloodrecon.modules.colors import Fore, Style

def get_dns_records(domain):
    """Fetch and display DNS records for a domain"""
    try:
        print(f"\n{Fore.CYAN}╔══════════════════════════════════════════════════════════════╗")
        print(f"║                    {Fore.YELLOW}DNS RECORDS ANALYSIS{Fore.CYAN}                      ║")
        print(f"╚══════════════════════════════════════════════════════════════╝{Style.RESET_ALL}")
        
        domain = domain.lower().strip()
        
        # Function for record checking
        def check_record(record_type):
            try:
                responses = dns.resolver.resolve(domain, record_type)
                print(f"\n{Fore.GREEN}[+] {record_type} Records:{Style.RESET_ALL}")
                for data in responses:
                    print(f"    {Fore.YELLOW}{data.to_text()}{Style.RESET_ALL}")
            except dns.resolver.NoAnswer:
                print(f"    {Fore.RED}No {record_type} records found.{Style.RESET_ALL}")
            except dns.resolver.NXDOMAIN:
                print(f"    {Fore.RED}Domain does not exist ({record_type}).{Style.RESET_ALL}")
            except dns.exception.Timeout:
                print(f"    {Fore.RED}Timed out while fetching {record_type} records.{Style.RESET_ALL}")
            except Exception as e:
                print(f"    {Fore.RED}Unexpected error: {str(e)}{Style.RESET_ALL}")

        # Query different record types
        query_types = ['A', 'MX', 'TXT', 'NS']
        
        for qtype in query_types:
            check_record(qtype)

    except Exception as e:
        print(f"{Fore.RED}[ERROR] Unexpected error in DNS lookup: {str(e)}{Style.RESET_ALL}")
