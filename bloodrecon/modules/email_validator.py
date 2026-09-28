#!/usr/bin/env python3
"""
Email Validation Module
Validate email format and domain
Author : Alex Butler (@MrHacker-X)
Org    : Vritra Security Organization
"""

import re
import dns.resolver
from bloodrecon.modules.colors import Fore, Style

def validate_email(email):
    """Validate email format and domain"""
    try:
        print(f"\n{Fore.CYAN}╔══════════════════════════════════════════════════════════════╗")
        print(f"║                      {Fore.YELLOW}EMAIL VALIDATION{Fore.CYAN}                        ║")
        print(f"╚══════════════════════════════════════════════════════════════╝{Style.RESET_ALL}")
        
        print(f"\n{Fore.GREEN}[+] Email Analysis:{Style.RESET_ALL}")
        print(f"    Email: {Fore.YELLOW}{email}{Style.RESET_ALL}")
        
        # Basic format validation
        email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        if re.match(email_pattern, email):
            print(f"    Format: {Fore.GREEN}✓ Valid{Style.RESET_ALL}")
        else:
            print(f"    Format: {Fore.RED}✗ Invalid{Style.RESET_ALL}")
            return
        
        # Extract domain
        domain = email.split('@')[1]
        print(f"    Domain: {Fore.CYAN}{domain}{Style.RESET_ALL}")
        
        # Check MX records
        try:
            mx_records = dns.resolver.resolve(domain, 'MX')
            print(f"    MX Records: {Fore.GREEN}✓ Found{Style.RESET_ALL}")
            for mx in mx_records:
                print(f"      {Fore.CYAN}{mx}{Style.RESET_ALL}")
        except:
            print(f"    MX Records: {Fore.RED}✗ Not found{Style.RESET_ALL}")
        
        # Check A records
        try:
            a_records = dns.resolver.resolve(domain, 'A')
            print(f"    A Records: {Fore.GREEN}✓ Found{Style.RESET_ALL}")
            for a in a_records:
                print(f"      {Fore.CYAN}{a}{Style.RESET_ALL}")
        except:
            print(f"    A Records: {Fore.RED}✗ Not found{Style.RESET_ALL}")
        
        # Common email providers
        common_providers = {
            'gmail.com': 'Google Gmail',
            'yahoo.com': 'Yahoo Mail',
            'hotmail.com': 'Microsoft Hotmail',
            'outlook.com': 'Microsoft Outlook',
            'icloud.com': 'Apple iCloud',
            'protonmail.com': 'ProtonMail'
        }
        
        if domain in common_providers:
            print(f"    Provider: {Fore.MAGENTA}{common_providers[domain]}{Style.RESET_ALL}")
        else:
            print(f"    Provider: {Fore.YELLOW}Custom/Business{Style.RESET_ALL}")
        
    except Exception as e:
        print(f"{Fore.RED}[ERROR] Unexpected error in email validation: {str(e)}{Style.RESET_ALL}")
