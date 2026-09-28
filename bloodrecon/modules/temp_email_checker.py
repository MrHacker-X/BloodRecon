#!/usr/bin/env python3
"""
Temporary Email Domain Checker
Detect temporary/disposable email addresses
Author : Alex Butler (@MrHacker-X)
Org    : Vritra Security Organization
"""

import os
import re
from bloodrecon.modules.colors import Fore, Style


def load_temp_domains(file_path=None):
    """Load the temp-domain list; path resolved relative to this module file."""
    if file_path is None:
        file_path = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                 'list-imp', 'temp_domains.txt')
    try:
        with open(file_path, 'r') as f:
            return set(line.strip().lower() for line in f
                       if line.strip() and not line.startswith("#"))
    except FileNotFoundError:
        print(f"[!] Temp email domain list not found: {file_path}")
        return set()

TEMP_DOMAINS_LST = load_temp_domains()

# Word-boundary patterns — substring matching caused false positives
# (e.g. "temperature-check.com" or "contest.win" flagged as temp mail).
TEMP_PATTERNS = [
    re.compile(r'\btemp\b|\btmp\b'),
    re.compile(r'tempmail|temp-mail|tmpmail|tmp-mail|temprmail'),
    re.compile(r'\btrash(?:mail)?\b'),
    re.compile(r'\bfakemail\b|\bfake-mail\b'),
    re.compile(r'\bthrowaway\b|\bthrow-?away\b'),
    re.compile(r'\bdisposable\b|\bdispose\b'),
    re.compile(r'\bspam(?:mail|hole)?\b|\bspam-?mail\b'),
    re.compile(r'10min(?:ute)?s?mail|10minmail|10minutemail'),
    re.compile(r'guerrillamail|guerrilla-mail'),
    re.compile(r'mailinator|yopmail|getnada|jetable|maildrop|mailnesia|'
               r'dispostable|sharklasers|burnermail|moakt'),
    re.compile(r'\bdiscard\b|\bburner\b|\bonetime\b|one-time'),
]


def check_temp_email(email):
    """Check if email domain is from a temporary email service"""
    try:
        print(f"\n{Fore.CYAN}╔══════════════════════════════════════════════════════════════╗")
        print(f"║                  {Fore.YELLOW}TEMPORARY EMAIL CHECKER{Fore.CYAN}                     ║")
        print(f"╚══════════════════════════════════════════════════════════════╝{Style.RESET_ALL}")
        
        if '@' not in email:
            print(f"{Fore.RED}[ERROR] Invalid email format{Style.RESET_ALL}")
            return
        
        domain = email.split('@')[1].lower()
        
        print(f"\n{Fore.GREEN}[+] Email Analysis:{Style.RESET_ALL}")
        print(f"    Email: {Fore.YELLOW}{email}{Style.RESET_ALL}")
        print(f"    Domain: {Fore.CYAN}{domain}{Style.RESET_ALL}")
        
        # Use updated temporary domains list
        temp_domains = TEMP_DOMAINS_LST
        
        # Check if domain is in temp list
        is_temp = domain in temp_domains
        
        print(f"\n{Fore.GREEN}[+] Analysis Results:{Style.RESET_ALL}")
        
        if is_temp:
            print(f"    Status: {Fore.RED}⚠️  TEMPORARY EMAIL DETECTED{Style.RESET_ALL}")
            print(f"    Risk Level: {Fore.RED}HIGH{Style.RESET_ALL}")
            print(f"    Type: {Fore.YELLOW}Disposable/Temporary Service{Style.RESET_ALL}")
        else:
            # Word-boundary pattern check (avoids substring false positives)
            suspicious_patterns = [p.pattern for p in TEMP_PATTERNS if p.search(domain)]
            
            if suspicious_patterns:
                print(f"    Status: {Fore.YELLOW}⚠️  POTENTIALLY TEMPORARY{Style.RESET_ALL}")
                print(f"    Risk Level: {Fore.YELLOW}MEDIUM{Style.RESET_ALL}")
                print(f"    Suspicious Patterns: {Fore.YELLOW}{', '.join(suspicious_patterns)}{Style.RESET_ALL}")
            else:
                print(f"    Status: {Fore.GREEN}✓ APPEARS LEGITIMATE{Style.RESET_ALL}")
                print(f"    Risk Level: {Fore.GREEN}LOW{Style.RESET_ALL}")
        
        # Domain age and reputation (simulated)
        print(f"\n{Fore.GREEN}[+] Domain Assessment:{Style.RESET_ALL}")
        
        # Check for common legitimate domains
        legitimate_domains = {
            'gmail.com', 'yahoo.com', 'hotmail.com', 'outlook.com', 'aol.com',
            'icloud.com', 'mail.com', 'protonmail.com', 'tutanota.com'
        }
        
        if domain in legitimate_domains:
            print(f"    Provider Type: {Fore.GREEN}Major Email Provider{Style.RESET_ALL}")
            print(f"    Reputation: {Fore.GREEN}Excellent{Style.RESET_ALL}")
        elif is_temp:
            print(f"    Provider Type: {Fore.RED}Temporary Email Service{Style.RESET_ALL}")
            print(f"    Reputation: {Fore.RED}Poor (Disposable){Style.RESET_ALL}")
        else:
            print(f"    Provider Type: {Fore.YELLOW}Custom/Business Domain{Style.RESET_ALL}")
            print(f"    Reputation: {Fore.CYAN}Requires verification{Style.RESET_ALL}")
        
        # Recommendations
        print(f"\n{Fore.GREEN}[+] Recommendations:{Style.RESET_ALL}")
        
        if is_temp:
            print(f"    {Fore.RED}• Block or flag this email address{Style.RESET_ALL}")
            print(f"    {Fore.RED}• Require email verification{Style.RESET_ALL}")
            print(f"    {Fore.RED}• Consider additional authentication{Style.RESET_ALL}")
        else:
            print(f"    {Fore.GREEN}• Email appears to be from legitimate domain{Style.RESET_ALL}")
            print(f"    {Fore.YELLOW}• Still recommend email verification{Style.RESET_ALL}")
            print(f"    {Fore.CYAN}• Monitor for suspicious activity{Style.RESET_ALL}")
        
        # Additional resources
        print(f"\n{Fore.GREEN}[+] Additional Verification:{Style.RESET_ALL}")
        print(f"    Check Domain: {Fore.MAGENTA}whois {domain}{Style.RESET_ALL}")
        print(f"    MX Records: {Fore.MAGENTA}dig MX {domain}{Style.RESET_ALL}")
        print(f"    Reputation: {Fore.MAGENTA}Check domain reputation databases{Style.RESET_ALL}")
        
    except Exception as e:
        print(f"{Fore.RED}[ERROR] Unexpected error in temp email check: {str(e)}{Style.RESET_ALL}")
