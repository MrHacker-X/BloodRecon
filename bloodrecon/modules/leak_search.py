#!/usr/bin/env python3
"""
Data Leak Search Module
Search for leaked data in public breach databases.

Everything shown to the user comes from a real API response or is explicitly
labelled as guidance — this module never fabricates results.
Author : Alex Butler (@MrHacker-X)
Org    : Vritra Security Organization
"""

import hashlib
import os
import requests
from bloodrecon.modules.colors import Fore, Style

HIBP_ACCOUNT_URL = "https://haveibeenpwned.com/api/v3/breachedaccount/{account}"
HIBP_PASSWORD_URL = "https://api.pwnedpasswords.com/range/{prefix}"


def search_leaks(email):
    """Search for an email address in known data breaches."""
    try:
        print(f"\n{Fore.CYAN}╔══════════════════════════════════════════════════════════════╗")
        print(f"║                     {Fore.YELLOW}DATA BREACH SEARCH{Fore.CYAN}                       ║")
        print(f"╚══════════════════════════════════════════════════════════════╝{Style.RESET_ALL}")

        # Basic format check
        if '@' not in email or '.' not in email.split('@', 1)[1]:
            print(f"{Fore.RED}[ERROR] Invalid email format{Style.RESET_ALL}")
            return

        breaches = check_public_breaches(email)

        if breaches is None:
            # API could not be queried (offline / unauthorised / rate limited)
            print(f"\n{Fore.YELLOW}[!] Live breach verification unavailable.{Style.RESET_ALL}")
            print(f"    {Fore.CYAN}Verify manually at:{Style.RESET_ALL}")
            print(f"    • HaveIBeenPwned: {Fore.MAGENTA}https://haveibeenpwned.com/account/{email}{Style.RESET_ALL}")
            print(f"    • Firefox Monitor: {Fore.MAGENTA}https://monitor.firefox.com/{Style.RESET_ALL}")
            print(f"    • Google Password Checkup: {Fore.MAGENTA}https://passwords.google.com/checkup{Style.RESET_ALL}")
            print(f"\n    {Fore.YELLOW}Tip: set HIBP_API_KEY (a paid HaveIBeenPwned key) to enable")
            print(f"    automatic account-breach lookups:{Style.RESET_ALL}")
            print(f"    {Fore.CYAN}export HIBP_API_KEY=\"your_key\"{Style.RESET_ALL}")
        elif not breaches:
            print(f"\n{Fore.GREEN}[+] No breaches found for this email (verified via HaveIBeenPwned){Style.RESET_ALL}")
        else:
            print(f"\n{Fore.RED}[!] POTENTIAL BREACHES FOUND:{Style.RESET_ALL}")
            for i, breach in enumerate(breaches, 1):
                print(f"\n    {Fore.RED}[{i}] {breach['name']}{Style.RESET_ALL}")
                print(f"        Date: {Fore.YELLOW}{breach['date']}{Style.RESET_ALL}")
                affected = breach.get('affected', 0)
                if isinstance(affected, int):
                    print(f"        Affected: {Fore.CYAN}{affected:,} accounts{Style.RESET_ALL}")
                else:
                    print(f"        Affected: {Fore.CYAN}{affected}{Style.RESET_ALL}")
                print(f"        Data Types: {Fore.MAGENTA}{', '.join(breach['data_types'])}{Style.RESET_ALL}")
                print(f"        Verified: {Fore.RED if breach['verified'] else Fore.YELLOW}"
                      f"{'✓ Yes (live API)' if breach['verified'] else '? Unverified'}{Style.RESET_ALL}")

        # Password security check using HIBP Passwords API (k-anonymity, no key needed)
        password_security_demo()

        # Security recommendations
        print(f"\n{Fore.GREEN}[+] Security Recommendations:{Style.RESET_ALL}")
        if breaches:
            print(f"    {Fore.RED}• Immediately change passwords for affected accounts{Style.RESET_ALL}")
            print(f"    {Fore.RED}• Enable two-factor authentication on all accounts{Style.RESET_ALL}")
            print(f"    {Fore.RED}• Monitor accounts for suspicious activity{Style.RESET_ALL}")
            print(f"    {Fore.RED}• Consider using a password manager{Style.RESET_ALL}")
        else:
            print(f"    {Fore.GREEN}• Continue using unique passwords for each account{Style.RESET_ALL}")
            print(f"    {Fore.GREEN}• Enable two-factor authentication where possible{Style.RESET_ALL}")
            print(f"    {Fore.GREEN}• Regularly monitor account activity{Style.RESET_ALL}")

    except Exception as e:
        print(f"{Fore.RED}[ERROR] Unexpected error in leak search: {str(e)}{Style.RESET_ALL}")


def check_public_breaches(email):
    """Query the HaveIBeenPwned breached-account API.

    Returns:
        list  — breaches found (each marked verified=True, straight from API)
        []    — API reachable, account not found in any breach
        None  — API could not be queried (no key, network error, rate limit)
    """
    api_key = os.environ.get('HIBP_API_KEY')
    if not api_key:
        # The v3 account API requires a paid key; without one we cannot check
        # accounts live. Never fabricate a result in its place.
        return None

    headers = {
        'hibp-api-key': api_key,
        'User-Agent': 'BloodRecon-OSINT/1.0',
    }
    try:
        resp = requests.get(
            HIBP_ACCOUNT_URL.format(account=email),
            headers=headers, timeout=15,
            params={'truncateResponse': 'false'},
        )
        if resp.status_code == 200:
            data = resp.json() or []
            breaches = []
            for b in data:
                breaches.append({
                    'name': b.get('Name', 'Unknown'),
                    'date': b.get('BreachDate', 'Unknown'),
                    'affected': b.get('PwnCount', 0),
                    'data_types': b.get('DataClasses', ['Email']),
                    'verified': b.get('IsVerified', False),
                })
            return breaches
        if resp.status_code == 404:
            return []  # verified: not in any known breach
        if resp.status_code == 401:
            print(f"{Fore.RED}[ERROR] HIBP rejected the API key (401){Style.RESET_ALL}")
            return None
        if resp.status_code == 429:
            print(f"{Fore.YELLOW}[!] HIBP rate limit reached — try again later{Style.RESET_ALL}")
            return None
        print(f"{Fore.RED}[ERROR] HIBP API returned status {resp.status_code}{Style.RESET_ALL}")
        return None
    except requests.RequestException as e:
        print(f"{Fore.RED}[ERROR] Network error contacting HIBP: {str(e)}{Style.RESET_ALL}")
        return None


def password_security_demo():
    """Interactive k-anonymity password check against the free HIBP range API."""
    print(f"\n{Fore.GREEN}[+] Password Exposure Check (k-anonymity — your password never leaves this machine):{Style.RESET_ALL}")
    try:
        answer = input(f"    {Fore.CYAN}Type a password to check (or press Enter to skip): {Style.RESET_ALL}")
        if not answer:
            print(f"    {Fore.YELLOW}Skipped.{Style.RESET_ALL}")
            return

        sha1 = hashlib.sha1(answer.encode('utf-8')).hexdigest().upper()
        prefix, suffix = sha1[:5], sha1[5:]
        resp = requests.get(HIBP_PASSWORD_URL.format(prefix=prefix), timeout=15)
        resp.raise_for_status()

        count = 0
        for line in resp.text.splitlines():
            parts = line.strip().split(':')
            if len(parts) == 2 and parts[0] == suffix:
                count = int(parts[1])
                break

        if count > 0:
            print(f"    {Fore.RED}⚠ EXPOSED — seen {count:,} times in known data breaches!{Style.RESET_ALL}")
            print(f"    {Fore.RED}• Do NOT use this password anywhere. Change it now.{Style.RESET_ALL}")
        else:
            print(f"    {Fore.GREEN}✓ Not found in the HIBP password corpus (no known exposure).{Style.RESET_ALL}")
    except requests.RequestException as e:
        print(f"    {Fore.RED}Password range API unreachable: {str(e)}{Style.RESET_ALL}")
    except Exception as e:
        print(f"    {Fore.RED}Password check failed: {str(e)}{Style.RESET_ALL}")
