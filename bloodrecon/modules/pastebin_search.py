#!/usr/bin/env python3
"""
Pastebin Dump Search Module
Search for leaked data in Pastebin and similar services.

The psbdmp.ws API indexes public pastebins and requires no key; results shown
are real. Manual-search links are clearly labelled as manual.
Author : Alex Butler (@MrHacker-X)
Org    : Vritra Security Organization
"""

import requests
import re
from bloodrecon.modules.colors import Fore, Style

PSBDMP_SEARCH_URL = "https://psbdmp.ws/api/search/{term}"


def search_pastebin(query):
    """Search for data in Pastebin and similar services."""
    try:
        print(f"\n{Fore.CYAN}╔══════════════════════════════════════════════════════════════╗")
        print(f"║                    {Fore.YELLOW}PASTEBIN DUMP SEARCH{Fore.CYAN}                      ║")
        print(f"╚══════════════════════════════════════════════════════════════╝{Style.RESET_ALL}")

        print(f"\n{Fore.GREEN}[+] Searching for: {Fore.YELLOW}{query}{Style.RESET_ALL}")

        # Real search via the psbdmp.ws paste aggregator API
        query_paste_index(query)

        # Google dork links (manual)
        search_google_for_pastes(query)

        # Manual search links
        provide_manual_search_links(query)

        # Security recommendations
        print(f"\n{Fore.GREEN}[+] Security Recommendations:{Style.RESET_ALL}")
        print(f"    {Fore.RED}• If sensitive data is found, take immediate action{Style.RESET_ALL}")
        print(f"    {Fore.RED}• Change passwords and API keys immediately{Style.RESET_ALL}")
        print(f"    {Fore.RED}• Contact the paste service to request removal{Style.RESET_ALL}")
        print(f"    {Fore.YELLOW}• Monitor for future data exposures{Style.RESET_ALL}")

    except Exception as e:
        print(f"{Fore.RED}[ERROR] Unexpected error in Pastebin search: {str(e)}{Style.RESET_ALL}")


def query_paste_index(query):
    """Query the psbdmp.ws public paste index (no API key required)."""
    print(f"\n{Fore.GREEN}[+] Paste Index Search (psbdmp.ws):{Style.RESET_ALL}")
    try:
        url = PSBDMP_SEARCH_URL.format(term=requests.utils.quote(query))
        resp = requests.get(url, timeout=15,
                            headers={'User-Agent': 'BloodRecon-OSINT/1.0'})

        if resp.status_code == 429:
            print(f"    {Fore.YELLOW}⚠ Rate limited by psbdmp.ws — try again later{Style.RESET_ALL}")
            return
        if resp.status_code != 200:
            print(f"    {Fore.RED}✗ Paste index unavailable (status {resp.status_code}){Style.RESET_ALL}")
            return

        data = resp.json()
        # API returns {'count': N, 'data': [{'id': ..., 'date': ..., 'tags': [...]}]}
        hits = data.get('data') or []
        count = data.get('count', len(hits))

        if not hits:
            print(f"    {Fore.GREEN}✓ No pastes matching '{query}' in the index{Style.RESET_ALL}")
            return

        print(f"    {Fore.CYAN}Indexed pastes found: {count}{Style.RESET_ALL}")
        for i, paste in enumerate(hits[:15], 1):
            paste_id = paste.get('id', '')
            paste_url = f"https://pastebin.com/{paste_id}" if paste_id else 'Unknown'
            date = paste.get('date', '')
            if isinstance(date, (int, float)) and date > 0:
                try:
                    from datetime import datetime, timezone
                    date = datetime.fromtimestamp(date, tz=timezone.utc).strftime('%Y-%m-%d')
                except Exception:
                    pass
            tags = ', '.join(paste.get('tags', []) or [])
            print(f"    {Fore.YELLOW}[{i:2d}] {paste_url}{Style.RESET_ALL}")
            if date:
                print(f"          Date: {Fore.CYAN}{date}{Style.RESET_ALL}")
            if tags:
                print(f"          Tags: {Fore.MAGENTA}{tags}{Style.RESET_ALL}")

        if count > 15:
            print(f"    {Fore.CYAN}... and {count - 15} more (view in the index){Style.RESET_ALL}")

        print(f"\n    {Fore.YELLOW}⚠ Paste contents are not fetched automatically — review manually{Style.RESET_ALL}")
        print(f"    {Fore.YELLOW}  before opening (pastebins can host malicious content).{Style.RESET_ALL}")

    except requests.RequestException as e:
        print(f"    {Fore.RED}✗ Paste index unreachable: {str(e)}{Style.RESET_ALL}")
    except ValueError:
        print(f"    {Fore.RED}✗ Paste index returned invalid data{Style.RESET_ALL}")


def search_google_for_pastes(query):
    """Generate Google search URLs for different paste services (manual)."""
    try:
        print(f"\n{Fore.GREEN}[+] Google Dork Links (manual search):{Style.RESET_ALL}")

        paste_sites = [
            "pastebin.com", "paste.ee", "hastebin.com", "justpaste.it",
            "dpaste.org", "rentry.co"
        ]

        for site in paste_sites:
            search_url = f"https://www.google.com/search?q=site:{site}%20\"{requests.utils.quote(query)}\""
            print(f"    🔗 {site}: {Fore.MAGENTA}{search_url}{Style.RESET_ALL}")

    except Exception as e:
        print(f"{Fore.RED}[ERROR] Error generating search URLs: {str(e)}{Style.RESET_ALL}")


def provide_manual_search_links(query):
    """Provide manual search links and tools."""
    try:
        print(f"\n{Fore.GREEN}[+] Manual Search Tools:{Style.RESET_ALL}")

        q = requests.utils.quote(query)
        search_engines = {
            "IntelX.io": f"https://intelx.io/?s={q}",
            "Dehashed.com": f"https://dehashed.com/search?query={q}",
            "LeakCheck.io": "https://leakcheck.io/",
            "HaveIBeenPwned": "https://haveibeenpwned.com/",
        }

        for tool, url in search_engines.items():
            print(f"    🔗 {tool}: {Fore.MAGENTA}{url}{Style.RESET_ALL}")

        print(f"\n{Fore.GREEN}[+] GitHub Code Search (manual):{Style.RESET_ALL}")
        github_searches = [
            f"\"{query}\" password",
            f"\"{query}\" api_key",
            f"\"{query}\" secret",
        ]
        for search in github_searches:
            encoded = requests.utils.quote(search)
            print(f"    🔗 {search}")
            print(f"      {Fore.MAGENTA}https://github.com/search?q={encoded}&type=code{Style.RESET_ALL}")

    except Exception as e:
        print(f"{Fore.RED}[ERROR] Error providing manual links: {str(e)}{Style.RESET_ALL}")


def analyze_paste_content(content):
    """Analyze paste content for sensitive information (used after manual fetch)."""
    try:
        print(f"\n{Fore.GREEN}[+] Content Analysis:{Style.RESET_ALL}")

        patterns = {
            'emails': r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}',
            'passwords': r'password[:\s=]+[^\s\n]+',
            'api_keys': r'api[_\s]*key[:\s=]+[A-Za-z0-9]+',
            'phone_numbers': r'\b\d{3}[-.]?\d{3}[-.]?\d{4}\b',
            'credit_cards': r'\b\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b',
            'ip_addresses': r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b'
        }

        findings = {}
        for pattern_name, pattern in patterns.items():
            matches = re.findall(pattern, content, re.IGNORECASE)
            if matches:
                findings[pattern_name] = len(matches)

        if findings:
            print(f"    {Fore.RED}⚠️  SENSITIVE DATA DETECTED:{Style.RESET_ALL}")
            for data_type, count in findings.items():
                print(f"      {data_type}: {Fore.YELLOW}{count} matches{Style.RESET_ALL}")
        else:
            print(f"    {Fore.GREEN}✓ No obvious sensitive patterns detected{Style.RESET_ALL}")

        return findings

    except Exception as e:
        print(f"{Fore.RED}[ERROR] Error analyzing content: {str(e)}{Style.RESET_ALL}")
        return {}
