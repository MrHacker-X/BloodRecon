#!/usr/bin/env python3
"""
Wayback Machine Snapshot Finder
Locate historical snapshots of a URL from the Internet Archive
Author : Alex Butler (@MrHacker-X)
Org    : Vritra Security Organization
"""

import requests
from bloodrecon.modules.colors import Fore, Style
from urllib.parse import quote

def search_wayback(url):
    """Search Internet Archive for wayback snapshots"""
    try:
        print(f"\n{Fore.CYAN}╔══════════════════════════════════════════════════════════════╗")
        print(f"║                  {Fore.YELLOW}WAYBACK MACHINE FINDER{Fore.CYAN}                      ║")
        print(f"╚══════════════════════════════════════════════════════════════╝{Style.RESET_ALL}")
        
        # Ensure URL has proper format
        if not url.startswith(('http://', 'https://')):
            url = 'http://' + url
        
        # Query the Wayback Machine (https — http 301s to it anyway)
        api_url = f"https://archive.org/wayback/available?url={quote(url)}"
        try:
            response = requests.get(api_url, timeout=10)
            if response.status_code == 200:
                data = response.json()
                if 'archived_snapshots' in data and data['archived_snapshots']:
                    print(f"\n{Fore.GREEN}[+] Latest Snapshot:{Style.RESET_ALL}")
                    snapshot = data['archived_snapshots']['closest']
                    
                    if 'available' in snapshot and snapshot['available']:
                        print(f"    Snapshot URL: {Fore.YELLOW}{snapshot['url']}{Style.RESET_ALL}")
                        print(f"    Timestamp: {Fore.YELLOW}{snapshot['timestamp']}{Style.RESET_ALL}")
                        print(f"    Status: {Fore.GREEN}Available{Style.RESET_ALL}")
                    else:
                        print(f"    {Fore.RED}No available snapshot found.{Style.RESET_ALL}")
                else:
                    print(f"    {Fore.RED}No snapshots found for this URL.{Style.RESET_ALL}")
            else:
                print(f"    {Fore.RED}Failed to contact Wayback Machine.{Style.RESET_ALL}")
        except requests.RequestException as e:
            print(f"{Fore.RED}[ERROR] Network error while contacting Wayback Machine: {str(e)}{Style.RESET_ALL}")
            
        # Advanced search
        print(f"\n{Fore.GREEN}[+] Advanced Search:{Style.RESET_ALL}")
        timeline_url = f"https://web.archive.org/web/*/{url}"
        print(f"    Explore full timeline: {Fore.CYAN}{timeline_url}{Style.RESET_ALL}")

        # Historical snapshot list via the CDX API (real data)
        show_cdx_history(url)

    except Exception as e:
        print(f"{Fore.RED}[ERROR] Unexpected error in Wayback Machine search: {str(e)}{Style.RESET_ALL}")


def show_cdx_history(url):
    """Query the Wayback CDX API for the most recent archived captures."""
    try:
        print(f"\n{Fore.GREEN}[+] Recent Captures (CDX API):{Style.RESET_ALL}")
        cdx_url = (f"https://web.archive.org/cdx/search/cdx?url={quote(url, safe='')}")
        params = {'output': 'json', 'limit': '15', 'collapse': 'timestamp:6'}
        resp = requests.get(cdx_url, params=params, timeout=20,
                            headers={'User-Agent': 'BloodRecon-OSINT/1.0'})
        if resp.status_code != 200:
            print(f"    {Fore.RED}✗ CDX API unavailable (status {resp.status_code}){Style.RESET_ALL}")
            return

        rows = resp.json()
        if len(rows) < 2:  # first row is the header
            print(f"    {Fore.YELLOW}No captures recorded{Style.RESET_ALL}")
            return

        header = rows[0]
        ts_idx = header.index('timestamp') if 'timestamp' in header else 1
        status_idx = header.index('statuscode') if 'statuscode' in header else 3

        for row in rows[1:]:
            ts = str(row[ts_idx])
            status = row[status_idx] if status_idx < len(row) else '?'
            if len(ts) >= 8:
                readable = f"{ts[0:4]}-{ts[4:6]}-{ts[6:8]}"
            else:
                readable = ts
            archived = f"https://web.archive.org/web/{ts}/{url}"
            print(f"    {Fore.CYAN}{readable}{Style.RESET_ALL} "
                  f"[{status}] {Fore.MAGENTA}{archived}{Style.RESET_ALL}")

    except requests.RequestException as e:
        print(f"    {Fore.RED}✗ CDX request failed: {str(e)}{Style.RESET_ALL}")
    except (ValueError, IndexError):
        print(f"    {Fore.RED}✗ CDX returned unexpected data{Style.RESET_ALL}")
