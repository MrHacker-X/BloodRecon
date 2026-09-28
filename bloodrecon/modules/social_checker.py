#!/usr/bin/env python3
"""
Social Media Username Checker
Check username availability across social platforms
Author : Alex Butler (@MrHacker-X)
Org    : Vritra Security Organization
"""

import requests
from bloodrecon.modules.colors import Fore, Style

def check_username(username):
    """Check username across social media platforms"""
    try:
        print(f"\n{Fore.CYAN}╔══════════════════════════════════════════════════════════════╗")
        print(f"║                   {Fore.YELLOW}SOCIAL MEDIA CHECKER{Fore.CYAN}                       ║")
        print(f"╚══════════════════════════════════════════════════════════════╝{Style.RESET_ALL}")
        
        print(f"\n{Fore.GREEN}[+] Username Analysis:{Style.RESET_ALL}")
        print(f"    Username: {Fore.YELLOW}{username}{Style.RESET_ALL}")
        
        # Social media platforms to check
        platforms = {
            'GitHub': f'https://github.com/{username}',
            'Twitter/X': f'https://x.com/{username}',
            'Instagram': f'https://www.instagram.com/{username}/',
            'Reddit': f'https://www.reddit.com/user/{username}/',
            'LinkedIn': f'https://www.linkedin.com/in/{username}',
            'YouTube': f'https://www.youtube.com/@{username}',
            'Facebook': f'https://www.facebook.com/{username}',
            'TikTok': f'https://www.tiktok.com/@{username}',
            'Pinterest': f'https://www.pinterest.com/{username}/',
            'Medium': f'https://medium.com/@{username}',
            'Telegram': f'https://t.me/{username}',
        }

        headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'}

        print(f"\n{Fore.GREEN}[+] Platform Availability:{Style.RESET_ALL}")

        for platform, url in platforms.items():
            try:
                response = requests.get(url, timeout=10, allow_redirects=True,
                                        headers=headers)

                # Sites that aggressively block bots (403/999/anti-bot pages)
                # must be reported as UNKNOWN, never as Taken or Available.
                if response.status_code in (403, 999):
                    status = f"{Fore.YELLOW}Blocked (bot protection) — check manually{Style.RESET_ALL}"
                elif response.status_code == 404:
                    status = f"{Fore.GREEN}Available{Style.RESET_ALL}"
                elif response.status_code == 200:
                    body = response.text.lower()
                    # error-page heuristics: these strings mean the profile is NOT real
                    error_markers = {
                        'GitHub': 'not found',
                        'Twitter/X': "this account doesn\u2019t exist",
                        'Instagram': 'sorry, this page isn\u2019t available',
                        'Reddit': 'sorry, nobody on reddit goes by that name',
                        'TikTok': "couldn't find this account",
                        'Medium': 'out of nothing, something',
                        'Telegram': "if you have telegram, you can contact",
                    }
                    marker = error_markers.get(platform)
                    if marker and marker in body:
                        status = f"{Fore.GREEN}Available{Style.RESET_ALL}"
                    else:
                        status = f"{Fore.RED}Taken{Style.RESET_ALL}"
                else:
                    status = f"{Fore.YELLOW}Unknown ({response.status_code}){Style.RESET_ALL}"

                print(f"    {platform:12} - {status} - {Fore.CYAN}{url}{Style.RESET_ALL}")

            except requests.RequestException:
                print(f"    {platform:12} - {Fore.YELLOW}Unreachable{Style.RESET_ALL} - {Fore.CYAN}{url}{Style.RESET_ALL}")
        
        # Additional checks
        print(f"\n{Fore.GREEN}[+] Additional Resources:{Style.RESET_ALL}")
        print(f"    Namechk: {Fore.MAGENTA}https://namechk.com/{username}{Style.RESET_ALL}")
        print(f"    KnowEm: {Fore.MAGENTA}https://knowem.com/checkusernames.php?u={username}{Style.RESET_ALL}")
        print(f"    UserSearch: {Fore.MAGENTA}https://usersearch.org/user/{username}{Style.RESET_ALL}")
        
    except Exception as e:
        print(f"{Fore.RED}[ERROR] Unexpected error in social media check: {str(e)}{Style.RESET_ALL}")
