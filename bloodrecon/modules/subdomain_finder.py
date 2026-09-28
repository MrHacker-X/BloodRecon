#!/usr/bin/env python3
"""
Subdomain Finder Module
Discover subdomains using various techniques
Author : Alex Butler (@MrHacker-X)
Org    : Vritra Security Organization
"""

import dns.resolver
import time
from bloodrecon.modules.colors import Fore, Style

def find_subdomains(domain):
    """Find subdomains for a domain"""
    try:
        print(f"\n{Fore.CYAN}╔══════════════════════════════════════════════════════════════╗")
        print(f"║                    {Fore.YELLOW}SUBDOMAIN DISCOVERY{Fore.CYAN}                       ║")
        print(f"╚══════════════════════════════════════════════════════════════╝{Style.RESET_ALL}")
        
        domain = domain.lower().strip()
        if domain.startswith(('http://', 'https://')):
            domain = domain.split('//')[1].split('/')[0]
        
        print(f"\n{Fore.GREEN}[+] Subdomain Discovery:{Style.RESET_ALL}")
        print(f"    Target Domain: {Fore.YELLOW}{domain}{Style.RESET_ALL}")
        
        # Common subdomain prefixes
        common_subdomains = [
            'www', 'mail', 'ftp', 'admin', 'test', 'dev', 'staging', 'api',
            'blog', 'shop', 'store', 'secure', 'vpn', 'remote', 'support',
            'help', 'docs', 'cdn', 'assets', 'img', 'images', 'static',
            'beta', 'demo', 'portal', 'wiki', 'forum', 'news', 'mobile',
            'm', 'app', 'apps', 'db', 'database', 'sql', 'mysql', 'backup'
        ]
        
        found_subdomains = []
        
        print(f"\n{Fore.GREEN}[+] Testing Common Subdomains:{Style.RESET_ALL}")
        
        for subdomain in common_subdomains:
            full_domain = f"{subdomain}.{domain}"
            time.sleep(0.1)  # Rate limiting
            try:
                # Try DNS resolution
                answers = dns.resolver.resolve(full_domain, 'A')
                for answer in answers:
                    ip_str = str(answer)
                    if not is_private_ip_address(ip_str):  # Ensure it's not private IP
                        print(f"    {Fore.GREEN}✓ {full_domain}{Style.RESET_ALL} -> {Fore.CYAN}{answer}{Style.RESET_ALL}")
                        found_subdomains.append((full_domain, str(answer)))
                        break
            except dns.resolver.NXDOMAIN:
                pass
            except dns.resolver.NoAnswer:
                pass
            except Exception:
                pass
        
        # Expand wordlist for deeper scanning
        print(f"\n{Fore.GREEN}[+] Extended Subdomain Wordlist:{Style.RESET_ALL}")
        extended_subdomains = [
            'staging', 'prod', 'production', 'dev', 'development', 'qa', 'testing',
            'sandbox', 'demo2', 'beta2', 'alpha', 'preview', 'temp', 'old',
            'new', 'v1', 'v2', 'api-v1', 'api-v2', 'webmail', 'mail2', 'smtp',
            'imap', 'pop', 'ns1', 'ns2', 'dns1', 'dns2', 'mx1', 'mx2'
        ]
        
        for subdomain in extended_subdomains:
            full_domain = f"{subdomain}.{domain}"
            time.sleep(0.05)  # Faster rate limiting for extended scan
            try:
                answers = dns.resolver.resolve(full_domain, 'A')
                for answer in answers:
                    ip_str = str(answer)
                    if not is_private_ip_address(ip_str):
                        print(f"    {Fore.GREEN}✓ {full_domain}{Style.RESET_ALL} -> {Fore.CYAN}{answer}{Style.RESET_ALL}")
                        found_subdomains.append((full_domain, str(answer)))
                        break
            except:
                pass
        
        # Query certificate transparency logs for REAL subdomain data
        ct_subdomains = query_certificate_transparency(domain)

        # Try DNS enumeration with wildcards
        print(f"\n{Fore.GREEN}[+] Wildcard Test:{Style.RESET_ALL}")
        try:
            wildcard_test = f"nonexistent-{domain.replace('.', '-')}.{domain}"
            dns.resolver.resolve(wildcard_test, 'A')
            print(f"    {Fore.YELLOW}⚠️  Wildcard DNS detected - results may include false positives{Style.RESET_ALL}")
        except:
            print(f"    {Fore.GREEN}✓ No wildcard DNS detected{Style.RESET_ALL}")
        
        # Results summary
        if ct_subdomains:
            print(f"\n{Fore.GREEN}[+] CT-Log Subdomains (resolved now):{Style.RESET_ALL}")
            for sub in ct_subdomains[:25]:
                full = f"{sub}.{domain}"
                try:
                    answers = dns.resolver.resolve(full, 'A')
                    ip = str(answers[0])
                    print(f"    {Fore.GREEN}✓ {full}{Style.RESET_ALL} -> {Fore.CYAN}{ip}{Style.RESET_ALL}")
                    if (full, ip) not in found_subdomains:
                        found_subdomains.append((full, ip))
                except Exception:
                    print(f"    {Fore.YELLOW}? {full}{Style.RESET_ALL} {Fore.BLUE}(in CT log, no current A record){Style.RESET_ALL}")

        if found_subdomains:
            print(f"\n{Fore.GREEN}[+] Discovery Summary:{Style.RESET_ALL}")
            print(f"    Found Subdomains: {Fore.YELLOW}{len(found_subdomains)}{Style.RESET_ALL}")
            
            print(f"\n{Fore.GREEN}[+] All Discovered Subdomains:{Style.RESET_ALL}")
            for subdomain, ip in found_subdomains:
                print(f"    {Fore.CYAN}{subdomain:<30} {Fore.YELLOW}{ip}{Style.RESET_ALL}")
        else:
            print(f"\n{Fore.YELLOW}[!] No subdomains found using common prefixes{Style.RESET_ALL}")
        
        # Additional tools suggestions
        print(f"\n{Fore.GREEN}[+] Advanced Tools:{Style.RESET_ALL}")
        print(f"    {Fore.CYAN}• Use subfinder, amass, or sublist3r for comprehensive scanning{Style.RESET_ALL}")
        print(f"    {Fore.CYAN}• Check DNS brute force tools like dnsrecon{Style.RESET_ALL}")
        print(f"    {Fore.CYAN}• Monitor passive DNS databases{Style.RESET_ALL}")
        
    except Exception as e:
        print(f"{Fore.RED}[ERROR] Unexpected error in subdomain discovery: {str(e)}{Style.RESET_ALL}")

def query_certificate_transparency(domain):
    """Query crt.sh certificate-transparency logs for real subdomain names.

    Returns a sorted list of unique subdomains (may include historic hosts).
    """
    import time
    import requests

    print(f"\n{Fore.GREEN}[+] Certificate Transparency Logs (crt.sh):{Style.RESET_ALL}")
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    resp = None
    # crt.sh is chronically overloaded (502/503) — one polite retry
    for attempt in (1, 2):
        try:
            resp = requests.get(url, timeout=30,
                                headers={'User-Agent': 'BloodRecon-OSINT/1.0'})
            if resp.status_code == 200:
                break
        except requests.RequestException:
            resp = None
        if attempt == 1:
            print(f"    {Fore.CYAN}crt.sh busy — retrying once...{Style.RESET_ALL}")
            time.sleep(2)
    try:
        if resp is None or resp.status_code != 200:
            code = resp.status_code if resp is not None else 'unreachable'
            print(f"    {Fore.RED}✗ crt.sh unavailable (status {code}){Style.RESET_ALL}")
            print(f"    {Fore.CYAN}Manual check: https://crt.sh/?q={domain}{Style.RESET_ALL}")
            return []

        entries = resp.json()
        names = set()
        for entry in entries:
            # name_value holds newline-separated SANs for the certificate
            raw = entry.get('name_value', '') or ''
            for name in raw.split('\n'):
                name = name.strip().lower().lstrip('*.')
                if name.endswith('.' + domain) and name != domain:
                    names.add(name)

        print(f"    {Fore.GREEN}✓ {len(names)} unique subdomains found in CT logs{Style.RESET_ALL}")
        return sorted(names)

    except requests.RequestException as e:
        print(f"    {Fore.RED}✗ crt.sh request failed: {str(e)}{Style.RESET_ALL}")
    except ValueError:
        print(f"    {Fore.RED}✗ crt.sh returned invalid JSON{Style.RESET_ALL}")
    return []


def is_private_ip_address(ip):
    """Check if IP address is private/internal"""
    try:
        parts = ip.split('.')
        if len(parts) != 4:
            return False
        
        first = int(parts[0])
        second = int(parts[1])
        
        # Private IP ranges
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
        
        return False
    except:
        return False
