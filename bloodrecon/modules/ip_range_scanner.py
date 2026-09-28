#!/usr/bin/env python3
"""
IP Range Scanner Module
Scan a range of IP addresses to find active hosts (concurrent TCP connect /
ICMP ping with a hard host-count safety cap).

Author : Alex Butler (@MrHacker-X)
Org    : Vritra Security Organization
"""

import ipaddress
import socket
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor
from bloodrecon.modules.colors import Fore, Style

MAX_HOSTS = 4096          # hard safety cap so /8 scans don't run for days
SCAN_WORKERS = 64         # concurrent probes
PING_TIMEOUT = 1          # seconds
TCP_PROBE_PORTS = [80, 443, 22]  # ports tried when ICMP is unavailable


def _probe_ping(ip):
    """Ping one IP. Returns True when the host answered."""
    try:
        if sys.platform.startswith('win'):
            # -n count, -w timeout (milliseconds)
            cmd = ["ping", "-n", "1", "-w", str(PING_TIMEOUT * 1000), str(ip)]
        else:
            # -c count, -W timeout (seconds) — iputils/BusyBox/BSD compatible
            cmd = ["ping", "-c", "1", "-W", str(PING_TIMEOUT), str(ip)]
        result = subprocess.run(
            cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=PING_TIMEOUT + 2
        )
        return result.returncode == 0
    except (subprocess.TimeoutExpired, OSError, FileNotFoundError):
        return False


def _probe_tcp(ip, port):
    """Try a TCP connect; returns True when the port is open."""
    try:
        with socket.create_connection((str(ip), port), timeout=1.5):
            return True
    except OSError:
        return False


def _probe_host(ip):
    """Probe one host: ping first, TCP fallback on the common ports."""
    if _probe_ping(ip):
        return str(ip), "ping"
    for port in TCP_PROBE_PORTS:
        if _probe_tcp(ip, port):
            return str(ip), f"tcp/{port}"
    return None


def scan_ip_range(ip_range):
    """Scan a range of IP addresses and display live hosts."""
    try:
        print(f"\n{Fore.CYAN}╔══════════════════════════════════════════════════════════════╗")
        print(f"║                      {Fore.YELLOW}IP RANGE SCANNER{Fore.CYAN}                        ║")
        print(f"╚══════════════════════════════════════════════════════════════╝{Style.RESET_ALL}")

        print(f"\n{Fore.GREEN}[+] Scanning IP Range: {Fore.YELLOW}{ip_range}{Style.RESET_ALL}")

        # Parse the IP range
        try:
            network = ipaddress.ip_network(ip_range, strict=False)
        except ValueError as e:
            print(f"{Fore.RED}[ERROR] Invalid IP range: {str(e)}{Style.RESET_ALL}")
            return

        hosts = list(network.hosts()) if network.num_addresses > 2 else [network.network_address]

        if len(hosts) > MAX_HOSTS:
            print(f"{Fore.YELLOW}[!] Range contains {len(hosts):,} hosts — capped to first {MAX_HOSTS:,}.")
            print(f"    Scan a narrower range (e.g. /24) for full coverage.{Style.RESET_ALL}")
            hosts = hosts[:MAX_HOSTS]

        print(f"    {Fore.CYAN}Probing {len(hosts)} hosts with {SCAN_WORKERS} workers "
              f"(ping + tcp/{','.join(map(str, TCP_PROBE_PORTS))})...{Style.RESET_ALL}")

        active_hosts = []
        with ThreadPoolExecutor(max_workers=SCAN_WORKERS) as pool:
            for result in pool.map(_probe_host, hosts):
                if result:
                    ip, method = result
                    active_hosts.append(ip)
                    print(f"    {Fore.GREEN}✓ Active: {ip}{Style.RESET_ALL} {Fore.BLUE}({method}){Style.RESET_ALL}")

        print(f"\n{Fore.GREEN}[+] Scan Complete. Active Hosts: {len(active_hosts)}{Style.RESET_ALL}")
        for host in active_hosts:
            print(f"    {Fore.CYAN}{host}{Style.RESET_ALL}")

        if not active_hosts:
            print(f"    {Fore.YELLOW}No active hosts found{Style.RESET_ALL}")
            print(f"    {Fore.YELLOW}Note: hosts may still drop ICMP and all probed ports —")
            print(f"    a full TCP scan (e.g. nmap) covers more.{Style.RESET_ALL}")

    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}[!] Scan interrupted by user{Style.RESET_ALL}")
    except Exception as e:
        print(f"{Fore.RED}[ERROR] Unexpected error in IP range scan: {str(e)}{Style.RESET_ALL}")
