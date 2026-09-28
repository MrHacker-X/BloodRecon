#!/usr/bin/env python3
"""
Port Scanner Module
Basic TCP port scanner for common ports
Author : Alex Butler (@MrHacker-X)
Org    : Vritra Security Organization
"""

import socket
import threading
from bloodrecon.modules.colors import Fore, Style
import time

def scan_ports(target):
    """Scan common TCP ports on target"""
    try:
        print(f"\n{Fore.CYAN}╔══════════════════════════════════════════════════════════════╗")
        print(f"║                       {Fore.YELLOW}PORT SCANNER{Fore.CYAN}                           ║")
        print(f"╚══════════════════════════════════════════════════════════════╝{Style.RESET_ALL}")
        
        # Common ports to scan
        common_ports = [
            21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 993, 995, 
            1723, 3306, 3389, 5432, 5900, 8080, 8443
        ]
        
        port_names = {
            21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP', 53: 'DNS',
            80: 'HTTP', 110: 'POP3', 135: 'RPC', 139: 'NetBIOS',
            143: 'IMAP', 443: 'HTTPS', 993: 'IMAPS', 995: 'POP3S',
            1723: 'PPTP', 3306: 'MySQL', 3389: 'RDP', 5432: 'PostgreSQL',
            5900: 'VNC', 8080: 'HTTP-Alt', 8443: 'HTTPS-Alt'
        }
        
        print(f"\n{Fore.GREEN}[+] Port Scan Results:{Style.RESET_ALL}")
        print(f"    Target: {Fore.YELLOW}{target}{Style.RESET_ALL}")
        
        open_ports = []
        
        def scan_port(port):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(2)
                result = sock.connect_ex((target, port))
                sock.close()
                
                if result == 0:
                    service = port_names.get(port, 'Unknown')
                    print(f"    Port {Fore.GREEN}{port:5}{Style.RESET_ALL} - {Fore.CYAN}{service:12}{Style.RESET_ALL} - {Fore.GREEN}Open{Style.RESET_ALL}")
                    open_ports.append(port)
            except Exception as e:
                pass
        
        # Use threading for faster scanning
        threads = []
        for port in common_ports:
            thread = threading.Thread(target=scan_port, args=(port,))
            thread.start()
            threads.append(thread)
        
        # Wait for all threads to complete
        for thread in threads:
            thread.join()
        
        if open_ports:
            print(f"\n{Fore.GREEN}[+] Summary:{Style.RESET_ALL}")
            print(f"    Open Ports: {Fore.YELLOW}{', '.join(map(str, open_ports))}{Style.RESET_ALL}")
            print(f"    Total Open: {Fore.YELLOW}{len(open_ports)}{Style.RESET_ALL}")
        else:
            print(f"\n{Fore.RED}[!] No open ports found on common ports{Style.RESET_ALL}")
        
    except Exception as e:
        print(f"{Fore.RED}[ERROR] Unexpected error in port scanner: {str(e)}{Style.RESET_ALL}")
