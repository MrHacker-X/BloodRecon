#!/usr/bin/env python3
"""
SSL Scanner Module
Analyze SSL certificates and security configurations
Author : Alex Butler (@MrHacker-X)
Org    : Vritra Security Organization
"""

import ssl
import socket
from datetime import datetime
from urllib.parse import urlparse
from bloodrecon.modules.colors import Fore, Style
import requests
import urllib3

# The scanner deliberately tests unverified/insecure TLS configurations, so
# suppress urllib3's InsecureRequestWarning noise.
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def scan_ssl_certificate(target):
    """Scan SSL certificate and security configuration"""
    try:
        print(f"\n{Fore.CYAN}╔══════════════════════════════════════════════════════════════╗")
        print(f"║                      {Fore.YELLOW}SSL SCANNER{Fore.CYAN}                             ║")
        print(f"╚══════════════════════════════════════════════════════════════╝{Style.RESET_ALL}")
        
        # Parse hostname and port
        if '://' in target:
            parsed = urlparse(target)
            hostname = parsed.hostname
            port = parsed.port or (443 if parsed.scheme == 'https' else 80)
        else:
            if ':' in target:
                hostname, port_str = target.split(':')
                port = int(port_str)
            else:
                hostname = target
                port = 443
        
        print(f"\n{Fore.GREEN}[+] SSL Certificate Analysis:{Style.RESET_ALL}")
        print(f"    Target: {Fore.YELLOW}{hostname}:{port}{Style.RESET_ALL}")
        
        # Get SSL certificate
        cert_info = get_ssl_certificate(hostname, port)
        if cert_info:
            analyze_certificate(cert_info, hostname)
            
        # Test SSL configuration
        test_ssl_configuration(hostname, port)
        
        # HTTP security headers
        test_security_headers(hostname, port)
        
    except Exception as e:
        print(f"{Fore.RED}[ERROR] Unexpected error in SSL scanning: {str(e)}{Style.RESET_ALL}")

def get_ssl_certificate(hostname, port):
    """Retrieve SSL certificate information"""
    try:
        print(f"\n{Fore.GREEN}[+] Retrieving Certificate:{Style.RESET_ALL}")
        
        context = ssl.create_default_context()
        
        with socket.create_connection((hostname, port), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                
                # Get additional certificate details
                cert_der = ssock.getpeercert(True)
                cert_pem = ssl.DER_cert_to_PEM_cert(cert_der)
                
                print(f"    {Fore.GREEN}✓ Certificate retrieved successfully{Style.RESET_ALL}")
                return cert
                
    except ssl.SSLError as e:
        print(f"    {Fore.RED}✗ SSL Error: {str(e)}{Style.RESET_ALL}")
        return None
    except socket.timeout:
        print(f"    {Fore.RED}✗ Connection timeout{Style.RESET_ALL}")
        return None
    except Exception as e:
        print(f"    {Fore.RED}✗ Error: {str(e)}{Style.RESET_ALL}")
        return None

def analyze_certificate(cert, hostname):
    """Analyze SSL certificate details"""  
    print(f"\n{Fore.GREEN}[+] Certificate Details:{Style.RESET_ALL}")
    
    # Subject information
    subject = dict(x[0] for x in cert['subject'])
    print(f"    Common Name: {Fore.CYAN}{subject.get('commonName', 'N/A')}{Style.RESET_ALL}")
    print(f"    Organization: {Fore.CYAN}{subject.get('organizationName', 'N/A')}{Style.RESET_ALL}")
    print(f"    Country: {Fore.CYAN}{subject.get('countryName', 'N/A')}{Style.RESET_ALL}")
    
    # Issuer information
    issuer = dict(x[0] for x in cert['issuer'])
    print(f"    Issued By: {Fore.YELLOW}{issuer.get('organizationName', 'N/A')}{Style.RESET_ALL}")
    print(f"    Issuer CN: {Fore.YELLOW}{issuer.get('commonName', 'N/A')}{Style.RESET_ALL}")
    
    # Validity dates
    not_before = datetime.strptime(cert['notBefore'], '%b %d %H:%M:%S %Y %Z')
    not_after = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
    now = datetime.now()
    
    print(f"    Valid From: {Fore.CYAN}{not_before.strftime('%Y-%m-%d %H:%M:%S')}{Style.RESET_ALL}")
    print(f"    Valid Until: {Fore.CYAN}{not_after.strftime('%Y-%m-%d %H:%M:%S')}{Style.RESET_ALL}")
    
    # Certificate validity status
    if now < not_before:
        print(f"    Status: {Fore.RED}Not yet valid{Style.RESET_ALL}")
    elif now > not_after:
        print(f"    Status: {Fore.RED}Expired{Style.RESET_ALL}")
    else:
        days_left = (not_after - now).days
        if days_left < 30:
            print(f"    Status: {Fore.YELLOW}Valid (expires in {days_left} days){Style.RESET_ALL}")
        else:
            print(f"    Status: {Fore.GREEN}Valid (expires in {days_left} days){Style.RESET_ALL}")
    
    # Serial number and fingerprint
    print(f"    Serial Number: {Fore.CYAN}{cert.get('serialNumber', 'N/A')}{Style.RESET_ALL}")
    print(f"    Version: {Fore.CYAN}{cert.get('version', 'N/A')}{Style.RESET_ALL}")
    
    # Subject Alternative Names
    if 'subjectAltName' in cert:
        san_names = [name[1] for name in cert['subjectAltName']]
        print(f"    Alt Names: {Fore.MAGENTA}{', '.join(san_names[:5])}{Style.RESET_ALL}")
        if len(san_names) > 5:
            print(f"               {Fore.MAGENTA}... and {len(san_names) - 5} more{Style.RESET_ALL}")
        
        # Check if hostname matches
        if hostname in san_names or subject.get('commonName') == hostname:
            print(f"    Hostname Match: {Fore.GREEN}✓ Valid{Style.RESET_ALL}")
        else:
            print(f"    Hostname Match: {Fore.RED}✗ Mismatch{Style.RESET_ALL}")

def test_ssl_configuration(hostname, port):
    """Test SSL/TLS configuration"""
    print(f"\n{Fore.GREEN}[+] SSL/TLS Configuration:{Style.RESET_ALL}")

    # Probe each TLS version explicitly using TLSVersion bounds. This works on
    # Python 3.7+ (ssl.TLSVersion) and detects TLS 1.0/1.1/1.2/1.3 correctly;
    # the old hasattr(PROTOCOL_TLSv1_3) check never existed in ssl and always
    # skipped TLS 1.3.
    versions = [
        ('TLSv1.0', ssl.TLSVersion.TLSv1, ssl.TLSVersion.TLSv1),
        ('TLSv1.1', ssl.TLSVersion.TLSv1_1, ssl.TLSVersion.TLSv1_1),
        ('TLSv1.2', ssl.TLSVersion.TLSv1_2, ssl.TLSVersion.TLSv1_2),
        ('TLSv1.3', ssl.TLSVersion.TLSv1_3, ssl.TLSVersion.TLSv1_3),
    ]

    supported_versions = []

    for version_name, min_v, max_v in versions:
        try:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            ctx.minimum_version = min_v
            ctx.maximum_version = max_v

            with socket.create_connection((hostname, port), timeout=5) as sock:
                with ctx.wrap_socket(sock, server_hostname=hostname):
                    supported_versions.append(version_name)
                    print(f"    {version_name}: {Fore.GREEN}✓ Supported{Style.RESET_ALL}")

        except (ssl.SSLError, socket.error, OSError):
            print(f"    {version_name}: {Fore.RED}✗ Not supported{Style.RESET_ALL}")

    # Security assessment
    print(f"\n{Fore.GREEN}[+] Security Assessment:{Style.RESET_ALL}")

    if 'SSLv3' in supported_versions:
        print(f"    {Fore.RED}⚠️  SSLv3 is supported (vulnerable to POODLE attack){Style.RESET_ALL}")

    if 'TLSv1.0' in supported_versions:
        print(f"    {Fore.RED}⚠️  TLSv1.0 is supported (deprecated — disable it){Style.RESET_ALL}")

    if 'TLSv1.1' in supported_versions:
        print(f"    {Fore.YELLOW}⚠️  TLSv1.1 is supported (deprecated — plan to disable){Style.RESET_ALL}")

    if 'TLSv1.3' in supported_versions:
        print(f"    {Fore.GREEN}✓ TLSv1.3 is supported (excellent){Style.RESET_ALL}")
    elif 'TLSv1.2' in supported_versions:
        print(f"    {Fore.GREEN}✓ TLSv1.2 is supported (good){Style.RESET_ALL}")

    # Print the negotiated protocol of the default handshake
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((hostname, port), timeout=10) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                proto = ssock.version() or 'Unknown'
                cipher = ssock.cipher()
                print(f"    {Fore.CYAN}Negotiated (default client): {proto}", end="")
                if cipher:
                    print(f" with {cipher[0]} ({cipher[2]}-bit)", end="")
                print(Style.RESET_ALL)
    except Exception:
        pass


def test_security_headers(hostname, port):
    """Test HTTP security headers"""
    print(f"\n{Fore.GREEN}[+] HTTP Security Headers:{Style.RESET_ALL}")
    
    try:
        # Try HTTPS first, then HTTP
        protocols = ['https', 'http'] if port == 443 else ['http', 'https']
        
        for protocol in protocols:
            try:
                url = f"{protocol}://{hostname}"
                if (protocol == 'https' and port != 443) or (protocol == 'http' and port != 80):
                    url += f":{port}"
                
                response = requests.head(url, timeout=10, verify=False, allow_redirects=True)
                break
            except:
                continue
        else:
            print(f"    {Fore.RED}✗ Could not connect to test headers{Style.RESET_ALL}")
            return
        
        # Security headers to check
        security_headers = {
            'Strict-Transport-Security': 'HSTS',
            'Content-Security-Policy': 'CSP',
            'X-Frame-Options': 'Clickjacking Protection',
            'X-Content-Type-Options': 'MIME Type Protection',
            'X-XSS-Protection': 'XSS Protection',
            'Referrer-Policy': 'Referrer Policy',
            'Permissions-Policy': 'Permissions Policy'
        }
        
        headers_found = 0
        for header, description in security_headers.items():
            if header in response.headers:
                headers_found += 1
                value = response.headers[header][:50] + '...' if len(response.headers[header]) > 50 else response.headers[header]
                print(f"    {Fore.GREEN}✓ {description}: {Fore.CYAN}{value}{Style.RESET_ALL}")
            else:
                print(f"    {Fore.RED}✗ {description}: {Fore.YELLOW}Missing{Style.RESET_ALL}")
        
        # Overall security score
        security_score = (headers_found / len(security_headers)) * 100
        
        print(f"\n{Fore.GREEN}[+] Security Headers Score:{Style.RESET_ALL}")
        if security_score >= 80:
            print(f"    Score: {Fore.GREEN}{security_score:.0f}% - Excellent{Style.RESET_ALL}")
        elif security_score >= 60:
            print(f"    Score: {Fore.YELLOW}{security_score:.0f}% - Good{Style.RESET_ALL}")
        elif security_score >= 40:
            print(f"    Score: {Fore.YELLOW}{security_score:.0f}% - Fair{Style.RESET_ALL}")
        else:
            print(f"    Score: {Fore.RED}{security_score:.0f}% - Poor{Style.RESET_ALL}")
            
    except Exception as e:
        print(f"    {Fore.RED}✗ Error testing headers: {str(e)}{Style.RESET_ALL}")

def get_cipher_info(hostname, port):
    """Get cipher suite information"""
    try:
        context = ssl.create_default_context()
        
        with socket.create_connection((hostname, port), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cipher = ssock.cipher()
                if cipher:
                    return {
                        'name': cipher[0],
                        'version': cipher[1], 
                        'bits': cipher[2]
                    }
    except:
        pass
    
    return None
