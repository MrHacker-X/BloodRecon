#!/usr/bin/env python3
"""
Module Registry for BloodRecon
Single source of truth: every module's menu id, name, category, CLI flag,
example target and runner. bloodrecon.py builds the interactive menu, the
argparse tree and the dispatch map from this table — no duplication.

Author : Alex Butler (@MrHacker-X)
Org    : Vritra Security Organization
"""

import os


def _wordlist(name):
    """Absolute path to a bundled wordlist."""
    return os.path.join(os.path.dirname(os.path.abspath(__file__)), 'list-imp', name)


# (id, module_name, callable_name, pretty name, category, cli_flag, example)
# ids follow CATEGORY_ORDER so menu numbers run sequentially down each section
_MODULES = [
    # ── network (1-9) ──────────────────────────────────────────────
    (1,  'ip_lookup',           'analyze_ip',                  'IP Address Intelligence',     'network',  '--ip',           '8.8.8.8'),
    (2,  'whois_lookup',        'get_whois_info',              'WHOIS Domain Lookup',         'network',  '--whois',        'example.com'),
    (3,  'dns_lookup',          'get_dns_records',             'DNS Records Analysis',        'network',  '--dns',          'google.com'),
    (4,  'reverse_dns',         'reverse_lookup',              'Reverse DNS Lookup',          'network',  '--reverse',      '8.8.8.8'),
    (5,  'port_scanner',        'scan_ports',                  'Port Scanner',                'network',  '--ports',        'scanme.nmap.org'),
    (6,  'ip_range_scanner',    'scan_ip_range',               'IP Range Scanner',            'network',  '--ip-scan',      '192.168.1.0/24'),
    (7,  'ssl_scanner',         'scan_ssl_certificate',        'SSL Certificate Scanner',     'network',  '--ssl',          'example.com:443'),
    (8,  'asn_resolver',        'resolve_asn_to_ranges',       'ASN to IP Range Resolver',    'network',  '--asn',          'AS15169'),
    (9,  'isp_tracker',         'track_ip_to_isp',             'IP to ISP Tracker',           'network',  '--isp',          '8.8.8.8'),
    # ── webapp (10-18) ─────────────────────────────────────────────
    (10, 'http_headers',        'get_headers',                 'HTTP Headers Analysis',       'webapp',   '--headers',      'https://example.com'),
    (11, 'robots_scanner',      'scan_robots',                 'Robots.txt Scanner',          'webapp',   '--robots',       'https://example.com'),
    (12, 'url_analyzer',        'analyze_url',                 'URL Threat Analysis',         'webapp',   '--url',          'https://example.com'),
    (13, 'useragent_detector',  'analyze_useragent',           'User-Agent Analyzer',         'webapp',   '--useragent',    'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'),
    (14, 'tech_fingerprint',    'fingerprint_technology',      'Technology Fingerprint',      'webapp',   '--tech',         'https://example.com'),
    (15, 'directory_bruteforce','bruteforce_directories',      'Directory Bruteforcer',       'webapp',   '--dir-brute',    'https://example.com'),
    (16, 'js_endpoint_scanner', 'scan_js_endpoints',           'JavaScript Endpoint Scanner', 'webapp',   '--js-endpoints', 'https://example.com'),
    (17, 'sitemap_parser',      'parse_sitemap',               'Sitemap Parser',              'webapp',   '--sitemap',      'https://example.com'),
    (18, 'favicon_hash',        'generate_favicon_hash',       'Favicon Hash Identifier',     'webapp',   '--favicon',      'https://example.com'),
    # ── search (19-26) ─────────────────────────────────────────────
    (19, 'wayback_machine',     'search_wayback',              'Wayback Machine Search',      'search',   '--wayback',      'example.com'),
    (20, 'leak_search',         'search_leaks',                'Data Breach Search',          'search',   '--leak',         'user@example.com'),
    (21, 'subdomain_finder',    'find_subdomains',             'Subdomain Discovery',         'search',   '--subdomains',   'example.com'),
    (22, 'google_dorking',      'perform_dorking',             'Google Dorking',              'search',   '--dork',         'site:example.com filetype:pdf'),
    (23, 'pastebin_search',     'search_pastebin',             'Pastebin Dump Search',        'search',   '--pastebin',     'password'),
    (24, 'google_drive_leaks',  'search_google_drive_leaks',   'Google Drive Leak Finder',    'search',   '--gdrive',       'folderID'),
    (25, 'common_crawl',        'search_common_crawl',         'Common Crawl Data Search',    'search',   '--common-crawl', 'example.com'),
    (26, 'maps_parser',         'parse_google_maps_link',      'Google Maps Link Parser',     'search',   '--maps',         'https://maps.google.com/?q=51.5074,-0.1278'),
    # ── people (27-29) ─────────────────────────────────────────────
    (27, 'social_checker',      'check_username',              'Social Media Checker',        'people',   '--social',       'johndoe'),
    (28, 'github_intel',        'analyze_github_target',       'GitHub Intelligence',         'people',   '--github',       'octocat'),
    (29, 'phone_intel',         'analyze_phone_number',        'Phone Number Intelligence',   'people',   '--phone',        '+14155552671'),
    # ── comms (30-31) ──────────────────────────────────────────────
    (30, 'email_validator',     'validate_email',              'Email Validation',            'comms',    '--email',        'user@example.com'),
    (31, 'temp_email_checker',  'check_temp_email',            'Temp Email Detector',         'comms',    '--temp-email',   'test@10minutemail.com'),
    # ── docs (32-33) ───────────────────────────────────────────────
    (32, 'exif_extractor',      'extract_exif',                'EXIF Metadata Extractor',     'docs',     '--exif',         '/path/to/photo.jpg'),
    (33, 'doc_metadata',        'extract_document_metadata',   'Document Metadata Extractor', 'docs',     '--metadata',     '/path/to/document.pdf'),
    # ── threat (34) ────────────────────────────────────────────────
    (34, 'shodan_lookup',       'search_shodan_host',          'Shodan Intelligence Lookup',  'threat',   '--shodan',       '8.8.8.8'),
]

# directory-bruteforce gets the bundled wordlist automatically
_WORDLIST_RUNNERS = {'directory_bruteforce'}

CATEGORY_ORDER = ['network', 'webapp', 'search', 'people', 'comms', 'docs', 'threat']
CATEGORY_LABELS = {
    'network': '🌐 Network & Infrastructure',
    'webapp':  '🔒 Web Application Security',
    'search':  '🔎 Search & Discovery',
    'people':  '👥 People & Social Intel',
    'comms':   '📧 Communication Intelligence',
    'docs':    '📄 Document & Metadata',
    'threat':  '🛡️  Threat Intelligence',
}

CATEGORY_SHORT = {
    'network': 'Network', 'webapp': 'WebApp', 'search': 'Search',
    'people': 'People', 'comms': 'Comms', 'docs': 'Docs', 'threat': 'Threat',
}


def category_ranges():
    """[(short_label, 'lo-hi')] per category, in menu order — for the menu legend."""
    out = []
    for cat in CATEGORY_ORDER:
        ids = [m['id'] for m in REGISTRY if m['category'] == cat]
        if not ids:
            continue
        lo, hi = min(ids), max(ids)
        out.append((CATEGORY_SHORT[cat], f"{lo}-{hi}" if hi > lo else str(lo)))
    return out

REGISTRY = [dict(zip(
    ('id', 'module', 'func', 'name', 'category', 'flag', 'example'), m))
    for m in _MODULES
]

BY_ID = {m['id']: m for m in REGISTRY}
BY_FLAG = {m['flag']: m for m in REGISTRY}


def runner_args(entry):
    """Extra positional args a runner needs (e.g. the dirbrute wordlist)."""
    if entry['module'] in _WORDLIST_RUNNERS:
        return [_wordlist('common.txt')]
    return []


def cli_flags():
    """{flag: example} for argparse construction."""
    return {m['flag']: m['example'] for m in REGISTRY}
