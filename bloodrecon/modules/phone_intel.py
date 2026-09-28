#!/usr/bin/env python3
"""
Phone Number Intelligence Module
Analyze and gather intelligence on phone numbers
Author : Alex Butler (@MrHacker-X)
Org    : Vritra Security Organization
"""

import re
try:
    from bloodrecon.modules.colors import Fore, Style
except Exception:
    # If colorama is not installed, create dummy classes so that attribute
    # accesses do not raise errors.  This allows the module to run without
    # colored output.
    class _DummyColor:
        BLACK = RED = GREEN = YELLOW = BLUE = MAGENTA = CYAN = WHITE = RESET = ""
    class _DummyStyle:
        RESET_ALL = ""
    Fore = _DummyColor()
    Style = _DummyStyle()

# Attempt to import the phonenumbers library.  This third‑party library provides
# comprehensive phone number parsing, validation and formatting.  If it isn't
# available (for example, in a restricted or offline environment), we fall back
# to basic regular‑expression based validation later on.
try:
    import phonenumbers
    from phonenumbers import geocoder, carrier, timezone
    from phonenumbers.phonenumberutil import NumberParseException
    PHONENUMBERS_AVAILABLE = True
except Exception:
    # The phonenumbers library is not installed; flag this so that callers know
    # detailed analysis will not be available.
    PHONENUMBERS_AVAILABLE = False

# Mapping of phonenumbers number type codes to human‑readable strings.  See
# https://github.com/daviddrysdale/python-phonenumbers for definitions.
NUMBER_TYPES = {
    1: "FIXED_LINE",
    2: "MOBILE",
    3: "FIXED_LINE_OR_MOBILE",
    4: "TOLL_FREE",
    5: "PREMIUM_RATE",
    6: "SHARED_COST",
    7: "VOIP",
    8: "PERSONAL_NUMBER",
    9: "PAGER",
    10: "UAN",
    11: "VOICEMAIL",
    -1: "UNKNOWN"
}

# Cache of the last detailed analysis, so helper functions reuse REAL parsed
# data instead of re-deriving or guessing it.
analysis_cache = {}


def analyze_phone_number_detailed(phone_number):
    """
    Perform a detailed analysis of a phone number using the phonenumbers library.
    Returns a dictionary of analysis results or None if the library is unavailable
    or the number cannot be parsed/validated.
    """
    if not PHONENUMBERS_AVAILABLE:
        # Without phonenumbers we cannot provide detailed analysis
        return None
    try:
        # Attempt to parse the number without specifying a region.  This works for
        # internationally formatted numbers beginning with '+'.
        parsed_number = phonenumbers.parse(phone_number, None)
        if not phonenumbers.is_valid_number(parsed_number):
            # If the international parse fails validation, attempt to parse using a
            # default region as a last resort (here we guess US).  Many national
            # numbers require a region hint to be parsed correctly.
            try:
                parsed_number = phonenumbers.parse(phone_number, "US")
                if not phonenumbers.is_valid_number(parsed_number):
                    return None
            except NumberParseException:
                # Could not parse the number at all
                return None
        # Build the analysis dictionary
        is_possible = phonenumbers.is_possible_number(parsed_number)
        is_valid = phonenumbers.is_valid_number(parsed_number)
        region_code = phonenumbers.region_code_for_number(parsed_number)
        number_type_code = phonenumbers.number_type(parsed_number)
        analysis = {
            "is_possible": is_possible,
            "is_valid": is_valid,
            "region": region_code,
            "country_code": parsed_number.country_code,
            "national_number": parsed_number.national_number,
            "extension": parsed_number.extension,
            "number_type": NUMBER_TYPES.get(number_type_code, "UNKNOWN"),
            "location": geocoder.description_for_number(parsed_number, "en"),
            "carrier": carrier.name_for_number(parsed_number, "en"),
            "time_zones": timezone.time_zones_for_number(parsed_number),
            "formats": {
                "E164": phonenumbers.format_number(parsed_number, phonenumbers.PhoneNumberFormat.E164),
                "INTERNATIONAL": phonenumbers.format_number(parsed_number, phonenumbers.PhoneNumberFormat.INTERNATIONAL),
                "NATIONAL": phonenumbers.format_number(parsed_number, phonenumbers.PhoneNumberFormat.NATIONAL),
                "RFC3966": phonenumbers.format_number(parsed_number, phonenumbers.PhoneNumberFormat.RFC3966),
            }
        }
        return analysis
    except NumberParseException:
        # Parsing error
        return None
    except Exception:
        # Catch all other unexpected errors quietly to prevent analysis from breaking
        return None

def print_detailed_analysis(analysis):
    """
    Nicely format and print the detailed analysis returned by
    analyze_phone_number_detailed().  If analysis is None, nothing is printed.
    """
    if not analysis:
        return

    # Header
    print(f"\n{Fore.CYAN}╔══════════════════════════════════════════════════════════════╗")
    print(f"║                    {Fore.YELLOW}PHONE NUMBER ANALYSIS{Fore.CYAN}                     ║")
    print(f"╚══════════════════════════════════════════════════════════════╝{Style.RESET_ALL}")

    # Validation results
    print(f"\n{Fore.GREEN}[+] Validation Results:{Style.RESET_ALL}")
    print(f"    - Is Possible: {'✓ Yes' if analysis['is_possible'] else '✗ No'}")
    print(f"    - Is Valid: {'✓ Yes' if analysis['is_valid'] else '✗ No'}")

    # Number details
    print(f"\n{Fore.GREEN}[+] Number Details:{Style.RESET_ALL}")
    region_display = analysis['region'] if analysis['region'] else 'Unknown'
    print(f"    - Country: {region_display} (+{analysis['country_code']})")
    location = analysis['location'] if analysis['location'] else 'N/A'
    print(f"    - Location: {location}")
    carrier_name = analysis['carrier'] if analysis['carrier'] else 'N/A'
    print(f"    - Carrier: {carrier_name}")
    time_zones = ', '.join(analysis['time_zones']) if analysis['time_zones'] else 'N/A'
    print(f"    - Time Zones: {time_zones}")
    print(f"    - Number Type: {analysis['number_type']}")

    # Formatting examples
    print(f"\n{Fore.GREEN}[+] Formatting Examples:{Style.RESET_ALL}")
    for format_name, formatted_number in analysis['formats'].items():
        print(f"    - {format_name}: {formatted_number}")

def analyze_phone_number(phone_number):
    """Analyze phone number and gather intelligence"""
    try:
        print(f"\n{Fore.CYAN}╔══════════════════════════════════════════════════════════════╗")
        print(f"║                     {Fore.YELLOW}PHONE NUMBER INTELLIGENCE{Fore.CYAN}                    ║")
        print(f"╚══════════════════════════════════════════════════════════════╝{Style.RESET_ALL}")
        
        # Clean phone number
        cleaned_number = clean_phone_number(phone_number)
        
        print(f"\n{Fore.GREEN}[+] Phone Number Analysis:{Style.RESET_ALL}")
        print(f"    Original: {Fore.YELLOW}{phone_number}{Style.RESET_ALL}")
        print(f"    Cleaned: {Fore.CYAN}{cleaned_number}{Style.RESET_ALL}")
        
        # Perform detailed analysis using the phonenumbers library if available.
        analysis = analyze_phone_number_detailed(cleaned_number)
        if analysis:
            # Print out the detailed breakdown (validation results, country, etc.)
            print_detailed_analysis(analysis)
            analysis_cache.clear()
            analysis_cache.update(analysis)
            is_valid = analysis['is_valid']
        else:
            # Fallback to basic regex-based validation if phonenumbers isn't available
            is_valid = validate_phone_format(cleaned_number)
            if not PHONENUMBERS_AVAILABLE:
                print(f"\n{Fore.YELLOW}[INFO] phonenumbers library not available, using basic format validation only{Style.RESET_ALL}")

        # Indicate whether the number appears valid (either via phonenumbers or regex)
        print(f"    Valid Format: {Fore.GREEN if is_valid else Fore.RED}{is_valid}{Style.RESET_ALL}")

        if is_valid:
            # Analyze number components (country code, national number)
            analyze_number_components(cleaned_number)
            # Country/region detection (approximate)
            detect_country_region(cleaned_number)
            # Real line-type analysis (MOBILE / FIXED_LINE / VOIP / TOLL_FREE...)
            check_voip_status(cleaned_number)
            # Real carrier info when numbering-plan data provides it
            analyze_carrier_info(cleaned_number)
            # Search social media presence
            search_social_media(phone_number)
        else:
            print(f"    {Fore.RED}⚠️  Invalid phone number format{Style.RESET_ALL}")
            suggest_valid_formats()
            
        # Security recommendations
        print(f"\n{Fore.GREEN}[+] Privacy & Security:{Style.RESET_ALL}")
        print(f"    {Fore.YELLOW}• Phone numbers can reveal location and carrier info{Style.RESET_ALL}")
        print(f"    {Fore.YELLOW}• Be cautious sharing personal numbers publicly{Style.RESET_ALL}")
        print(f"    {Fore.YELLOW}• Consider using secondary numbers for online services{Style.RESET_ALL}")
        
    except Exception as e:
        print(f"{Fore.RED}[ERROR] Unexpected error in phone analysis: {str(e)}{Style.RESET_ALL}")

def clean_phone_number(phone):
    """Clean and normalize phone number"""
    # Remove all non-digit characters except +
    cleaned = re.sub(r'[^\d+]', '', phone)
    return cleaned

def validate_phone_format(phone):
    """Validate phone number format"""
    # Basic validation patterns
    patterns = [
        r'^\+?1?[2-9]\d{2}[2-9]\d{2}\d{4}$',  # US/Canada
        r'^\+?44[1-9]\d{8,9}$',  # UK
        r'^\+?49[1-9]\d{7,11}$',  # Germany
        r'^\+?33[1-9]\d{8}$',  # France
        r'^\+?[1-9]\d{1,14}$'  # International format
    ]
    
    return any(re.match(pattern, phone) for pattern in patterns)

def analyze_number_components(phone):
    """Analyze phone number components"""
    print(f"\n{Fore.GREEN}[+] Number Components:{Style.RESET_ALL}")
    
    if phone.startswith('+'):
        country_code = ""
        number = phone[1:]
        
        # Extract potential country codes
        for length in [1, 2, 3]:
            if len(number) >= length:
                potential_cc = number[:length]
                if potential_cc in get_country_codes():
                    country_code = potential_cc
                    number = number[length:]
                    break
        
        if country_code:
            print(f"    Country Code: {Fore.CYAN}+{country_code}{Style.RESET_ALL}")
            print(f"    National Number: {Fore.CYAN}{number}{Style.RESET_ALL}")
        else:
            print(f"    {Fore.YELLOW}Could not parse country code{Style.RESET_ALL}")
    else:
        print(f"    {Fore.YELLOW}No international prefix detected{Style.RESET_ALL}")
        if len(phone) == 10 and phone[0] in '23456789':
            print(f"    Likely US/Canada: {Fore.CYAN}{phone[:3]}-{phone[3:6]}-{phone[6:]}{Style.RESET_ALL}")

def detect_country_region(phone):
    """Detect country/region from phone number"""
    print(f"\n{Fore.GREEN}[+] Geographic Information:{Style.RESET_ALL}")
    
    country_codes = {
        '1': 'United States/Canada',
        '7': 'Russia/Kazakhstan',
        '20': 'Egypt',
        '27': 'South Africa',
        '30': 'Greece',
        '31': 'Netherlands',
        '32': 'Belgium',
        '33': 'France',
        '34': 'Spain',
        '39': 'Italy',
        '40': 'Romania',
        '41': 'Switzerland',
        '43': 'Austria',
        '44': 'United Kingdom',
        '45': 'Denmark',
        '46': 'Sweden',
        '47': 'Norway',
        '48': 'Poland',
        '49': 'Germany',
        '52': 'Mexico',
        '55': 'Brazil',
        '61': 'Australia',
        '81': 'Japan',
        '82': 'South Korea',
        '86': 'China',
        '91': 'India'
    }
    
    if phone.startswith('+'):
        for code, country in country_codes.items():
            if phone[1:].startswith(code):
                print(f"    Country: {Fore.CYAN}{country}{Style.RESET_ALL}")
                print(f"    Country Code: {Fore.YELLOW}+{code}{Style.RESET_ALL}")
                return
    
    # US area code analysis
    if len(phone) == 10 and not phone.startswith('+'):
        area_code = phone[:3]
        region = get_us_area_code_region(area_code)
        if region:
            print(f"    Area Code: {Fore.CYAN}{area_code}{Style.RESET_ALL}")
            print(f"    Region: {Fore.YELLOW}{region}{Style.RESET_ALL}")

def get_country_codes():
    """Get list of known country codes"""
    return ['1', '7', '20', '27', '30', '31', '32', '33', '34', '39', '40', '41', '43', '44', '45', '46', '47', '48', '49', '52', '55', '61', '81', '82', '86', '91']

def get_us_area_code_region(area_code):
    """Get US region for area code"""
    area_codes = {
        '212': 'New York, NY',
        '213': 'Los Angeles, CA',
        '312': 'Chicago, IL',
        '415': 'San Francisco, CA',
        '617': 'Boston, MA',
        '713': 'Houston, TX',
        '202': 'Washington, DC',
        '305': 'Miami, FL',
        '404': 'Atlanta, GA',
        '214': 'Dallas, TX'
    }
    return area_codes.get(area_code, 'Unknown region')

def check_voip_status(phone):
    """Report the real number type from the phonenumbers library."""
    print(f"\n{Fore.GREEN}[+] Line Type Analysis:{Style.RESET_ALL}")

    # REAL data: phonenumbers.classifies the line type from allocation data.
    # No random guessing, no simulation.
    if analysis_cache.get('number_type'):
        ntype = analysis_cache['number_type']
        label = {
            'MOBILE': 'Mobile number',
            'FIXED_LINE': 'Fixed line (landline)',
            'FIXED_LINE_OR_MOBILE': 'Fixed line or mobile',
            'VOIP': 'VOIP number (internet-based)',
            'TOLL_FREE': 'Toll-free number',
            'PREMIUM_RATE': 'Premium rate number',
            'SHARED_COST': 'Shared cost number',
            'PERSONAL_NUMBER': 'Personal number',
            'PAGER': 'Pager',
            'UAN': 'Universal access number',
            'VOICEMAIL': 'Voicemail service',
        }.get(ntype, ntype)
        print(f"    Status: {Fore.CYAN}{label}{Style.RESET_ALL}")
        if ntype == 'VOIP':
            print(f"    Note: {Fore.YELLOW}VOIP numbers are frequently used for spoofing/throwaway use{Style.RESET_ALL}")
        elif ntype == 'UNKNOWN':
            print(f"    Note: {Fore.YELLOW}Line type not allocated in numbering-plan data{Style.RESET_ALL}")
    else:
        print(f"    Status: {Fore.YELLOW}Unknown (phonenumbers library unavailable){Style.RESET_ALL}")

def analyze_carrier_info(phone):
    """Report carrier information (real data when available)."""
    print(f"\n{Fore.GREEN}[+] Carrier Information:{Style.RESET_ALL}")

    if analysis_cache.get('carrier'):
        print(f"    Carrier: {Fore.CYAN}{analysis_cache['carrier']}{Style.RESET_ALL}")
    else:
        print(f"    Carrier: {Fore.YELLOW}Not available from numbering-plan data{Style.RESET_ALL}")
        print(f"    {Fore.CYAN}Tip: carrier lookups from HLR services can provide live line info{Style.RESET_ALL}")

def search_social_media(phone):
    """Search for phone number on social media"""
    print(f"\n{Fore.GREEN}[+] Social Media Search:{Style.RESET_ALL}")
    
    platforms = {
        'Facebook': f'https://www.facebook.com/search/people/?q={phone}',
        'WhatsApp': 'Manual search required',
        'Telegram': 'Check @username or add contact',
        'LinkedIn': f'https://www.linkedin.com/search/results/people/?keywords={phone}'
    }
    
    for platform, method in platforms.items():
        if method.startswith('http'):
            print(f"    🔗 {platform}: {Fore.MAGENTA}{method}{Style.RESET_ALL}")
        else:
            print(f"    📱 {platform}: {Fore.YELLOW}{method}{Style.RESET_ALL}")

def suggest_valid_formats():
    """Suggest valid phone number formats"""
    print(f"\n{Fore.GREEN}[+] Valid Formats:{Style.RESET_ALL}")
    formats = [
        '+1-555-123-4567 (US/Canada with country code)',
        '555-123-4567 (US/Canada without country code)', 
        '+44-20-7123-4567 (UK)',
        '+49-30-12345678 (Germany)',
        '+33-1-23-45-67-89 (France)'
    ]
    
    for fmt in formats:
        print(f"    {Fore.CYAN}• {fmt}{Style.RESET_ALL}")

def detect_voip_number(phone_number):
    """Specific VOIP detection function"""
    analyze_phone_number(phone_number)

def validate_phone_number(phone_number):
    """Specific phone validation function"""
    analyze_phone_number(phone_number)