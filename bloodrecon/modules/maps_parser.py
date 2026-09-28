#!/usr/bin/env python3
"""
Google Maps Link Parser Module
Parse and extract location information from Google Maps links and coordinates
Author : Alex Butler (@MrHacker-X)
Org    : Vritra Security Organization
"""

import re
import requests
from bloodrecon.modules.colors import Fore, Style
from urllib.parse import urlparse, parse_qs, unquote
import json

def parse_google_maps_link(link):
    """Parse and extract location data with improved logic"""
    """Main function to parse Google Maps links and extract location data"""
    try:
        print(f"\n{Fore.CYAN}╔══════════════════════════════════════════════════════════════╗")
        print(f"║                   {Fore.YELLOW}GOOGLE MAPS LINK PARSER{Fore.CYAN}                    ║")
        print(f"╚══════════════════════════════════════════════════════════════╝{Style.RESET_ALL}")
        
        print(f"\n{Fore.GREEN}[+] Parsing Google Maps link:{Style.RESET_ALL}")
        print(f"    {Fore.CYAN}{link}{Style.RESET_ALL}")
        
        # Extract location data from different Google Maps URL formats
        location_data = extract_location_from_url(link)
        
        if location_data:
            display_location_information(location_data)
            generate_alternative_links(location_data)
            provide_location_analysis(location_data)
        else:
            print(f"\n{Fore.RED}[ERROR] Could not extract location data from the provided link{Style.RESET_ALL}")
            print_supported_formats()
        
        provide_maps_recommendations()
        
    except Exception as e:
        print(f"{Fore.RED}[ERROR] Maps link parsing failed: {str(e)}{Style.RESET_ALL}")

def extract_location_from_url(url):
    """Extract location data from various Google Maps URL formats"""
    try:
        location_data = {}
        
        # Decode URL
        url = unquote(url)
        parsed_url = urlparse(url)
        
        print(f"\n{Fore.GREEN}[+] Analyzing URL components:{Style.RESET_ALL}")
        print(f"    {Fore.CYAN}Domain: {parsed_url.netloc}{Style.RESET_ALL}")
        print(f"    {Fore.CYAN}Path: {parsed_url.path}{Style.RESET_ALL}")
        print(f"    {Fore.CYAN}Query: {parsed_url.query[:100]}...{Style.RESET_ALL}")
        
        # Method 1: Extract from @coordinates format
        coords_match = re.search(r'@([+-]?\d+\.?\d*),([+-]?\d+\.?\d*)', url)
        if coords_match:
            latitude = float(coords_match.group(1))
            longitude = float(coords_match.group(2))
            location_data['latitude'] = latitude
            location_data['longitude'] = longitude
            location_data['source'] = 'coordinates'
            print(f"    {Fore.GREEN}✓ Found coordinates in @ format{Style.RESET_ALL}")
        
        # Method 2: Extract from ll parameter
        query_params = parse_qs(parsed_url.query)
        if 'll' in query_params:
            ll_value = query_params['ll'][0]
            ll_coords = ll_value.split(',')
            if len(ll_coords) == 2:
                try:
                    latitude = float(ll_coords[0])
                    longitude = float(ll_coords[1])
                    location_data['latitude'] = latitude
                    location_data['longitude'] = longitude
                    location_data['source'] = 'll_parameter'
                    print(f"    {Fore.GREEN}✓ Found coordinates in ll parameter{Style.RESET_ALL}")
                except ValueError:
                    pass
        
        # Method 3: Extract from query parameter
        if 'q' in query_params:
            query_value = query_params['q'][0]
            location_data['query'] = query_value
            
            # Try to extract coordinates from query
            query_coords = re.search(r'([+-]?\d+\.?\d*),([+-]?\d+\.?\d*)', query_value)
            if query_coords:
                latitude = float(query_coords.group(1))
                longitude = float(query_coords.group(2))
                location_data['latitude'] = latitude
                location_data['longitude'] = longitude
                location_data['source'] = 'query_coordinates'
                print(f"    {Fore.GREEN}✓ Found coordinates in query parameter{Style.RESET_ALL}")
        
        # Method 4: Extract from place_id
        if 'place_id' in query_params:
            location_data['place_id'] = query_params['place_id'][0]
            print(f"    {Fore.GREEN}✓ Found Google Place ID{Style.RESET_ALL}")
        
        # Method 5: Extract from data parameter (complex format)
        if 'data' in query_params:
            data_value = query_params['data'][0]
            location_data['data_parameter'] = data_value
            
            # Try to extract coordinates from data parameter
            data_coords = re.search(r'([+-]?\d+\.?\d*),([+-]?\d+\.?\d*)', data_value)
            if data_coords:
                latitude = float(data_coords.group(1))
                longitude = float(data_coords.group(2))
                location_data['latitude'] = latitude
                location_data['longitude'] = longitude
                location_data['source'] = 'data_parameter'
                print(f"    {Fore.GREEN}✓ Found coordinates in data parameter{Style.RESET_ALL}")
        
        # Method 6: Extract zoom level
        zoom_match = re.search(r'[,@](\d+\.?\d*)z', url)
        if zoom_match:
            location_data['zoom'] = float(zoom_match.group(1))
            print(f"    {Fore.GREEN}✓ Found zoom level{Style.RESET_ALL}")
        
        # Method 7: Extract place name from path
        if '/place/' in parsed_url.path:
            place_path = parsed_url.path.split('/place/')[-1]
            place_name = place_path.split('/')[0].replace('+', ' ')
            location_data['place_name'] = unquote(place_name)
            print(f"    {Fore.GREEN}✓ Found place name{Style.RESET_ALL}")
        
        # Method 8: Extract from search queries
        if '/search/' in parsed_url.path:
            search_query = parsed_url.path.split('/search/')[-1]
            location_data['search_query'] = unquote(search_query.replace('+', ' '))
            print(f"    {Fore.GREEN}✓ Found search query{Style.RESET_ALL}")
        
        # Method 9: Extract directions information
        if '/dir/' in parsed_url.path:
            location_data['type'] = 'directions'
            dir_parts = parsed_url.path.split('/dir/')[-1].split('/')
            if len(dir_parts) >= 2:
                location_data['origin'] = unquote(dir_parts[0].replace('+', ' '))
                location_data['destination'] = unquote(dir_parts[1].replace('+', ' '))
                print(f"    {Fore.GREEN}✓ Found directions information{Style.RESET_ALL}")
        
        return location_data if location_data else None
        
    except Exception as e:
        print(f"    {Fore.RED}✗ Error extracting location data: {str(e)}{Style.RESET_ALL}")
        return None

def display_location_information(location_data):
    """Display extracted location information"""
    try:
        print(f"\n{Fore.GREEN}[+] Extracted Location Information:{Style.RESET_ALL}")
        
        # Display coordinates
        if 'latitude' in location_data and 'longitude' in location_data:
            lat = location_data['latitude']
            lon = location_data['longitude']
            print(f"    {Fore.CYAN}Coordinates: {lat}, {lon}{Style.RESET_ALL}")
            print(f"    {Fore.CYAN}Source: {location_data.get('source', 'Unknown')}{Style.RESET_ALL}")
            
            # Convert to different coordinate formats
            print_coordinate_formats(lat, lon)
        
        # Display place information
        if 'place_name' in location_data:
            print(f"    {Fore.CYAN}Place Name: {location_data['place_name']}{Style.RESET_ALL}")
        
        if 'search_query' in location_data:
            print(f"    {Fore.CYAN}Search Query: {location_data['search_query']}{Style.RESET_ALL}")
        
        if 'query' in location_data:
            print(f"    {Fore.CYAN}Query Parameter: {location_data['query']}{Style.RESET_ALL}")
        
        if 'place_id' in location_data:
            print(f"    {Fore.CYAN}Google Place ID: {location_data['place_id']}{Style.RESET_ALL}")
        
        if 'zoom' in location_data:
            print(f"    {Fore.CYAN}Zoom Level: {location_data['zoom']}{Style.RESET_ALL}")
        
        # Display directions information
        if 'type' in location_data and location_data['type'] == 'directions':
            print(f"    {Fore.YELLOW}Type: Directions{Style.RESET_ALL}")
            if 'origin' in location_data:
                print(f"    {Fore.CYAN}Origin: {location_data['origin']}{Style.RESET_ALL}")
            if 'destination' in location_data:
                print(f"    {Fore.CYAN}Destination: {location_data['destination']}{Style.RESET_ALL}")
        
    except Exception as e:
        print(f"    {Fore.RED}✗ Error displaying location information: {str(e)}{Style.RESET_ALL}")

def print_coordinate_formats(latitude, longitude):
    """Print coordinates in different formats"""
    try:
        print(f"\n{Fore.GREEN}[+] Coordinate Formats:{Style.RESET_ALL}")
        
        # Decimal degrees
        print(f"    {Fore.CYAN}Decimal Degrees: {latitude}, {longitude}{Style.RESET_ALL}")
        
        # Degrees, minutes, seconds
        def dd_to_dms(dd):
            degrees = int(dd)
            minutes = int((abs(dd) - abs(degrees)) * 60)
            seconds = ((abs(dd) - abs(degrees)) * 60 - minutes) * 60
            return degrees, minutes, seconds
        
        lat_deg, lat_min, lat_sec = dd_to_dms(latitude)
        lon_deg, lon_min, lon_sec = dd_to_dms(longitude)
        
        lat_dir = 'N' if latitude >= 0 else 'S'
        lon_dir = 'E' if longitude >= 0 else 'W'
        
        print(f"    {Fore.CYAN}DMS: {abs(lat_deg)}°{lat_min}'{lat_sec:.2f}\"{lat_dir}, {abs(lon_deg)}°{lon_min}'{lon_sec:.2f}\"{lon_dir}{Style.RESET_ALL}")
        
        # Military Grid Reference System (simplified)
        print(f"    {Fore.CYAN}Plus Codes: (Approximate area){Style.RESET_ALL}")
        
        # What3Words format note
        print(f"    {Fore.YELLOW}Note: For What3Words, use their official API{Style.RESET_ALL}")
        
    except Exception as e:
        print(f"    {Fore.RED}✗ Error converting coordinate formats: {str(e)}{Style.RESET_ALL}")

def generate_alternative_links(location_data):
    """Generate alternative map service links"""
    try:
        if 'latitude' not in location_data or 'longitude' not in location_data:
            return
        
        lat = location_data['latitude']
        lon = location_data['longitude']
        zoom = location_data.get('zoom', 15)
        
        print(f"\n{Fore.GREEN}[+] Alternative Map Service Links:{Style.RESET_ALL}")
        
        # Google Maps
        google_url = f"https://www.google.com/maps/@{lat},{lon},{zoom}z"
        print(f"    {Fore.CYAN}Google Maps: {google_url}{Style.RESET_ALL}")
        
        # OpenStreetMap
        osm_url = f"https://www.openstreetmap.org/#map={int(zoom)}/{lat}/{lon}"
        print(f"    {Fore.CYAN}OpenStreetMap: {osm_url}{Style.RESET_ALL}")
        
        # Bing Maps
        bing_url = f"https://www.bing.com/maps?cp={lat}~{lon}&lvl={int(zoom)}"
        print(f"    {Fore.CYAN}Bing Maps: {bing_url}{Style.RESET_ALL}")
        
        # Apple Maps
        apple_url = f"https://maps.apple.com/?ll={lat},{lon}&z={int(zoom)}"
        print(f"    {Fore.CYAN}Apple Maps: {apple_url}{Style.RESET_ALL}")
        
        # Waze
        waze_url = f"https://www.waze.com/ul?ll={lat}%2C{lon}&navigate=yes"
        print(f"    {Fore.CYAN}Waze: {waze_url}{Style.RESET_ALL}")
        
        # Here Maps
        here_url = f"https://wego.here.com/?map={lat},{lon},{int(zoom)}"
        print(f"    {Fore.CYAN}HERE Maps: {here_url}{Style.RESET_ALL}")
        
    except Exception as e:
        print(f"    {Fore.RED}✗ Error generating alternative links: {str(e)}{Style.RESET_ALL}")

def provide_location_analysis(location_data):
    """Provide analysis and insights about the location"""
    try:
        if 'latitude' not in location_data or 'longitude' not in location_data:
            return
        
        lat = location_data['latitude']
        lon = location_data['longitude']
        
        print(f"\n{Fore.GREEN}[+] Location Analysis:{Style.RESET_ALL}")
        
        # Hemisphere analysis
        lat_hemisphere = "Northern" if lat >= 0 else "Southern"
        lon_hemisphere = "Eastern" if lon >= 0 else "Western"
        print(f"    {Fore.CYAN}Hemisphere: {lat_hemisphere} Latitude, {lon_hemisphere} Longitude{Style.RESET_ALL}")
        
        # Approximate region based on coordinates
        analyze_approximate_region(lat, lon)
        
        # Time zone estimation (very basic)
        estimate_timezone(lon)
        
        # Distance calculations from major cities
        calculate_distances_to_major_cities(lat, lon)
        
    except Exception as e:
        print(f"    {Fore.RED}✗ Error analyzing location: {str(e)}{Style.RESET_ALL}")

def analyze_approximate_region(lat, lon):
    """Analyze approximate geographical region"""
    try:
        # Very basic region analysis
        if lat >= 23.5:
            if lat >= 66.5:
                region = "Arctic"
            else:
                region = "Northern Temperate Zone"
        elif lat >= -23.5:
            region = "Tropical Zone"
        elif lat >= -66.5:
            region = "Southern Temperate Zone"
        else:
            region = "Antarctic"
        
        print(f"    {Fore.CYAN}Climate Zone: {region}{Style.RESET_ALL}")
        
        # Continent estimation (very rough)
        if -180 <= lon <= -30:
            if lat >= 15:
                continent = "North America"
            else:
                continent = "South America"
        elif -30 < lon <= 60:
            if lat >= 35:
                continent = "Europe"
            elif lat >= -35:
                continent = "Africa"
            else:
                continent = "Antarctica"
        elif 60 < lon <= 180:
            if lat >= 10:
                continent = "Asia"
            elif lat >= -10:
                continent = "Asia/Australia"
            else:
                continent = "Australia/Oceania"
        else:
            continent = "Unknown"
        
        print(f"    {Fore.CYAN}Estimated Continent: {continent}{Style.RESET_ALL}")
        
    except Exception as e:
        print(f"    {Fore.RED}✗ Error analyzing region: {str(e)}{Style.RESET_ALL}")

def estimate_timezone(longitude):
    """Estimate timezone based on longitude"""
    try:
        # Very rough timezone estimation (15 degrees per hour)
        timezone_offset = longitude / 15
        
        if timezone_offset >= 0:
            tz_str = f"UTC+{timezone_offset:.1f}"
        else:
            tz_str = f"UTC{timezone_offset:.1f}"
        
        print(f"    {Fore.CYAN}Estimated Timezone: {tz_str} (approximate){Style.RESET_ALL}")
        
    except Exception as e:
        print(f"    {Fore.RED}✗ Error estimating timezone: {str(e)}{Style.RESET_ALL}")

def calculate_distances_to_major_cities(lat, lon):
    """Calculate distances to major world cities"""
    try:
        import math
        
        major_cities = [
            ("New York", 40.7128, -74.0060),
            ("London", 51.5074, -0.1278),
            ("Tokyo", 35.6762, 139.6503),
            ("Sydney", -33.8688, 151.2093),
            ("Dubai", 25.2048, 55.2708),
            ("Los Angeles", 34.0522, -118.2437)
        ]
        
        def haversine_distance(lat1, lon1, lat2, lon2):
            """Calculate the great circle distance between two points"""
            R = 6371  # Earth's radius in kilometers
            
            lat1, lon1, lat2, lon2 = map(math.radians, [lat1, lon1, lat2, lon2])
            dlat = lat2 - lat1
            dlon = lon2 - lon1
            
            a = math.sin(dlat/2)**2 + math.cos(lat1) * math.cos(lat2) * math.sin(dlon/2)**2
            c = 2 * math.asin(math.sqrt(a))
            
            return R * c
        
        print(f"    {Fore.CYAN}Distances to Major Cities:{Style.RESET_ALL}")
        
        distances = []
        for city_name, city_lat, city_lon in major_cities:
            distance = haversine_distance(lat, lon, city_lat, city_lon)
            distances.append((city_name, distance))
        
        # Sort by distance and show closest 3
        distances.sort(key=lambda x: x[1])
        for city_name, distance in distances[:3]:
            print(f"      {Fore.YELLOW}• {city_name}: {distance:.0f} km{Style.RESET_ALL}")
        
    except Exception as e:
        print(f"    {Fore.RED}✗ Error calculating distances: {str(e)}{Style.RESET_ALL}")

def print_supported_formats():
    """Print supported Google Maps URL formats"""
    print(f"\n{Fore.GREEN}[+] Supported Google Maps URL Formats:{Style.RESET_ALL}")
    print(f"    {Fore.YELLOW}• https://www.google.com/maps/@lat,lng,zoom{Style.RESET_ALL}")
    print(f"    {Fore.YELLOW}• https://maps.google.com/maps?q=lat,lng{Style.RESET_ALL}")
    print(f"    {Fore.YELLOW}• https://www.google.com/maps/place/Place+Name{Style.RESET_ALL}")
    print(f"    {Fore.YELLOW}• https://maps.google.com/maps?ll=lat,lng{Style.RESET_ALL}")
    print(f"    {Fore.YELLOW}• https://www.google.com/maps/dir/Origin/Destination{Style.RESET_ALL}")
    print(f"    {Fore.YELLOW}• https://maps.google.com/maps?place_id=ChIJ...{Style.RESET_ALL}")

def provide_maps_recommendations():
    """Provide recommendations for maps analysis"""
    print(f"\n{Fore.GREEN}[+] Maps Analysis Recommendations:{Style.RESET_ALL}")
    print(f"    {Fore.CYAN}• Cross-reference coordinates with satellite imagery{Style.RESET_ALL}")
    print(f"    {Fore.CYAN}• Use Street View for ground-level reconnaissance{Style.RESET_ALL}")
    print(f"    {Fore.CYAN}• Check historical imagery for changes over time{Style.RESET_ALL}")
    print(f"    {Fore.CYAN}• Analyze nearby points of interest and landmarks{Style.RESET_ALL}")
    print(f"    {Fore.CYAN}• Consider privacy implications of location data{Style.RESET_ALL}")
    print(f"    {Fore.CYAN}• Verify coordinates with multiple mapping services{Style.RESET_ALL}")
    
    print(f"\n{Fore.GREEN}[+] OSINT Applications:{Style.RESET_ALL}")
    print(f"    {Fore.CYAN}• Geolocate photos using visible landmarks{Style.RESET_ALL}")
    print(f"    {Fore.CYAN}• Track movement patterns from multiple locations{Style.RESET_ALL}")
    print(f"    {Fore.CYAN}• Identify businesses and organizations at locations{Style.RESET_ALL}")
    print(f"    {Fore.CYAN}• Analyze transportation routes and accessibility{Style.RESET_ALL}")
    print(f"    {Fore.CYAN}• Cross-reference with social media check-ins{Style.RESET_ALL}")

def parse_coordinates_string(coord_string):
    """Parse coordinate string in various formats"""
    try:
        print(f"\n{Fore.GREEN}[+] Parsing coordinate string: {coord_string}{Style.RESET_ALL}")
        
        # Try different coordinate formats
        formats = [
            # Decimal degrees: 40.7128, -74.0060
            r'([+-]?\d+\.?\d*),\s*([+-]?\d+\.?\d*)',
            # DMS: 40°42'46.0"N 74°00'21.6"W
            r'(\d+)°(\d+)\'(\d+\.?\d*)"([NS])\s+(\d+)°(\d+)\'(\d+\.?\d*)"([EW])',
            # DM: 40°42.767'N 74°0.36'W
            r'(\d+)°(\d+\.?\d*)"([NS])\s+(\d+)°(\d+\.?\d*)"([EW])'
        ]
        
        for format_pattern in formats:
            match = re.search(format_pattern, coord_string)
            if match:
                print(f"    {Fore.GREEN}✓ Matched coordinate format{Style.RESET_ALL}")
                # Process based on format...
                break
        
        return None
        
    except Exception as e:
        print(f"    {Fore.RED}✗ Error parsing coordinates: {str(e)}{Style.RESET_ALL}")
        return None

# Export functions for use in main tool
__all__ = ['parse_google_maps_link', 'parse_coordinates_string']
