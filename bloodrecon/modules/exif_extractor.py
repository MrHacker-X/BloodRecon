#!/usr/bin/env python3
"""
EXIF Metadata Extractor
Extract geolocation and metadata from image files
Author : Alex Butler (@MrHacker-X)
Org    : Vritra Security Organization
"""

import os
import subprocess
import json
from bloodrecon.modules.colors import Fore, Style
try:
    from PIL import Image
    from PIL.ExifTags import TAGS, GPSTAGS
    PIL_AVAILABLE = True
except ImportError:
    PIL_AVAILABLE = False

def extract_exif(image_path):
    """Extract EXIF metadata from image file"""
    try:
        print(f"\n{Fore.CYAN}╔══════════════════════════════════════════════════════════════╗")
        print(f"║                  {Fore.YELLOW}EXIF METADATA EXTRACTOR{Fore.CYAN}                     ║")
        print(f"╚══════════════════════════════════════════════════════════════╝{Style.RESET_ALL}")
        
        if not PIL_AVAILABLE:
            print(f"{Fore.RED}[ERROR] PIL/Pillow not installed. Install with: pip install Pillow{Style.RESET_ALL}")
            return
        
        if not os.path.exists(image_path):
            print(f"{Fore.RED}[ERROR] Image file not found: {image_path}{Style.RESET_ALL}")
            return
        
        print(f"\n{Fore.GREEN}[+] Image Information:{Style.RESET_ALL}")
        print(f"    File: {Fore.YELLOW}{image_path}{Style.RESET_ALL}")
        print(f"    Size: {Fore.CYAN}{os.path.getsize(image_path)} bytes{Style.RESET_ALL}")
        
        try:
            # Open image and extract EXIF
            image = Image.open(image_path)
            exifdata = image.getexif()
            
            if not exifdata:
                print(f"    {Fore.RED}No EXIF data found in image{Style.RESET_ALL}")
                return
            
            print(f"\n{Fore.GREEN}[+] EXIF Metadata:{Style.RESET_ALL}")
            
            # Extract basic EXIF data
            gps_data = {}
            for tag_id in exifdata:
                tag = TAGS.get(tag_id, tag_id)
                data = exifdata.get(tag_id)
                
                # Skip binary data
                if isinstance(data, bytes):
                    continue
                
                if tag == "GPSInfo":
                    # Extract GPS data
                    for gps_tag in data:
                        gps_tag_name = GPSTAGS.get(gps_tag, gps_tag)
                        gps_data[gps_tag_name] = data[gps_tag]
                else:
                    print(f"    {tag}: {Fore.CYAN}{data}{Style.RESET_ALL}")
            
            # Process GPS data
            if gps_data:
                print(f"\n{Fore.GREEN}[+] GPS Information:{Style.RESET_ALL}")
                
                # Extract coordinates
                if 'GPSLatitude' in gps_data and 'GPSLongitude' in gps_data:
                    lat = convert_to_degrees(gps_data['GPSLatitude'])
                    lon = convert_to_degrees(gps_data['GPSLongitude'])
                    
                    # Apply direction
                    if 'GPSLatitudeRef' in gps_data and gps_data['GPSLatitudeRef'] == 'S':
                        lat = -lat
                    if 'GPSLongitudeRef' in gps_data and gps_data['GPSLongitudeRef'] == 'W':
                        lon = -lon
                    
                    print(f"    Coordinates: {Fore.YELLOW}{lat:.6f}, {lon:.6f}{Style.RESET_ALL}")
                    print(f"    Google Maps: {Fore.MAGENTA}https://maps.google.com/maps?q={lat},{lon}{Style.RESET_ALL}")
                
                # Other GPS data
                for key, value in gps_data.items():
                    if key not in ['GPSLatitude', 'GPSLongitude', 'GPSLatitudeRef', 'GPSLongitudeRef']:
                        print(f"    {key}: {Fore.CYAN}{value}{Style.RESET_ALL}")
            else:
                print(f"\n{Fore.YELLOW}[!] No GPS data found in EXIF{Style.RESET_ALL}")
        
        except Exception as e:
            print(f"{Fore.RED}[ERROR] Could not process image with PIL: {str(e)}{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}[INFO] Trying alternative methods...{Style.RESET_ALL}")
            
            # Try using exiftool as fallback
            try_exiftool_extraction(image_path)
        
    except Exception as e:
        print(f"{Fore.RED}[ERROR] Unexpected error in EXIF extraction: {str(e)}{Style.RESET_ALL}")

def try_exiftool_extraction(image_path):
    """Try extracting EXIF data using exiftool command"""
    try:
        print(f"\n{Fore.GREEN}[+] Trying ExifTool (if available):{Style.RESET_ALL}")
        
        # Check if exiftool is available
        result = subprocess.run(['which', 'exiftool'], 
                              capture_output=True, text=True, timeout=5)
        
        if result.returncode != 0:
            print(f"    {Fore.YELLOW}ExifTool not found. Install with: apt install exiftool{Style.RESET_ALL}")
            print_supported_formats()
            return
        
        # Run exiftool to extract metadata
        result = subprocess.run(['exiftool', '-json', image_path], 
                              capture_output=True, text=True, timeout=10)
        
        if result.returncode == 0 and result.stdout:
            try:
                data = json.loads(result.stdout)[0]
                
                print(f"\n{Fore.GREEN}[+] ExifTool Results:{Style.RESET_ALL}")
                
                # Filter and display relevant metadata
                important_fields = [
                    'FileName', 'FileSize', 'ImageWidth', 'ImageHeight',
                    'Make', 'Model', 'DateTime', 'GPS', 'GPSLatitude', 'GPSLongitude',
                    'Software', 'Orientation', 'XResolution', 'YResolution'
                ]
                
                for key, value in data.items():
                    if any(field.lower() in key.lower() for field in important_fields):
                        if 'GPS' in key and isinstance(value, (int, float)):
                            print(f"    {key}: {Fore.YELLOW}{value}{Style.RESET_ALL}")
                        elif not isinstance(value, dict):
                            print(f"    {key}: {Fore.CYAN}{value}{Style.RESET_ALL}")
                
                # Try to extract GPS coordinates if available
                if 'GPSLatitude' in data and 'GPSLongitude' in data:
                    lat = data['GPSLatitude']
                    lon = data['GPSLongitude']
                    
                    # Handle GPS reference
                    if 'GPSLatitudeRef' in data and data['GPSLatitudeRef'] == 'S':
                        lat = -abs(lat)
                    if 'GPSLongitudeRef' in data and data['GPSLongitudeRef'] == 'W':
                        lon = -abs(lon)
                    
                    print(f"\n{Fore.GREEN}[+] GPS Coordinates:{Style.RESET_ALL}")
                    print(f"    Coordinates: {Fore.YELLOW}{lat:.6f}, {lon:.6f}{Style.RESET_ALL}")
                    print(f"    Google Maps: {Fore.MAGENTA}https://maps.google.com/maps?q={lat},{lon}{Style.RESET_ALL}")
                
            except json.JSONDecodeError:
                print(f"    {Fore.RED}Could not parse ExifTool output{Style.RESET_ALL}")
        else:
            print(f"    {Fore.YELLOW}No EXIF data found with ExifTool{Style.RESET_ALL}")
            
    except subprocess.TimeoutExpired:
        print(f"    {Fore.RED}ExifTool command timed out{Style.RESET_ALL}")
    except Exception as e:
        print(f"    {Fore.RED}ExifTool error: {str(e)}{Style.RESET_ALL}")
        
    # Always show supported formats and recommendations
    print_supported_formats()

def print_supported_formats():
    """Print information about supported image formats"""
    print(f"\n{Fore.GREEN}[+] Supported Image Formats:{Style.RESET_ALL}")
    print(f"    {Fore.CYAN}• JPEG/JPG - Full EXIF support{Style.RESET_ALL}")
    print(f"    {Fore.CYAN}• TIFF - Full EXIF support{Style.RESET_ALL}")
    print(f"    {Fore.CYAN}• PNG - Limited metadata support{Style.RESET_ALL}")
    print(f"    {Fore.CYAN}• HEIC/HEIF - Requires ExifTool{Style.RESET_ALL}")
    print(f"    {Fore.CYAN}• RAW formats - Requires ExifTool{Style.RESET_ALL}")
    
    print(f"\n{Fore.GREEN}[+] Recommendations:{Style.RESET_ALL}")
    print(f"    {Fore.YELLOW}• Install ExifTool for better format support{Style.RESET_ALL}")
    print(f"    {Fore.YELLOW}• JPEG images typically contain the most metadata{Style.RESET_ALL}")
    print(f"    {Fore.YELLOW}• Social media platforms often strip EXIF data{Style.RESET_ALL}")
    print(f"    {Fore.YELLOW}• Screenshots usually don't contain location data{Style.RESET_ALL}")

def convert_to_degrees(value):
    """Convert GPS coordinates to decimal degrees"""
    try:
        degrees = float(value[0])
        minutes = float(value[1])
        seconds = float(value[2])
        return degrees + (minutes / 60.0) + (seconds / 3600.0)
    except:
        return 0.0
