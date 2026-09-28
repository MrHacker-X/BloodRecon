#!/usr/bin/env python3
"""
Document Metadata Extractor
Extract metadata from various document formats
Author : Alex Butler (@MrHacker-X)
Org    : Vritra Security Organization
"""

import os
import subprocess
import json
from datetime import datetime
from bloodrecon.modules.colors import Fore, Style
import mimetypes

def extract_document_metadata(file_path):
    """Extract metadata from document files"""
    try:
        print(f"\n{Fore.CYAN}╔══════════════════════════════════════════════════════════════╗")
        print(f"║                 {Fore.YELLOW}DOCUMENT METADATA EXTRACTOR{Fore.CYAN}                  ║")
        print(f"╚══════════════════════════════════════════════════════════════╝{Style.RESET_ALL}")
        
        if not os.path.exists(file_path):
            print(f"{Fore.RED}[ERROR] File not found: {file_path}{Style.RESET_ALL}")
            return
        
        print(f"\n{Fore.GREEN}[+] File Information:{Style.RESET_ALL}")
        print(f"    Path: {Fore.YELLOW}{file_path}{Style.RESET_ALL}")
        print(f"    Size: {Fore.CYAN}{format_file_size(os.path.getsize(file_path))}{Style.RESET_ALL}")
        
        # Detect file type
        file_type = detect_file_type(file_path)
        print(f"    Type: {Fore.CYAN}{file_type}{Style.RESET_ALL}")
        
        # Extract basic file system metadata
        extract_filesystem_metadata(file_path)
        
        # Try different extraction methods
        try_exiftool_extraction(file_path)
        
        # Format-specific extraction
        lower_path = file_path.lower()
        if lower_path.endswith('.pdf'):
            extract_pdf_metadata(file_path)
        elif lower_path.endswith(('.docx', '.doc')):
            extract_office_metadata(file_path)
        elif lower_path.endswith(('.xlsx', '.xls')):
            extract_office_metadata(file_path)
        elif lower_path.endswith(('.pptx', '.ppt')):
            extract_office_metadata(file_path)
        
        # Security analysis
        analyze_metadata_security(file_path)
        
    except Exception as e:
        print(f"{Fore.RED}[ERROR] Unexpected error in metadata extraction: {str(e)}{Style.RESET_ALL}")

def detect_file_type(file_path):
    """Detect file type using multiple methods"""
    try:
        # Use mimetypes
        mime_type, _ = mimetypes.guess_type(file_path)
        if mime_type:
            return mime_type
        
        # Use file extension
        _, ext = os.path.splitext(file_path)
        return f"File extension: {ext}" if ext else "Unknown"
        
    except Exception:
        return "Unknown"

def format_file_size(size_bytes):
    """Format file size in human readable format"""
    if size_bytes == 0:
        return "0 B"
    
    size_names = ["B", "KB", "MB", "GB", "TB"]
    i = 0
    while size_bytes >= 1024 and i < len(size_names) - 1:
        size_bytes /= 1024.0
        i += 1
    
    return f"{size_bytes:.2f} {size_names[i]}"

def extract_filesystem_metadata(file_path):
    """Extract file system metadata"""
    try:
        print(f"\n{Fore.GREEN}[+] File System Metadata:{Style.RESET_ALL}")
        
        stat = os.stat(file_path)
        
        # Timestamps
        created_time = datetime.fromtimestamp(stat.st_ctime)
        modified_time = datetime.fromtimestamp(stat.st_mtime)
        accessed_time = datetime.fromtimestamp(stat.st_atime)
        
        print(f"    Created: {Fore.YELLOW}{created_time.strftime('%Y-%m-%d %H:%M:%S')}{Style.RESET_ALL}")
        print(f"    Modified: {Fore.YELLOW}{modified_time.strftime('%Y-%m-%d %H:%M:%S')}{Style.RESET_ALL}")
        print(f"    Accessed: {Fore.YELLOW}{accessed_time.strftime('%Y-%m-%d %H:%M:%S')}{Style.RESET_ALL}")
        
        # Permissions
        print(f"    Permissions: {Fore.CYAN}{oct(stat.st_mode)[-3:]}{Style.RESET_ALL}")
        print(f"    Owner UID: {Fore.CYAN}{stat.st_uid}{Style.RESET_ALL}")
        print(f"    Group GID: {Fore.CYAN}{stat.st_gid}{Style.RESET_ALL}")
        
    except Exception as e:
        print(f"{Fore.RED}[ERROR] Failed to extract filesystem metadata: {str(e)}{Style.RESET_ALL}")

def try_exiftool_extraction(file_path):
    """Try extracting metadata using exiftool"""
    try:
        print(f"\n{Fore.GREEN}[+] ExifTool Metadata:{Style.RESET_ALL}")
        
        # Check if exiftool is available
        result = subprocess.run(['which', 'exiftool'], 
                              capture_output=True, text=True, timeout=5)
        
        if result.returncode != 0:
            print(f"    {Fore.YELLOW}ExifTool not found. Install with: apt install libimage-exiftool-perl{Style.RESET_ALL}")
            return
        
        # Run exiftool
        result = subprocess.run(['exiftool', '-json', '-all', file_path], 
                              capture_output=True, text=True, timeout=15)
        
        if result.returncode == 0 and result.stdout:
            try:
                data = json.loads(result.stdout)[0]
                
                # Important metadata fields
                important_fields = [
                    'Title', 'Subject', 'Author', 'Creator', 'Producer', 'CreationDate',
                    'ModifyDate', 'CreateDate', 'Software', 'Application', 'Company',
                    'LastModifiedBy', 'RevisionNumber', 'TotalEditTime', 'Template',
                    'Keywords', 'Comments', 'Category', 'Manager', 'HyperlinkBase'
                ]
                
                metadata_found = False
                for key, value in data.items():
                    if any(field.lower() in key.lower() for field in important_fields):
                        if isinstance(value, str) and value.strip():
                            print(f"    {key}: {Fore.CYAN}{value}{Style.RESET_ALL}")
                            metadata_found = True
                        elif not isinstance(value, str) and value:
                            print(f"    {key}: {Fore.CYAN}{value}{Style.RESET_ALL}")
                            metadata_found = True
                
                if not metadata_found:
                    print(f"    {Fore.YELLOW}No significant metadata found{Style.RESET_ALL}")
                    
            except json.JSONDecodeError:
                print(f"    {Fore.RED}Could not parse ExifTool output{Style.RESET_ALL}")
        else:
            print(f"    {Fore.YELLOW}ExifTool extraction failed or no metadata found{Style.RESET_ALL}")
            
    except subprocess.TimeoutExpired:
        print(f"    {Fore.RED}ExifTool command timed out{Style.RESET_ALL}")
    except Exception as e:
        print(f"    {Fore.RED}ExifTool error: {str(e)}{Style.RESET_ALL}")

def extract_pdf_metadata(file_path):
    """Extract PDF-specific metadata"""
    try:
        print(f"\n{Fore.GREEN}[+] PDF Metadata Analysis:{Style.RESET_ALL}")
        
        # Try using pdfinfo if available
        try:
            result = subprocess.run(['pdfinfo', file_path], 
                                  capture_output=True, text=True, timeout=10)
            
            if result.returncode == 0:
                print(f"    {Fore.CYAN}PDF Information:{Style.RESET_ALL}")
                for line in result.stdout.split('\n'):
                    if ':' in line and line.strip():
                        key, value = line.split(':', 1)
                        print(f"      {key.strip()}: {Fore.YELLOW}{value.strip()}{Style.RESET_ALL}")
            else:
                print(f"    {Fore.YELLOW}pdfinfo not available or failed{Style.RESET_ALL}")
                
        except subprocess.TimeoutExpired:
            print(f"    {Fore.RED}pdfinfo command timed out{Style.RESET_ALL}")
        except FileNotFoundError:
            print(f"    {Fore.YELLOW}pdfinfo not installed. Install with: apt install poppler-utils{Style.RESET_ALL}")
            
    except Exception as e:
        print(f"{Fore.RED}[ERROR] PDF metadata extraction failed: {str(e)}{Style.RESET_ALL}")

def extract_office_metadata(file_path):
    """Extract Microsoft Office document metadata"""
    try:
        print(f"\n{Fore.GREEN}[+] Office Document Analysis:{Style.RESET_ALL}")
        
        # For modern Office formats (.docx, .xlsx, .pptx), these are ZIP files
        if file_path.lower().endswith(('.docx', '.xlsx', '.pptx')):
            analyze_office_zip_structure(file_path)
        
        print(f"    {Fore.CYAN}Use ExifTool output above for detailed Office metadata{Style.RESET_ALL}")
        
    except Exception as e:
        print(f"{Fore.RED}[ERROR] Office metadata extraction failed: {str(e)}{Style.RESET_ALL}")

def analyze_office_zip_structure(file_path):
    """Analyze Office document ZIP structure"""
    try:
        # Office documents are ZIP files - we can list their contents
        result = subprocess.run(['unzip', '-l', file_path], 
                              capture_output=True, text=True, timeout=10)
        
        if result.returncode == 0:
            print(f"    {Fore.CYAN}Document Structure:{Style.RESET_ALL}")
            lines = result.stdout.split('\n')
            for line in lines:
                if 'core.xml' in line or 'app.xml' in line or 'custom.xml' in line:
                    print(f"      {Fore.YELLOW}• {line.strip()}{Style.RESET_ALL}")
                    
    except Exception as e:
        print(f"    {Fore.YELLOW}Could not analyze ZIP structure: {str(e)}{Style.RESET_ALL}")

def analyze_metadata_security(file_path):
    """Analyze metadata for security implications"""
    try:
        print(f"\n{Fore.GREEN}[+] Security Analysis:{Style.RESET_ALL}")
        
        # Get file size for analysis
        file_size = os.path.getsize(file_path)
        
        security_notes = []
        
        # Check for potentially sensitive metadata
        if file_size > 0:
            security_notes.append("Document contains metadata that may reveal:")
            security_notes.append("  • Author information and system details")
            security_notes.append("  • Creation and modification timestamps")
            security_notes.append("  • Software versions used")
            security_notes.append("  • Document revision history")
            security_notes.append("  • File paths and system information")
        
        # Recommendations
        print(f"    {Fore.YELLOW}Security Considerations:{Style.RESET_ALL}")
        for note in security_notes:
            print(f"    {Fore.CYAN}{note}{Style.RESET_ALL}")
        
        print(f"\n    {Fore.GREEN}Recommendations:{Style.RESET_ALL}")
        print(f"    {Fore.CYAN}• Remove metadata before sharing documents{Style.RESET_ALL}")
        print(f"    {Fore.CYAN}• Use 'Document Inspector' in Office applications{Style.RESET_ALL}")
        print(f"    {Fore.CYAN}• Consider PDF/A format for long-term storage{Style.RESET_ALL}")
        print(f"    {Fore.CYAN}• Review metadata policies in your organization{Style.RESET_ALL}")
        
        # Tools for metadata removal
        print(f"\n    {Fore.GREEN}Metadata Removal Tools:{Style.RESET_ALL}")
        tools = [
            "ExifTool: exiftool -all= file.pdf",
            "qpdf: qpdf --linearize input.pdf output.pdf",
            "Microsoft Office: File > Info > Inspect Document",
            "LibreOffice: File > Properties > Reset Properties"
        ]
        
        for tool in tools:
            print(f"    {Fore.MAGENTA}• {tool}{Style.RESET_ALL}")
            
    except Exception as e:
        print(f"{Fore.RED}[ERROR] Security analysis failed: {str(e)}{Style.RESET_ALL}")
