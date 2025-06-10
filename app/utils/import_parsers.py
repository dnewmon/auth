"""
Password Manager Import Parsers

This module provides parsers for importing credentials from popular password managers.
Supports Chrome, Firefox, Safari, LastPass, 1Password, Bitwarden, Dashlane, and KeePass formats.
"""

import csv
import json
import xml.etree.ElementTree as ET
from io import StringIO
from typing import List, Dict, Any, Optional, Tuple
from abc import ABC, abstractmethod


class ImportParser(ABC):
    """Abstract base class for password manager import parsers."""
    
    @abstractmethod
    def parse(self, content: str) -> List[Dict[str, Any]]:
        """Parse the content and return a list of credential dictionaries."""
        pass
    
    @abstractmethod
    def detect_format(self, content: str) -> bool:
        """Detect if the content matches this parser's format."""
        pass
    
    @property
    @abstractmethod
    def name(self) -> str:
        """Return the name of this parser."""
        pass


class ChromeCSVParser(ImportParser):
    """Parser for Chrome/Edge/Firefox CSV exports."""
    
    def parse(self, content: str) -> List[Dict[str, Any]]:
        """Parse Chrome CSV format: name, url, username, password"""
        credentials = []
        csv_reader = csv.DictReader(StringIO(content))
        
        for row in csv_reader:
            # Chrome exports use these column names
            service_name = row.get('name', '').strip()
            service_url = row.get('url', '').strip()
            username = row.get('username', '').strip()
            password = row.get('password', '').strip()
            
            if not service_name and service_url:
                # Extract service name from URL if not provided
                service_name = self._extract_service_name(service_url)
            
            if service_name or username:  # Only import if we have at least a service name or username
                credentials.append({
                    'service_name': service_name or 'Imported Site',
                    'service_url': service_url,
                    'username': username,
                    'password': password,
                    'category': 'imported',
                    'notes': f'Imported from Chrome/Edge/Firefox'
                })
        
        return credentials
    
    def detect_format(self, content: str) -> bool:
        """Detect Chrome CSV format by checking for expected headers."""
        try:
            first_line = content.split('\n')[0].lower()
            expected_headers = ['name', 'url', 'username', 'password']
            return all(header in first_line for header in expected_headers)
        except:
            return False
    
    @property
    def name(self) -> str:
        return "Chrome/Edge/Firefox CSV"
    
    def _extract_service_name(self, url: str) -> str:
        """Extract a service name from a URL."""
        try:
            if '://' in url:
                domain = url.split('://')[1].split('/')[0]
            else:
                domain = url.split('/')[0]
            
            # Remove www. prefix and get the main domain
            if domain.startswith('www.'):
                domain = domain[4:]
            
            # Take the first part before any dots for simple naming
            return domain.split('.')[0].title()
        except:
            return 'Unknown Site'


class LastPassCSVParser(ImportParser):
    """Parser for LastPass CSV exports."""
    
    def parse(self, content: str) -> List[Dict[str, Any]]:
        """Parse LastPass CSV format: url, username, password, extra, name, grouping, fav"""
        credentials = []
        csv_reader = csv.DictReader(StringIO(content))
        
        for row in csv_reader:
            service_name = row.get('name', '').strip()
            service_url = row.get('url', '').strip()
            username = row.get('username', '').strip()
            password = row.get('password', '').strip()
            extra = row.get('extra', '').strip()
            grouping = row.get('grouping', '').strip()
            
            if not service_name and service_url:
                service_name = self._extract_service_name(service_url)
            
            # Use grouping as category if available
            category = grouping.lower() if grouping else 'imported'
            
            notes = f'Imported from LastPass'
            if extra:
                notes += f'\nExtra: {extra}'
            
            if service_name or username:
                credentials.append({
                    'service_name': service_name or 'Imported Site',
                    'service_url': service_url,
                    'username': username,
                    'password': password,
                    'category': category,
                    'notes': notes
                })
        
        return credentials
    
    def detect_format(self, content: str) -> bool:
        """Detect LastPass CSV format by checking for expected headers."""
        try:
            first_line = content.split('\n')[0].lower()
            # LastPass has distinctive headers including 'extra' and 'grouping'
            # Check for presence of 'extra' which is unique to LastPass
            return ('extra' in first_line and 
                    'url' in first_line and 
                    'username' in first_line and 
                    'password' in first_line)
        except:
            return False
    
    @property
    def name(self) -> str:
        return "LastPass CSV"
    
    def _extract_service_name(self, url: str) -> str:
        """Extract a service name from a URL."""
        try:
            if '://' in url:
                domain = url.split('://')[1].split('/')[0]
            else:
                domain = url.split('/')[0]
            
            if domain.startswith('www.'):
                domain = domain[4:]
            
            return domain.split('.')[0].title()
        except:
            return 'Unknown Site'


class OnePasswordCSVParser(ImportParser):
    """Parser for 1Password CSV exports."""
    
    def parse(self, content: str) -> List[Dict[str, Any]]:
        """Parse 1Password CSV format: Title, Website, Username, Password, Notes"""
        credentials = []
        csv_reader = csv.DictReader(StringIO(content))
        
        for row in csv_reader:
            service_name = row.get('Title', '').strip()
            service_url = row.get('Website', '').strip()
            username = row.get('Username', '').strip()
            password = row.get('Password', '').strip()
            notes = row.get('Notes', '').strip()
            
            if not service_name and service_url:
                service_name = self._extract_service_name(service_url)
            
            full_notes = f'Imported from 1Password'
            if notes:
                full_notes += f'\n{notes}'
            
            if service_name or username:
                credentials.append({
                    'service_name': service_name or 'Imported Site',
                    'service_url': service_url,
                    'username': username,
                    'password': password,
                    'category': 'imported',
                    'notes': full_notes
                })
        
        return credentials
    
    def detect_format(self, content: str) -> bool:
        """Detect 1Password CSV format by checking for expected headers."""
        try:
            first_line = content.split('\n')[0].lower()
            # 1Password uses 'Title' instead of 'name' and 'Website' instead of 'url'
            expected_headers = ['title', 'website', 'username', 'password']
            return all(header in first_line for header in expected_headers)
        except:
            return False
    
    @property
    def name(self) -> str:
        return "1Password CSV"
    
    def _extract_service_name(self, url: str) -> str:
        """Extract a service name from a URL."""
        try:
            if '://' in url:
                domain = url.split('://')[1].split('/')[0]
            else:
                domain = url.split('/')[0]
            
            if domain.startswith('www.'):
                domain = domain[4:]
            
            return domain.split('.')[0].title()
        except:
            return 'Unknown Site'


class BitwardenJSONParser(ImportParser):
    """Parser for Bitwarden JSON exports."""
    
    def parse(self, content: str) -> List[Dict[str, Any]]:
        """Parse Bitwarden JSON format."""
        credentials = []
        
        try:
            data = json.loads(content)
            items = data.get('items', [])
            
            for item in items:
                if item.get('type') != 1:  # Only process login items (type 1)
                    continue
                
                login = item.get('login', {})
                service_name = item.get('name', '').strip()
                service_url = ''
                username = login.get('username', '').strip()
                password = login.get('password', '').strip()
                notes = item.get('notes', '').strip()
                
                # Get URL from URIs array
                uris = login.get('uris', [])
                if uris and uris[0].get('uri'):
                    service_url = uris[0]['uri'].strip()
                
                if not service_name and service_url:
                    service_name = self._extract_service_name(service_url)
                
                # Get category from folder
                folder_id = item.get('folderId')
                category = 'imported'
                if folder_id and 'folders' in data:
                    for folder in data.get('folders', []):
                        if folder.get('id') == folder_id:
                            category = folder.get('name', 'imported').lower()
                            break
                
                full_notes = f'Imported from Bitwarden'
                if notes:
                    full_notes += f'\n{notes}'
                
                if service_name or username:
                    credentials.append({
                        'service_name': service_name or 'Imported Site',
                        'service_url': service_url,
                        'username': username,
                        'password': password,
                        'category': category,
                        'notes': full_notes
                    })
        
        except json.JSONDecodeError:
            raise ValueError("Invalid JSON format")
        
        return credentials
    
    def detect_format(self, content: str) -> bool:
        """Detect Bitwarden JSON format by checking for expected structure."""
        try:
            data = json.loads(content)
            return 'items' in data and 'encrypted' in data
        except:
            return False
    
    @property
    def name(self) -> str:
        return "Bitwarden JSON"
    
    def _extract_service_name(self, url: str) -> str:
        """Extract a service name from a URL."""
        try:
            if '://' in url:
                domain = url.split('://')[1].split('/')[0]
            else:
                domain = url.split('/')[0]
            
            if domain.startswith('www.'):
                domain = domain[4:]
            
            return domain.split('.')[0].title()
        except:
            return 'Unknown Site'


class BitwardenCSVParser(ImportParser):
    """Parser for Bitwarden CSV exports."""
    
    def parse(self, content: str) -> List[Dict[str, Any]]:
        """Parse Bitwarden CSV format: folder, favorite, type, name, notes, fields, login_uri, login_username, login_password, login_totp"""
        credentials = []
        csv_reader = csv.DictReader(StringIO(content))
        
        for row in csv_reader:
            if row.get('type', '').strip() != 'login':  # Only process login items
                continue
            
            service_name = row.get('name', '').strip()
            service_url = row.get('login_uri', '').strip()
            username = row.get('login_username', '').strip()
            password = row.get('login_password', '').strip()
            notes = row.get('notes', '').strip()
            folder = row.get('folder', '').strip()
            
            if not service_name and service_url:
                service_name = self._extract_service_name(service_url)
            
            category = folder.lower() if folder else 'imported'
            
            full_notes = f'Imported from Bitwarden'
            if notes:
                full_notes += f'\n{notes}'
            
            if service_name or username:
                credentials.append({
                    'service_name': service_name or 'Imported Site',
                    'service_url': service_url,
                    'username': username,
                    'password': password,
                    'category': category,
                    'notes': full_notes
                })
        
        return credentials
    
    def detect_format(self, content: str) -> bool:
        """Detect Bitwarden CSV format by checking for expected headers."""
        try:
            first_line = content.split('\n')[0].lower()
            # Bitwarden CSV has distinctive headers
            expected_headers = ['login_uri', 'login_username', 'login_password']
            return all(header in first_line for header in expected_headers)
        except:
            return False
    
    @property
    def name(self) -> str:
        return "Bitwarden CSV"
    
    def _extract_service_name(self, url: str) -> str:
        """Extract a service name from a URL."""
        try:
            if '://' in url:
                domain = url.split('://')[1].split('/')[0]
            else:
                domain = url.split('/')[0]
            
            if domain.startswith('www.'):
                domain = domain[4:]
            
            return domain.split('.')[0].title()
        except:
            return 'Unknown Site'


class KeePassXMLParser(ImportParser):
    """Parser for KeePass XML exports."""
    
    def parse(self, content: str) -> List[Dict[str, Any]]:
        """Parse KeePass XML format."""
        credentials = []
        
        try:
            root = ET.fromstring(content)
            
            # Find all Entry elements
            for entry in root.findall('.//Entry'):
                service_name = ''
                service_url = ''
                username = ''
                password = ''
                notes = ''
                
                # Parse String elements
                for string_elem in entry.findall('String'):
                    key_elem = string_elem.find('Key')
                    value_elem = string_elem.find('Value')
                    
                    if key_elem is not None and value_elem is not None:
                        key = key_elem.text
                        value = value_elem.text or ''
                        
                        if key == 'Title':
                            service_name = value
                        elif key == 'URL':
                            service_url = value
                        elif key == 'UserName':
                            username = value
                        elif key == 'Password':
                            password = value
                        elif key == 'Notes':
                            notes = value
                
                if not service_name and service_url:
                    service_name = self._extract_service_name(service_url)
                
                full_notes = f'Imported from KeePass'
                if notes:
                    full_notes += f'\n{notes}'
                
                if service_name or username:
                    credentials.append({
                        'service_name': service_name or 'Imported Site',
                        'service_url': service_url,
                        'username': username,
                        'password': password,
                        'category': 'imported',
                        'notes': full_notes
                    })
        
        except ET.ParseError:
            raise ValueError("Invalid XML format")
        
        return credentials
    
    def detect_format(self, content: str) -> bool:
        """Detect KeePass XML format by checking for expected structure."""
        try:
            content_lower = content.lower()
            return ('<?xml' in content_lower and 
                    'keepass' in content_lower and 
                    '<entry>' in content_lower)
        except:
            return False
    
    @property
    def name(self) -> str:
        return "KeePass XML"
    
    def _extract_service_name(self, url: str) -> str:
        """Extract a service name from a URL."""
        try:
            if '://' in url:
                domain = url.split('://')[1].split('/')[0]
            else:
                domain = url.split('/')[0]
            
            if domain.startswith('www.'):
                domain = domain[4:]
            
            return domain.split('.')[0].title()
        except:
            return 'Unknown Site'


class ImportManager:
    """Manager class for handling password manager imports."""
    
    def __init__(self):
        # Order matters - more specific formats should be checked first
        self.parsers = [
            BitwardenJSONParser(),      # Most specific - JSON with specific structure
            KeePassXMLParser(),         # XML format is distinctive
            LastPassCSVParser(),        # Has unique 'extra' and 'grouping' headers
            OnePasswordCSVParser(),     # Uses 'Title' and 'Website' instead of 'name' and 'url'
            BitwardenCSVParser(),       # Has unique 'login_' prefixed headers
            ChromeCSVParser(),          # Most generic - should be last
        ]
    
    def detect_format(self, content: str) -> Optional[ImportParser]:
        """Detect the format of the import content and return appropriate parser."""
        for parser in self.parsers:
            if parser.detect_format(content):
                return parser
        return None
    
    def parse_import(self, content: str, parser_name: Optional[str] = None) -> Tuple[List[Dict[str, Any]], str]:
        """
        Parse import content using automatic detection or specified parser.
        
        Returns:
            Tuple of (credentials_list, parser_name_used)
        """
        if parser_name:
            # Use specified parser
            parser = self._get_parser_by_name(parser_name)
            if not parser:
                raise ValueError(f"Unknown parser: {parser_name}")
        else:
            # Auto-detect format
            parser = self.detect_format(content)
            if not parser:
                raise ValueError("Could not detect import format. Supported formats: Chrome/Edge/Firefox CSV, LastPass CSV, 1Password CSV, Bitwarden JSON/CSV, KeePass XML")
        
        credentials = parser.parse(content)
        return credentials, parser.name
    
    def _get_parser_by_name(self, name: str) -> Optional[ImportParser]:
        """Get parser by name."""
        for parser in self.parsers:
            if parser.name.lower() == name.lower():
                return parser
        return None
    
    def get_supported_formats(self) -> List[str]:
        """Get list of supported import formats."""
        return [parser.name for parser in self.parsers]
    
    def validate_credentials(self, credentials: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Validate and clean up imported credentials.
        
        Returns:
            List of validation errors/warnings
        """
        issues = []
        
        for i, cred in enumerate(credentials):
            cred_issues = []
            
            # Check required fields
            if not cred.get('service_name'):
                cred_issues.append("Missing service name")
            
            if not cred.get('username') and not cred.get('password'):
                cred_issues.append("Missing both username and password")
            
            # Validate URL format
            service_url = cred.get('service_url', '')
            if service_url and not self._is_valid_url(service_url):
                cred_issues.append("Invalid URL format")
            
            # Check password strength (warning only)
            password = cred.get('password', '')
            if password and len(password) < 8:
                cred_issues.append("Weak password (less than 8 characters)")
            
            if cred_issues:
                issues.append({
                    'index': i,
                    'service_name': cred.get('service_name', 'Unknown'),
                    'issues': cred_issues
                })
        
        return issues
    
    def _is_valid_url(self, url: str) -> bool:
        """Basic URL validation."""
        try:
            return (url.startswith('http://') or 
                    url.startswith('https://') or 
                    '.' in url)  # Simple domain check
        except:
            return False