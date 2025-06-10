"""
Tests for password manager import parsers and functionality.
"""

import pytest
import json
from unittest.mock import patch, Mock

from app.utils.import_parsers import (
    ImportManager, ChromeCSVParser, LastPassCSVParser, OnePasswordCSVParser,
    BitwardenJSONParser, BitwardenCSVParser, KeePassXMLParser
)


class TestChromeCSVParser:
    """Tests for Chrome/Edge/Firefox CSV parser."""
    
    def test_parse_chrome_csv(self):
        """Test parsing Chrome CSV format."""
        content = """name,url,username,password
Gmail,https://gmail.com,user@gmail.com,password123
Facebook,https://facebook.com,myuser,fb_pass
GitHub,https://github.com,developer,dev_password"""
        
        parser = ChromeCSVParser()
        credentials = parser.parse(content)
        
        assert len(credentials) == 3
        assert credentials[0]['service_name'] == 'Gmail'
        assert credentials[0]['service_url'] == 'https://gmail.com'
        assert credentials[0]['username'] == 'user@gmail.com'
        assert credentials[0]['password'] == 'password123'
        assert credentials[0]['category'] == 'imported'
        assert 'Chrome/Edge/Firefox' in credentials[0]['notes']
    
    def test_detect_chrome_format(self):
        """Test Chrome format detection."""
        parser = ChromeCSVParser()
        
        # Valid Chrome format
        content = "name,url,username,password\nGmail,https://gmail.com,user,pass"
        assert parser.detect_format(content) == True
        
        # Missing required headers
        content = "title,website,user,pass\nGmail,https://gmail.com,user,pass"
        assert parser.detect_format(content) == False
    
    def test_extract_service_name_from_url(self):
        """Test service name extraction from URL."""
        parser = ChromeCSVParser()
        
        assert parser._extract_service_name("https://www.google.com/mail") == "Google"
        assert parser._extract_service_name("facebook.com") == "Facebook"
        assert parser._extract_service_name("invalid-url") == "Invalid-Url"


class TestLastPassCSVParser:
    """Tests for LastPass CSV parser."""
    
    def test_parse_lastpass_csv(self):
        """Test parsing LastPass CSV format."""
        content = """url,username,password,extra,name,grouping,fav
https://gmail.com,user@gmail.com,password123,Notes here,Gmail,Email,0
https://facebook.com,myuser,fb_pass,,Facebook,Social,1"""
        
        parser = LastPassCSVParser()
        credentials = parser.parse(content)
        
        assert len(credentials) == 2
        assert credentials[0]['service_name'] == 'Gmail'
        assert credentials[0]['category'] == 'email'
        assert 'Notes here' in credentials[0]['notes']
        assert credentials[1]['category'] == 'social'
    
    def test_detect_lastpass_format(self):
        """Test LastPass format detection."""
        parser = LastPassCSVParser()
        
        # Valid LastPass format
        content = "url,username,password,extra,name,grouping\nhttp://test.com,user,pass,notes,Test,Work"
        assert parser.detect_format(content) == True
        
        # Missing required headers
        content = "name,url,username,password\nTest,http://test.com,user,pass"
        assert parser.detect_format(content) == False


class TestOnePasswordCSVParser:
    """Tests for 1Password CSV parser."""
    
    def test_parse_1password_csv(self):
        """Test parsing 1Password CSV format."""
        content = """Title,Website,Username,Password,Notes
Gmail,https://gmail.com,user@gmail.com,password123,Important email account
Facebook,https://facebook.com,myuser,fb_pass,Social media"""
        
        parser = OnePasswordCSVParser()
        credentials = parser.parse(content)
        
        assert len(credentials) == 2
        assert credentials[0]['service_name'] == 'Gmail'
        assert credentials[0]['service_url'] == 'https://gmail.com'
        assert 'Important email account' in credentials[0]['notes']
        assert '1Password' in credentials[0]['notes']
    
    def test_detect_1password_format(self):
        """Test 1Password format detection."""
        parser = OnePasswordCSVParser()
        
        # Valid 1Password format
        content = "Title,Website,Username,Password,Notes\nGmail,https://gmail.com,user,pass,notes"
        assert parser.detect_format(content) == True
        
        # Chrome format (different headers)
        content = "name,url,username,password\nGmail,https://gmail.com,user,pass"
        assert parser.detect_format(content) == False


class TestBitwardenJSONParser:
    """Tests for Bitwarden JSON parser."""
    
    def test_parse_bitwarden_json(self):
        """Test parsing Bitwarden JSON format."""
        content = json.dumps({
            "encrypted": False,
            "folders": [
                {"id": "folder1", "name": "Work"},
                {"id": "folder2", "name": "Personal"}
            ],
            "items": [
                {
                    "id": "item1",
                    "type": 1,  # Login type
                    "name": "Gmail",
                    "notes": "Work email",
                    "folderId": "folder1",
                    "login": {
                        "username": "user@gmail.com",
                        "password": "password123",
                        "uris": [{"uri": "https://gmail.com"}]
                    }
                },
                {
                    "id": "item2", 
                    "type": 2,  # Note type (should be skipped)
                    "name": "Important Note"
                }
            ]
        })
        
        parser = BitwardenJSONParser()
        credentials = parser.parse(content)
        
        assert len(credentials) == 1  # Only login items processed
        assert credentials[0]['service_name'] == 'Gmail'
        assert credentials[0]['service_url'] == 'https://gmail.com'
        assert credentials[0]['category'] == 'work'
        assert 'Work email' in credentials[0]['notes']
    
    def test_detect_bitwarden_json_format(self):
        """Test Bitwarden JSON format detection."""
        parser = BitwardenJSONParser()
        
        # Valid Bitwarden JSON
        content = '{"items": [], "encrypted": false}'
        assert parser.detect_format(content) == True
        
        # Invalid JSON
        content = "not json"
        assert parser.detect_format(content) == False


class TestBitwardenCSVParser:
    """Tests for Bitwarden CSV parser."""
    
    def test_parse_bitwarden_csv(self):
        """Test parsing Bitwarden CSV format."""
        content = """folder,favorite,type,name,notes,fields,login_uri,login_username,login_password,login_totp
Work,0,login,Gmail,Work email,,https://gmail.com,user@gmail.com,password123,
Personal,1,login,Facebook,Social media,,https://facebook.com,myuser,fb_pass,"""
        
        parser = BitwardenCSVParser()
        credentials = parser.parse(content)
        
        assert len(credentials) == 2
        assert credentials[0]['service_name'] == 'Gmail'
        assert credentials[0]['category'] == 'work'
        assert credentials[1]['category'] == 'personal'
    
    def test_detect_bitwarden_csv_format(self):
        """Test Bitwarden CSV format detection."""
        parser = BitwardenCSVParser()
        
        # Valid Bitwarden CSV
        content = "folder,type,name,login_uri,login_username,login_password\nWork,login,Test,http://test.com,user,pass"
        assert parser.detect_format(content) == True
        
        # Chrome format
        content = "name,url,username,password\nTest,http://test.com,user,pass"
        assert parser.detect_format(content) == False


class TestKeePassXMLParser:
    """Tests for KeePass XML parser."""
    
    def test_parse_keepass_xml(self):
        """Test parsing KeePass XML format."""
        content = """<?xml version="1.0" encoding="utf-8"?>
<KeePassFile>
    <Root>
        <Group>
            <Entry>
                <String>
                    <Key>Title</Key>
                    <Value>Gmail</Value>
                </String>
                <String>
                    <Key>UserName</Key>
                    <Value>user@gmail.com</Value>
                </String>
                <String>
                    <Key>Password</Key>
                    <Value>password123</Value>
                </String>
                <String>
                    <Key>URL</Key>
                    <Value>https://gmail.com</Value>
                </String>
                <String>
                    <Key>Notes</Key>
                    <Value>Work email account</Value>
                </String>
            </Entry>
        </Group>
    </Root>
</KeePassFile>"""
        
        parser = KeePassXMLParser()
        credentials = parser.parse(content)
        
        assert len(credentials) == 1
        assert credentials[0]['service_name'] == 'Gmail'
        assert credentials[0]['service_url'] == 'https://gmail.com'
        assert credentials[0]['username'] == 'user@gmail.com'
        assert credentials[0]['password'] == 'password123'
        assert 'Work email account' in credentials[0]['notes']
    
    def test_detect_keepass_xml_format(self):
        """Test KeePass XML format detection."""
        parser = KeePassXMLParser()
        
        # Valid KeePass XML
        content = '<?xml version="1.0"?><KeePassFile><Entry></Entry></KeePassFile>'
        assert parser.detect_format(content) == True
        
        # Regular XML without KeePass structure
        content = '<?xml version="1.0"?><root><item></item></root>'
        assert parser.detect_format(content) == False


class TestImportManager:
    """Tests for the ImportManager class."""
    
    def test_auto_detect_chrome_format(self):
        """Test automatic detection of Chrome format."""
        content = "name,url,username,password\nGmail,https://gmail.com,user,pass"
        
        manager = ImportManager()
        parser = manager.detect_format(content)
        
        assert parser is not None
        assert parser.name == "Chrome/Edge/Firefox CSV"
    
    def test_auto_detect_lastpass_format(self):
        """Test automatic detection of LastPass format."""
        content = "url,username,password,extra,name,grouping\nhttp://test.com,user,pass,notes,Test,Work"
        
        manager = ImportManager()
        parser = manager.detect_format(content)
        
        assert parser is not None
        assert parser.name == "LastPass CSV"
    
    def test_parse_import_with_auto_detection(self):
        """Test parsing with automatic format detection."""
        content = "name,url,username,password\nGmail,https://gmail.com,user@gmail.com,password123"
        
        manager = ImportManager()
        credentials, detected_format = manager.parse_import(content)
        
        assert detected_format == "Chrome/Edge/Firefox CSV"
        assert len(credentials) == 1
        assert credentials[0]['service_name'] == 'Gmail'
    
    def test_parse_import_with_specified_format(self):
        """Test parsing with specified format."""
        content = "name,url,username,password\nGmail,https://gmail.com,user@gmail.com,password123"
        
        manager = ImportManager()
        credentials, detected_format = manager.parse_import(content, "Chrome/Edge/Firefox CSV")
        
        assert detected_format == "Chrome/Edge/Firefox CSV"
        assert len(credentials) == 1
    
    def test_parse_import_unknown_format(self):
        """Test parsing with unknown format."""
        content = "unknown,format,headers\ndata,data,data"
        
        manager = ImportManager()
        
        with pytest.raises(ValueError, match="Could not detect import format"):
            manager.parse_import(content)
    
    def test_validate_credentials(self):
        """Test credential validation."""
        credentials = [
            {
                'service_name': 'Gmail',
                'username': 'user@gmail.com',
                'password': 'password123',
                'service_url': 'https://gmail.com'
            },
            {
                'service_name': '',  # Missing service name
                'username': '',      # Missing username
                'password': '',      # Missing password
                'service_url': 'invalid-url'  # Invalid URL
            },
            {
                'service_name': 'Weak',
                'username': 'user',
                'password': 'weak',  # Weak password
                'service_url': 'https://weak.com'
            }
        ]
        
        manager = ImportManager()
        issues = manager.validate_credentials(credentials)
        
        assert len(issues) == 2  # Second and third credentials have issues
        assert 'Missing service name' in issues[0]['issues']
        assert 'Missing both username and password' in issues[0]['issues']
        assert 'Weak password (less than 8 characters)' in issues[1]['issues']
    
    def test_get_supported_formats(self):
        """Test getting supported formats."""
        manager = ImportManager()
        formats = manager.get_supported_formats()
        
        expected_formats = [
            "Chrome/Edge/Firefox CSV",
            "LastPass CSV",
            "1Password CSV", 
            "Bitwarden JSON",
            "Bitwarden CSV",
            "KeePass XML"
        ]
        
        assert all(fmt in formats for fmt in expected_formats)
        assert len(formats) == len(expected_formats)