"""
Breach monitoring utilities for checking if credentials have been compromised.
Integrates with HaveIBeenPwned API to check password hashes against known breaches.
"""

import hashlib
import requests
import time
from typing import Tuple, Optional
from flask import current_app


class BreachMonitor:
    """Service for checking passwords against known breaches using HaveIBeenPwned API."""
    
    HIBP_API_URL = "https://api.pwnedpasswords.com/range/"
    
    @staticmethod
    def hash_password(password: str) -> str:
        """Hash password using SHA-1 for HaveIBeenPwned API."""
        return hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    
    @staticmethod
    def check_password_breach(password: str) -> Tuple[bool, int]:
        """
        Check if a password has been found in known data breaches.
        
        Args:
            password: The password to check
            
        Returns:
            Tuple of (is_breached: bool, breach_count: int)
        """
        try:
            # Hash the password and split into prefix and suffix
            password_hash = BreachMonitor.hash_password(password)
            hash_prefix = password_hash[:5]
            hash_suffix = password_hash[5:]
            
            # Query HaveIBeenPwned API with prefix
            response = requests.get(
                f"{BreachMonitor.HIBP_API_URL}{hash_prefix}",
                timeout=10,
                headers={
                    'User-Agent': 'PasswordManager-BreachCheck/1.0'
                }
            )
            
            if response.status_code == 200:
                # Parse response to find our hash suffix
                for line in response.text.splitlines():
                    suffix, count = line.split(':')
                    if suffix == hash_suffix:
                        return True, int(count)
                
                # Hash not found in breaches
                return False, 0
                
            elif response.status_code == 404:
                # No matches found for this prefix
                return False, 0
                
            else:
                current_app.logger.warning(f"HaveIBeenPwned API returned status {response.status_code}")
                return False, 0
                
        except requests.RequestException as e:
            current_app.logger.error(f"Error checking password breach: {e}")
            return False, 0
        except Exception as e:
            current_app.logger.error(f"Unexpected error in breach check: {e}")
            return False, 0
    
    @staticmethod
    def check_email_breach(email: str) -> Tuple[bool, list]:
        """
        Check if an email address has been involved in known breaches.
        
        Args:
            email: The email address to check
            
        Returns:
            Tuple of (is_breached: bool, breach_list: list)
        """
        try:
            response = requests.get(
                f"https://haveibeenpwned.com/api/v3/breachedaccount/{email}",
                timeout=10,
                headers={
                    'User-Agent': 'PasswordManager-BreachCheck/1.0',
                    'hibp-api-key': current_app.config.get('HIBP_API_KEY', '')
                }
            )
            
            if response.status_code == 200:
                breaches = response.json()
                return True, [breach['Name'] for breach in breaches]
            elif response.status_code == 404:
                return False, []
            else:
                current_app.logger.warning(f"HaveIBeenPwned email API returned status {response.status_code}")
                return False, []
                
        except requests.RequestException as e:
            current_app.logger.error(f"Error checking email breach: {e}")
            return False, []
        except Exception as e:
            current_app.logger.error(f"Unexpected error in email breach check: {e}")
            return False, []


def analyze_credential_security(credentials: list) -> dict:
    """
    Analyze a list of credentials for security issues.
    
    Args:
        credentials: List of credential objects with 'password' field
        
    Returns:
        Dictionary with security analysis results
    """
    results = {
        'total_credentials': len(credentials),
        'breached_passwords': 0,
        'high_risk_passwords': [],
        'reused_passwords': {},
        'weak_passwords': 0,
        'analysis_timestamp': time.time()
    }
    
    password_usage = {}
    
    for i, credential in enumerate(credentials):
        try:
            password = credential.get('password', '')
            if not password:
                continue
                
            # Track password reuse
            if password in password_usage:
                password_usage[password].append(i)
            else:
                password_usage[password] = [i]
            
            # Check for breaches (with rate limiting)
            is_breached, breach_count = BreachMonitor.check_password_breach(password)
            
            if is_breached:
                results['breached_passwords'] += 1
                results['high_risk_passwords'].append({
                    'credential_index': i,
                    'service_name': credential.get('service_name', 'Unknown'),
                    'breach_count': breach_count,
                    'risk_level': 'CRITICAL' if breach_count > 1000 else 'HIGH'
                })
            
            # Basic password strength check
            if len(password) < 12 or password.isdigit() or password.isalpha():
                results['weak_passwords'] += 1
            
            # Rate limiting to be respectful to HaveIBeenPwned API
            time.sleep(0.1)
            
        except Exception as e:
            current_app.logger.error(f"Error analyzing credential {i}: {e}")
            continue
    
    # Identify password reuse
    for password, usage_list in password_usage.items():
        if len(usage_list) > 1:
            results['reused_passwords'][password[:8] + '***'] = {
                'count': len(usage_list),
                'services': [credentials[i].get('service_name', 'Unknown') for i in usage_list]
            }
    
    return results


def generate_security_recommendations(analysis_results: dict) -> list:
    """
    Generate security recommendations based on credential analysis.
    
    Args:
        analysis_results: Results from analyze_credential_security
        
    Returns:
        List of recommendation dictionaries
    """
    recommendations = []
    
    if analysis_results['breached_passwords'] > 0:
        recommendations.append({
            'priority': 'CRITICAL',
            'title': 'Breached Passwords Detected',
            'description': f"Found {analysis_results['breached_passwords']} passwords that have been exposed in data breaches.",
            'action': 'Change these passwords immediately',
            'affected_count': analysis_results['breached_passwords']
        })
    
    if analysis_results['reused_passwords']:
        reuse_count = len(analysis_results['reused_passwords'])
        recommendations.append({
            'priority': 'HIGH',
            'title': 'Password Reuse Detected',
            'description': f"Found {reuse_count} passwords being used across multiple services.",
            'action': 'Use unique passwords for each service',
            'affected_count': reuse_count
        })
    
    if analysis_results['weak_passwords'] > 0:
        recommendations.append({
            'priority': 'MEDIUM',
            'title': 'Weak Passwords Found',
            'description': f"Found {analysis_results['weak_passwords']} passwords that don't meet strength requirements.",
            'action': 'Generate stronger passwords using the password generator',
            'affected_count': analysis_results['weak_passwords']
        })
    
    if not recommendations:
        recommendations.append({
            'priority': 'INFO',
            'title': 'Strong Security Posture',
            'description': 'No major security issues detected with your credentials.',
            'action': 'Continue monitoring and updating passwords regularly',
            'affected_count': 0
        })
    
    return recommendations