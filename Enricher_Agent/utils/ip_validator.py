"""
IP Address Validation Utilities

This module provides IP address validation functions based on the patterns
from the existing ip_lookup_enhanced.py implementation.
"""

import re
import ipaddress
import logging
from typing import List, Tuple

logger = logging.getLogger(__name__)

def validate_ip_address(ip: str) -> bool:
    """
    Validate IP address format (IPv4 and IPv6).
    
    This function validates both IPv4 and IPv6 addresses using comprehensive
    regex patterns and the ipaddress module for additional validation.
    
    Args:
        ip: IP address string to validate
        
    Returns:
        bool: True if valid IP address, False otherwise
    """
    if not ip or not isinstance(ip, str):
        return False
    
    ip = ip.strip()
    
    # Basic format check first
    if not ip:
        return False
    
    try:
        # Use Python's built-in ipaddress module for comprehensive validation
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        pass
    
    # Fallback to regex validation for edge cases
    # IPv4 pattern - comprehensive validation
    ipv4_pattern = r'^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$'
    
    # IPv6 pattern - covers most common formats
    ipv6_pattern = r'^([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$|^::1$|^::$|^([0-9a-fA-F]{1,4}:){0,6}::([0-9a-fA-F]{1,4}:){0,6}[0-9a-fA-F]{1,4}$'
    
    return bool(re.match(ipv4_pattern, ip) or re.match(ipv6_pattern, ip))


def validate_multiple_ips(ip_input: str) -> Tuple[List[str], List[str]]:
    """
    Validate and parse multiple IP addresses from input string.
    
    Args:
        ip_input: String containing one or more IP addresses separated by commas, spaces, or newlines
        
    Returns:
        Tuple of (valid_ips, invalid_ips)
    """
    if not ip_input or not isinstance(ip_input, str):
        return [], []
    
    # Split by various delimiters
    ip_list = re.split(r'[,\s\n\r]+', ip_input.strip())
    
    valid_ips = []
    invalid_ips = []
    
    for ip in ip_list:
        ip = ip.strip()
        if not ip:  # Skip empty strings
            continue
            
        if validate_ip_address(ip):
            if ip not in valid_ips:  # Avoid duplicates
                valid_ips.append(ip)
        else:
            invalid_ips.append(ip)
    
    return valid_ips, invalid_ips


def get_ip_type(ip: str) -> str:
    """
    Determine the type of IP address.
    
    Args:
        ip: IP address string
        
    Returns:
        str: IP type ('ipv4', 'ipv6', 'invalid')
    """
    if not validate_ip_address(ip):
        return 'invalid'
    
    try:
        ip_obj = ipaddress.ip_address(ip)
        return 'ipv4' if isinstance(ip_obj, ipaddress.IPv4Address) else 'ipv6'
    except ValueError:
        return 'invalid'


def is_private_ip(ip: str) -> bool:
    """
    Check if IP address is in private range.
    
    Args:
        ip: IP address string
        
    Returns:
        bool: True if private IP, False otherwise
    """
    if not validate_ip_address(ip):
        return False
    
    try:
        ip_obj = ipaddress.ip_address(ip)
        return ip_obj.is_private
    except ValueError:
        return False


def is_reserved_ip(ip: str) -> bool:
    """
    Check if IP address is reserved (loopback, multicast, etc.).
    
    Args:
        ip: IP address string
        
    Returns:
        bool: True if reserved IP, False otherwise
    """
    if not validate_ip_address(ip):
        return False
    
    try:
        ip_obj = ipaddress.ip_address(ip)
        return (ip_obj.is_loopback or 
                ip_obj.is_multicast or 
                ip_obj.is_reserved or
                ip_obj.is_link_local)
    except ValueError:
        return False


def get_ip_classification(ip: str) -> dict:
    """
    Get comprehensive classification of an IP address.
    
    Args:
        ip: IP address string
        
    Returns:
        dict: Classification information
    """
    if not validate_ip_address(ip):
        return {
            'ip': ip,
            'valid': False,
            'type': 'invalid',
            'classification': 'invalid'
        }
    
    try:
        ip_obj = ipaddress.ip_address(ip)
        
        # Determine classification
        if ip_obj.is_loopback:
            classification = 'loopback'
        elif ip_obj.is_private:
            classification = 'private'
        elif ip_obj.is_multicast:
            classification = 'multicast'
        elif ip_obj.is_link_local:
            classification = 'link_local'
        elif ip_obj.is_reserved:
            classification = 'reserved'
        else:
            classification = 'public'
        
        return {
            'ip': ip,
            'valid': True,
            'type': 'ipv4' if isinstance(ip_obj, ipaddress.IPv4Address) else 'ipv6',
            'classification': classification,
            'is_public': classification == 'public',
            'is_private': ip_obj.is_private,
            'is_loopback': ip_obj.is_loopback,
            'is_multicast': ip_obj.is_multicast,
            'is_reserved': ip_obj.is_reserved,
            'is_link_local': ip_obj.is_link_local
        }
        
    except ValueError as e:
        logger.error(f"Error classifying IP {ip}: {e}")
        return {
            'ip': ip,
            'valid': False,
            'type': 'invalid',
            'classification': 'invalid',
            'error': str(e)
        }


def should_analyze_ip(ip: str) -> Tuple[bool, str]:
    """
    Determine if an IP address should be analyzed by external APIs.
    
    Args:
        ip: IP address string
        
    Returns:
        Tuple of (should_analyze: bool, reason: str)
    """
    classification = get_ip_classification(ip)
    
    if not classification['valid']:
        return False, f"Invalid IP address format: {ip}"
    
    if classification['classification'] == 'private':
        return False, f"Private IP address ({ip}) - not suitable for external analysis"
    
    if classification['classification'] == 'loopback':
        return False, f"Loopback IP address ({ip}) - not suitable for external analysis"
    
    if classification['classification'] == 'link_local':
        return False, f"Link-local IP address ({ip}) - not suitable for external analysis"
    
    if classification['classification'] == 'multicast':
        return False, f"Multicast IP address ({ip}) - not suitable for external analysis"
    
    if classification['classification'] == 'reserved':
        return False, f"Reserved IP address ({ip}) - not suitable for external analysis"
    
    return True, f"Public IP address ({ip}) - suitable for analysis"


def filter_analyzable_ips(ip_list: List[str]) -> Tuple[List[str], List[Tuple[str, str]]]:
    """
    Filter a list of IPs to only include those suitable for external analysis.
    
    Args:
        ip_list: List of IP address strings
        
    Returns:
        Tuple of (analyzable_ips, rejected_ips_with_reasons)
    """
    analyzable = []
    rejected = []
    
    for ip in ip_list:
        should_analyze, reason = should_analyze_ip(ip)
        if should_analyze:
            analyzable.append(ip)
        else:
            rejected.append((ip, reason))
    
    return analyzable, rejected