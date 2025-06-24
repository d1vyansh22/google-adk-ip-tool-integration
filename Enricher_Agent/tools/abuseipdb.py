"""
AbuseIPDB API Integration Tool for IP Threat Intelligence
========================================================

This module provides comprehensive integration with AbuseIPDB API for community-driven
threat intelligence and abuse reporting. AbuseIPDB maintains a database of IP addresses
that have been associated with malicious activity, providing abuse confidence scores
and detailed reporting information.

Key Features:
- IP abuse confidence scoring (0-100%)
- Community-driven threat intelligence
- Detailed abuse report history
- Country and ISP information
- Usage type classification
- Whitelist checking

Author: Enhanced IP Threat Intelligence System
Version: 1.0.0
"""

import requests
import json
import time
import logging
from datetime import datetime
from typing import Dict, Any, Optional
from .cache_service import RedisCacheService

# Configure logging
logger = logging.getLogger(__name__)

class AbuseIPDBError(Exception):
    """Custom exception for AbuseIPDB API errors."""
    pass

def get_abuseipdb_data(ip_address: str, api_key: str, cache_service: Optional[RedisCacheService] = None, 
                       max_age_days: int = 90, verbose: bool = True) -> Dict[str, Any]:
    """
    Retrieve IP abuse information from AbuseIPDB API.
    
    This function queries AbuseIPDB's community-driven database to determine
    if an IP address has been reported for malicious activity. It provides
    an abuse confidence score based on community reports and detailed
    information about the IP's reputation.
    
    Args:
        ip_address: The IP address to check for abuse reports
        api_key: AbuseIPDB API key for authentication
        cache_service: Optional Redis cache service for performance optimization
        max_age_days: Maximum age in days for reports to consider (1-365, default: 90)
        verbose: Include detailed report information in response
        
    Returns:
        Dictionary containing comprehensive abuse intelligence:
        {
            "ip": "8.8.8.8",
            "is_public": True,
            "ip_version": 4,
            "is_whitelisted": False,
            "abuse_confidence_score": 0,
            "country_code": "US",
            "country_name": "United States",
            "usage_type": "Data Center/Web Hosting/Transit",
            "isp": "Google LLC",
            "domain": "google.com",
            "hostnames": ["dns.google"],
            "is_tor": False,
            "total_reports": 0,
            "num_distinct_users": 0,
            "last_reported_at": None,
            "reports": [],
            "malicious": False,
            "risk_level": "LOW",
            "source": "abuseipdb"
        }
        
    Raises:
        AbuseIPDBError: When API request fails or returns invalid data
        ValueError: When invalid parameters are provided
    """
    
    # Validate input parameters
    if not ip_address or not isinstance(ip_address, str):
        raise ValueError("IP address must be a non-empty string")
    
    if not api_key or not isinstance(api_key, str):
        raise ValueError("API key must be a non-empty string")
    
    if not (1 <= max_age_days <= 365):
        raise ValueError("max_age_days must be between 1 and 365")
    
    service_name = "abuseipdb"
    
    # Check cache first if available
    if cache_service and cache_service.is_cached(ip_address, service_name):
        cached_data = cache_service.get_cached_data(ip_address, service_name)
        if cached_data:
            logger.info(f"Retrieved AbuseIPDB data for {ip_address} from cache")
            return cached_data
    
    # Prepare API request
    url = "https://api.abuseipdb.com/api/v2/check"
    
    headers = {
        "Key": api_key,
        "Accept": "application/json"
    }
    
    params = {
        "ipAddress": ip_address,
        "maxAgeInDays": max_age_days
    }
    
    # Add verbose flag if requested
    if verbose:
        params["verbose"] = ""
    
    try:
        # Make API request with timeout and retry logic
        logger.info(f"Querying AbuseIPDB for IP: {ip_address}")
        
        response = requests.get(
            url=url,
            headers=headers,
            params=params,
            timeout=30  # 30 second timeout
        )
        
        # Check for rate limiting
        if response.status_code == 429:
            logger.warning(f"AbuseIPDB rate limit exceeded for IP: {ip_address}")
            return {
                "ip": ip_address,
                "error": "Rate limit exceeded",
                "retry_after": response.headers.get("Retry-After", "Unknown"),
                "source": "abuseipdb"
            }
        
        # Check for authentication errors
        if response.status_code == 401:
            logger.error("AbuseIPDB API authentication failed - check API key")
            return {
                "ip": ip_address,
                "error": "Authentication failed - invalid API key",
                "source": "abuseipdb"
            }
        
        # Check for other HTTP errors
        if response.status_code != 200:
            logger.error(f"AbuseIPDB API error {response.status_code}: {response.text}")
            return {
                "ip": ip_address,
                "error": f"HTTP {response.status_code}: {response.text}",
                "source": "abuseipdb"
            }
        
        # Parse JSON response
        try:
            json_response = response.json()
        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse AbuseIPDB JSON response: {e}")
            return {
                "ip": ip_address,
                "error": f"Invalid JSON response: {str(e)}",
                "source": "abuseipdb"
            }
        
        # Extract data from response
        if "data" not in json_response:
            logger.error("AbuseIPDB response missing 'data' field")
            return {
                "ip": ip_address,
                "error": "Invalid response format - missing data field",
                "source": "abuseipdb"
            }
        
        api_data = json_response["data"]
        
        # Process and enhance the response data
        result = {
            "ip": api_data.get("ipAddress", ip_address),
            "is_public": api_data.get("isPublic", True),
            "ip_version": api_data.get("ipVersion", 4),
            "is_whitelisted": api_data.get("isWhitelisted", False),
            "abuse_confidence_score": api_data.get("abuseConfidenceScore", 0),
            "country_code": api_data.get("countryCode", "Unknown"),
            "country_name": api_data.get("countryName", "Unknown"),
            "usage_type": api_data.get("usageType", "Unknown"),
            "isp": api_data.get("isp", "Unknown"),
            "domain": api_data.get("domain", "Unknown"),
            "hostnames": api_data.get("hostnames", []),
            "is_tor": api_data.get("isTor", False),
            "total_reports": api_data.get("totalReports", 0),
            "num_distinct_users": api_data.get("numDistinctUsers", 0),
            "last_reported_at": api_data.get("lastReportedAt"),
            "source": "abuseipdb",
            "query_timestamp": datetime.now().isoformat(),
            "max_age_days": max_age_days
        }
        
        # Include reports if verbose and available
        if verbose and "reports" in api_data:
            result["reports"] = api_data["reports"]
            result["report_count"] = len(api_data["reports"])
        else:
            result["reports"] = []
            result["report_count"] = 0
        
        # Determine malicious status and risk level
        abuse_score = result["abuse_confidence_score"]
        total_reports = result["total_reports"]
        
        # Enhanced malicious detection logic
        is_malicious = False
        risk_level = "MINIMAL"
        
        if abuse_score >= 75:
            is_malicious = True
            risk_level = "CRITICAL"
        elif abuse_score >= 50:
            is_malicious = True
            risk_level = "HIGH"
        elif abuse_score >= 25:
            is_malicious = True
            risk_level = "MEDIUM"
        elif abuse_score > 0 or total_reports > 0:
            risk_level = "LOW"
        
        # Additional risk factors
        risk_factors = []
        
        if result["is_tor"]:
            risk_factors.append("Tor exit node")
            if risk_level == "MINIMAL":
                risk_level = "LOW"
        
        if result["usage_type"] == "Data Center/Web Hosting/Transit":
            risk_factors.append("Hosting/VPS infrastructure")
        
        if total_reports > 10:
            risk_factors.append(f"High report volume ({total_reports} reports)")
        
        if result["num_distinct_users"] > 5:
            risk_factors.append(f"Multiple reporters ({result['num_distinct_users']} users)")
        
        result.update({
            "malicious": is_malicious,
            "risk_level": risk_level,
            "risk_factors": risk_factors
        })
        
        # Add summary information
        result["summary"] = _generate_summary(result)
        
        # Cache the results if cache service is available
        if cache_service:
            cache_service.cache_data(ip_address, service_name, result)
            logger.info(f"Cached AbuseIPDB data for {ip_address}")
        
        logger.info(f"Successfully retrieved AbuseIPDB data for {ip_address} - "
                   f"Abuse Score: {abuse_score}%, Risk: {risk_level}")
        
        return result
        
    except requests.exceptions.Timeout:
        logger.error(f"AbuseIPDB API timeout for IP: {ip_address}")
        return {
            "ip": ip_address,
            "error": "Request timeout - AbuseIPDB API not responding",
            "source": "abuseipdb"
        }
        
    except requests.exceptions.ConnectionError:
        logger.error(f"AbuseIPDB API connection error for IP: {ip_address}")
        return {
            "ip": ip_address,
            "error": "Connection error - unable to reach AbuseIPDB API",
            "source": "abuseipdb"
        }
        
    except requests.exceptions.RequestException as e:
        logger.error(f"AbuseIPDB API request error for IP {ip_address}: {str(e)}")
        return {
            "ip": ip_address,
            "error": f"Request error: {str(e)}",
            "source": "abuseipdb"
        }
        
    except Exception as e:
        logger.error(f"Unexpected error querying AbuseIPDB for IP {ip_address}: {str(e)}")
        return {
            "ip": ip_address,
            "error": f"Unexpected error: {str(e)}",
            "source": "abuseipdb"
        }

def _generate_summary(data: Dict[str, Any]) -> str:
    """
    Generate a human-readable summary of AbuseIPDB data.
    
    Args:
        data: Processed AbuseIPDB response data
        
    Returns:
        Formatted summary string
    """
    ip = data.get("ip", "Unknown")
    abuse_score = data.get("abuse_confidence_score", 0)
    total_reports = data.get("total_reports", 0)
    country = data.get("country_name", "Unknown")
    risk_level = data.get("risk_level", "UNKNOWN")
    
    summary = f"IP {ip} has an abuse confidence score of {abuse_score}% "
    
    if total_reports > 0:
        summary += f"with {total_reports} community reports. "
    else:
        summary += "with no community reports. "
    
    summary += f"Located in {country}. Risk level: {risk_level}."
    
    if data.get("is_whitelisted"):
        summary += " Note: This IP is whitelisted in AbuseIPDB."
    
    if data.get("is_tor"):
        summary += " Warning: This is a Tor exit node."
    
    return summary

def get_abuseipdb_reports(ip_address: str, api_key: str, max_age_days: int = 90, 
                         page: int = 1, per_page: int = 25) -> Dict[str, Any]:
    """
    Retrieve detailed abuse reports for an IP address from AbuseIPDB.
    
    This function fetches paginated detailed reports about an IP address,
    providing comprehensive information about each abuse incident.
    
    Args:
        ip_address: IP address to get reports for
        api_key: AbuseIPDB API key
        max_age_days: Maximum age of reports in days (1-365)
        page: Page number for pagination (default: 1)
        per_page: Number of reports per page (1-100, default: 25)
        
    Returns:
        Dictionary containing paginated report data
    """
    
    url = "https://api.abuseipdb.com/api/v2/reports"
    
    headers = {
        "Key": api_key,
        "Accept": "application/json"
    }
    
    params = {
        "ipAddress": ip_address,
        "maxAgeInDays": max_age_days,
        "page": page,
        "perPage": per_page
    }
    
    try:
        response = requests.get(url, headers=headers, params=params, timeout=30)
        
        if response.status_code == 200:
            return response.json()
        else:
            return {
                "error": f"HTTP {response.status_code}: {response.text}",
                "ip": ip_address
            }
            
    except Exception as e:
        return {
            "error": f"Request failed: {str(e)}",
            "ip": ip_address
        }

def check_abuseipdb_blacklist(api_key: str, confidence_minimum: int = 75, 
                             limit: int = 10000) -> Dict[str, Any]:
    """
    Retrieve AbuseIPDB blacklist of most reported IP addresses.
    
    Args:
        api_key: AbuseIPDB API key
        confidence_minimum: Minimum abuse confidence score (25-100)
        limit: Maximum number of IPs to retrieve
        
    Returns:
        Dictionary containing blacklist data
    """
    
    url = "https://api.abuseipdb.com/api/v2/blacklist"
    
    headers = {
        "Key": api_key,
        "Accept": "application/json"
    }
    
    params = {
        "confidenceMinimum": confidence_minimum,
        "limit": limit
    }
    
    try:
        response = requests.get(url, headers=headers, params=params, timeout=30)
        
        if response.status_code == 200:
            return response.json()
        else:
            return {
                "error": f"HTTP {response.status_code}: {response.text}"
            }
            
    except Exception as e:
        return {
            "error": f"Request failed: {str(e)}"
        }

# Usage example and testing functions
if __name__ == "__main__":
    # Example usage - replace with your actual API key
    API_KEY = "your_abuseipdb_api_key_here"
    TEST_IP = "8.8.8.8"
    
    print(f"Testing AbuseIPDB integration with IP: {TEST_IP}")
