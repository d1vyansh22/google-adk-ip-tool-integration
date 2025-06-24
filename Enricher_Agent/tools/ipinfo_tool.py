"""
IPInfo API Tool for Google ADK

This tool integrates with IPInfo API to gather geolocation and network information about IP addresses.
Based on the existing ip_lookup_enhanced.py implementation patterns.
"""

import requests
import logging
import time
from typing import Dict, Any, Optional
from .cache_service import RedisCacheService

logger = logging.getLogger(__name__)

def get_ipinfo_data(ip_address: str, api_key: Optional[str] = None, 
                   cache_service: Optional[RedisCacheService] = None,
                   timeout: int = 10, max_retries: int = 3) -> Dict[str, Any]:
    """
    Fetches IP information from IPInfo API with caching and retry logic.
    
    This tool retrieves geolocation, network, and organizational information 
    about an IP address using the IPInfo API.
    
    Args:
        ip_address: The IP address to lookup (e.g., "8.8.8.8")
        api_key: IPInfo API key for authenticated requests (optional)
        cache_service: Redis cache service instance (optional)
        timeout: Request timeout in seconds (default: 10)
        max_retries: Maximum number of retry attempts (default: 3)
        
    Returns:
        dict: IP information including location, ISP, and network details
              Returns error information if lookup fails
    """
    service_name = "ipinfo"
    
    # Check cache first if available
    if cache_service and cache_service.is_available():
        cached_data = cache_service.get_cached_data(ip_address, service_name)
        if cached_data:
            logger.info(f"🎯 Retrieved {ip_address} from cache")
            return cached_data
    
    # API call logic with retries and exponential backoff
    base_url = "https://ipinfo.io"
    
    for attempt in range(max_retries):
        try:
            # Construct URL
            url = f"{base_url}/{ip_address}/json"
            
            # Prepare headers
            headers = {'User-Agent': 'google-adk-ip-enricher/1.0'}
            if api_key:
                headers['Authorization'] = f'Bearer {api_key}'
            
            # Make API request
            logger.debug(f"🌐 IPInfo API call attempt {attempt + 1} for {ip_address}")
            start_time = time.time()
            
            response = requests.get(url, headers=headers, timeout=timeout)
            elapsed_time = time.time() - start_time
            
            # Check response status
            if response.status_code == 200:
                data = response.json()
                
                # Structure the response data
                result = {
                    "ip": ip_address,
                    "hostname": data.get('hostname'),
                    "city": data.get('city'),
                    "region": data.get('region'),
                    "country": data.get('country'),
                    "country_name": data.get('country_name'),
                    "location": data.get('loc'),
                    "organization": data.get('org'),
                    "postal": data.get('postal'),
                    "timezone": data.get('timezone'),
                    "asn": data.get('asn'),
                    "company": data.get('company', {}),
                    "carrier": data.get('carrier', {}),
                    "privacy": data.get('privacy', {}),
                    "abuse": data.get('abuse', {}),
                    "domains": data.get('domains', []),
                    "source": service_name,
                    "api_response_time": round(elapsed_time, 3),
                    "status": "success"
                }
                
                # Check for privacy/security flags
                privacy_info = data.get('privacy', {})
                if privacy_info:
                    result["privacy_flags"] = {
                        "vpn": privacy_info.get('vpn', False),
                        "proxy": privacy_info.get('proxy', False),
                        "tor": privacy_info.get('tor', False),
                        "relay": privacy_info.get('relay', False),
                        "hosting": privacy_info.get('hosting', False)
                    }
                    result["has_privacy_concerns"] = any(result["privacy_flags"].values())
                
                # Cache the results
                if cache_service and cache_service.is_available():
                    cache_service.cache_data(ip_address, service_name, result)
                
                logger.info(f"✅ IPInfo lookup successful for {ip_address} ({elapsed_time:.3f}s)")
                return result
                
            elif response.status_code == 429:
                logger.warning(f"⚠️ IPInfo rate limit exceeded. Attempt {attempt + 1}/{max_retries}")
                if attempt < max_retries - 1:
                    wait_time = 2 ** attempt
                    logger.info(f"⏳ Waiting {wait_time} seconds before retry...")
                    time.sleep(wait_time)
                    
            elif response.status_code == 404:
                logger.error(f"❌ IPInfo: IP address not found: {ip_address}")
                return {
                    "ip": ip_address,
                    "error": f"IP address not found in IPInfo database",
                    "error_code": 404,
                    "source": service_name,
                    "status": "not_found"
                }
                
            elif response.status_code == 401:
                logger.error(f"❌ IPInfo: Authentication failed")
                return {
                    "ip": ip_address,
                    "error": "IPInfo API authentication failed. Check your API key.",
                    "error_code": 401,
                    "source": service_name,
                    "status": "auth_error"
                }
                
            else:
                logger.error(f"❌ IPInfo HTTP Error {response.status_code}: {response.text}")
                if attempt == max_retries - 1:
                    return {
                        "ip": ip_address,
                        "error": f"IPInfo API error: HTTP {response.status_code}",
                        "error_code": response.status_code,
                        "source": service_name,
                        "status": "api_error"
                    }
                    
        except requests.exceptions.Timeout:
            logger.error(f"⏰ IPInfo timeout on attempt {attempt + 1}/{max_retries}")
            if attempt == max_retries - 1:
                return {
                    "ip": ip_address,
                    "error": f"IPInfo API timeout after {max_retries} attempts",
                    "error_type": "timeout",
                    "source": service_name,
                    "status": "timeout_error"
                }
                
        except requests.exceptions.ConnectionError:
            logger.error(f"🌐 IPInfo connection error on attempt {attempt + 1}/{max_retries}")
            if attempt == max_retries - 1:
                return {
                    "ip": ip_address,
                    "error": f"IPInfo API connection error after {max_retries} attempts",
                    "error_type": "connection_error",
                    "source": service_name,
                    "status": "connection_error"
                }
                
        except requests.exceptions.RequestException as e:
            logger.error(f"📡 IPInfo request error: {e}")
            return {
                "ip": ip_address,
                "error": f"IPInfo API request error: {str(e)}",
                "error_type": "request_error",
                "source": service_name,
                "status": "request_error"
            }
            
        except Exception as e:
            logger.error(f"❌ Unexpected IPInfo error: {e}")
            return {
                "ip": ip_address,
                "error": f"Unexpected error during IPInfo lookup: {str(e)}",
                "error_type": "unexpected_error",
                "source": service_name,
                "status": "unexpected_error"
            }
        
        # Wait before retry (exponential backoff)
        if attempt < max_retries - 1:
            wait_time = 2 ** attempt
            logger.info(f"⏳ Retrying IPInfo in {wait_time} seconds...")
            time.sleep(wait_time)
    
    # If we get here, all retries failed
    logger.error(f"❌ IPInfo lookup failed for {ip_address} after {max_retries} attempts")
    return {
        "ip": ip_address,
        "error": f"IPInfo lookup failed after {max_retries} attempts",
        "source": service_name,
        "status": "max_retries_exceeded"
    }


def check_ipinfo_tool(ip_address: str) -> Dict[str, Any]:
    """
    ADK Function Tool wrapper for IPInfo API.
    
    This function is designed to be used as a Google ADK Function Tool.
    It provides a clean interface for the agent to lookup IP information.
    
    Args:
        ip_address: The IP address to lookup
        
    Returns:
        dict: Formatted response for the ADK agent
    """
    import os
    from .cache_service import create_cache_service_from_config
    
    # Get configuration from environment
    api_key = os.getenv('IPINFO_API_KEY')
    timeout = int(os.getenv('API_TIMEOUT', 10))
    max_retries = int(os.getenv('MAX_RETRIES', 3))
    
    # Create cache service
    cache_service = create_cache_service_from_config()
    
    # Perform lookup
    result = get_ipinfo_data(
        ip_address=ip_address,
        api_key=api_key,
        cache_service=cache_service,
        timeout=timeout,
        max_retries=max_retries
    )
    
    # Format for ADK agent consumption
    if result.get('status') == 'success':
        return {
            "status": "success",
            "service": "ipinfo",
            "ip_address": ip_address,
            "location": {
                "city": result.get('city'),
                "region": result.get('region'),
                "country": result.get('country'),
                "country_name": result.get('country_name'),
                "coordinates": result.get('location'),
                "postal_code": result.get('postal'),
                "timezone": result.get('timezone')
            },
            "network": {
                "organization": result.get('organization'),
                "asn": result.get('asn'),
                "hostname": result.get('hostname')
            },
            "privacy": result.get('privacy_flags', {}),
            "has_privacy_concerns": result.get('has_privacy_concerns', False),
            "response_time": result.get('api_response_time'),
            "data_source": "ipinfo"
        }
    else:
        return {
            "status": "error",
            "service": "ipinfo", 
            "ip_address": ip_address,
            "error_message": result.get('error', 'Unknown error'),
            "error_type": result.get('error_type', 'unknown'),
            "data_source": "ipinfo"
        }