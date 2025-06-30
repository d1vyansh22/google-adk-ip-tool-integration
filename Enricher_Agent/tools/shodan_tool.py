"""
Shodan API Tool for Google ADK

This tool integrates with Shodan API to gather information about open ports, services,
and vulnerabilities for IP addresses using direct REST API calls.

Updated to use: https://api.shodan.io/shodan/host/{ip}?key=API_KEY
No longer requires the shodan Python module.
"""

import requests
import logging
import time
import json
from typing import Dict, Any, Optional
from .cache_service import RedisCacheService

logger = logging.getLogger(__name__)

def get_shodan_data(ip_address: str, api_key: str, 
                   cache_service: Optional[RedisCacheService] = None,
                   timeout: int = 10, max_retries: int = 3) -> Dict[str, Any]:
    """
    Fetches IP information from Shodan API with caching and retry logic.
    
    This tool retrieves information about open ports, running services, and known
    vulnerabilities for an IP address using the Shodan REST API.
    
    Args:
        ip_address: The IP address to lookup (e.g., "8.8.8.8")
        api_key: Shodan API key (required)
        cache_service: Redis cache service instance (optional)
        timeout: Request timeout in seconds (default: 10)
        max_retries: Maximum number of retry attempts (default: 3)
        
    Returns:
        dict: Shodan information including ports, services, and vulnerabilities
              Returns error information if lookup fails
    """
    service_name = "shodan"
    
    # Check cache first if available
    if cache_service and cache_service.is_available():
        cached_data = cache_service.get_cached_data(ip_address, service_name)
        if cached_data:
            logger.info(f"[-] Retrieved {ip_address} from Shodan cache")
            return cached_data
    
    # Build the REST API URL
    base_url = "https://api.shodan.io/shodan/host"
    url = f"{base_url}/{ip_address}?key={api_key}"
    
    # API call logic with retries
    for attempt in range(max_retries):
        try:
            logger.debug(f"[-] Shodan REST API call attempt {attempt + 1} for {ip_address}")
            start_time = time.time()
            
            # Make direct REST API request
            response = requests.get(url, timeout=timeout)
            elapsed_time = time.time() - start_time
            
            # Handle successful response
            if response.status_code == 200:
                host_info = response.json()
                
                # Extract and structure the data (same as before)
                ports = host_info.get("ports", [])
                hostnames = host_info.get("hostnames", [])
                vulnerabilities = host_info.get("vulns", [])
                tags = host_info.get("tags", [])
                
                # Determine if IP appears malicious based on tags and vulnerabilities
                suspicious_tags = ["malware", "botnet", "spam", "phishing", "tor", "proxy"]
                has_suspicious_tags = any(tag.lower() in suspicious_tags for tag in tags)
                has_vulnerabilities = len(vulnerabilities) > 0
                
                # Calculate risk score based on various factors
                risk_score = 0
                
                # Add points for vulnerabilities
                if vulnerabilities:
                    risk_score += min(len(vulnerabilities) * 10, 40)
                
                # Add points for suspicious tags
                if has_suspicious_tags:
                    risk_score += 30
                
                # Add points for excessive open ports (might indicate compromised system)
                if len(ports) > 10:
                    risk_score += 20
                
                # Check for commonly abused ports
                high_risk_ports = [22, 23, 135, 139, 445, 1433, 3389, 5900]
                open_high_risk_ports = [port for port in ports if port in high_risk_ports]
                if open_high_risk_ports:
                    risk_score += len(open_high_risk_ports) * 5
                
                risk_score = min(risk_score, 100)  # Cap at 100
                
                # Structure the response data (identical format)
                result = {
                    "ip": ip_address,
                    "ports": sorted(ports),
                    "port_count": len(ports),
                    "hostnames": hostnames,
                    "country": host_info.get("country_name", "Unknown"),
                    "country_code": host_info.get("country_code", "Unknown"),
                    "city": host_info.get("city", "Unknown"),
                    "region": host_info.get("region_code", "Unknown"),
                    "organization": host_info.get("org", "Unknown"),
                    "isp": host_info.get("isp", "Unknown"),
                    "asn": host_info.get("asn", "Unknown"),
                    "last_update": host_info.get("last_update", "Unknown"),
                    "vulnerabilities": vulnerabilities,
                    "vulnerability_count": len(vulnerabilities),
                    "tags": tags,
                    "os": host_info.get("os"),
                    "risk_score": risk_score,
                    "risk_level": _get_shodan_risk_level(risk_score),
                    "is_suspicious": has_suspicious_tags or has_vulnerabilities or risk_score > 30,
                    "high_risk_ports": open_high_risk_ports,
                    "source": service_name,
                    "api_response_time": round(elapsed_time, 3),
                    "status": "success"
                }
                
                # Add service details for the most interesting ports
                data = host_info.get("data", [])
                if data:
                    services = []
                    for service in data[:10]:  # Limit to first 10 services
                        service_info = {
                            "port": service.get("port"),
                            "protocol": service.get("transport", "tcp"),
                            "service": service.get("product", "unknown"),
                            "version": service.get("version", ""),
                            "banner": service.get("data", "")[:200] + "..." if len(service.get("data", "")) > 200 else service.get("data", ""),
                            "timestamp": service.get("timestamp")
                        }
                        services.append(service_info)
                    result["services"] = services
                
                # Cache the results
                if cache_service and cache_service.is_available():
                    cache_service.cache_data(ip_address, service_name, result)
                
                logger.info(f"[-] Shodan REST lookup successful for {ip_address} ({elapsed_time:.3f}s)")
                return result
            
            # Handle specific HTTP error codes
            elif response.status_code == 401:
                logger.error(f"[x] Shodan: Authentication failed")
                return {
                    "ip": ip_address,
                    "error": "Shodan API authentication failed. Check your API key.",
                    "error_code": 401,
                    "source": service_name,
                    "status": "auth_error"
                }
                
            elif response.status_code == 404:
                logger.warning(f"[!] Shodan: No data found for IP {ip_address}")
                return {
                    "ip": ip_address,
                    "message": "No information available for this IP address in Shodan",
                    "ports": [],
                    "port_count": 0,
                    "vulnerability_count": 0,
                    "risk_score": 0,
                    "risk_level": "unknown",
                    "is_suspicious": False,
                    "source": service_name,
                    "status": "no_data"
                }
                
            elif response.status_code == 429:
                logger.warning(f"[!] Shodan rate limit exceeded. Attempt {attempt + 1}/{max_retries}")
                if attempt < max_retries - 1:
                    wait_time = 2 ** attempt
                    logger.info(f"[-] Waiting {wait_time} seconds before retry...")
                    time.sleep(wait_time)
                    continue
                else:
                    return {
                        "ip": ip_address,
                        "error": "Shodan rate limit exceeded",
                        "error_code": 429,
                        "source": service_name,
                        "status": "rate_limit"
                    }
            
            else:
                logger.error(f"[x] Shodan API HTTP {response.status_code}: {response.text}")
                if attempt == max_retries - 1:
                    return {
                        "ip": ip_address,
                        "error": f"Shodan API HTTP error: {response.status_code}",
                        "error_type": "http_error",
                        "source": service_name,
                        "status": "http_error"
                    }
                    
        except requests.exceptions.Timeout:
            logger.error(f"[!] Shodan request timeout on attempt {attempt + 1}/{max_retries}")
            if attempt == max_retries - 1:
                return {
                    "ip": ip_address,
                    "error": "Request timeout",
                    "error_type": "timeout",
                    "source": service_name,
                    "status": "timeout"
                }
                
        except requests.exceptions.ConnectionError:
            logger.error(f"[!] Shodan connection error on attempt {attempt + 1}/{max_retries}")
            if attempt == max_retries - 1:
                return {
                    "ip": ip_address,
                    "error": "Connection error",
                    "error_type": "connection_error",
                    "source": service_name,
                    "status": "connection_error"
                }
                
        except requests.exceptions.RequestException as e:
            logger.error(f"[x] Shodan request error: {e}")
            return {
                "ip": ip_address,
                "error": f"Request error: {str(e)}",
                "error_type": "request_error",
                "source": service_name,
                "status": "request_error"
            }
            
        except json.JSONDecodeError as e:
            logger.error(f"[x] Shodan JSON decode error: {e}")
            return {
                "ip": ip_address,
                "error": f"Invalid JSON response: {str(e)}",
                "error_type": "json_error",
                "source": service_name,
                "status": "json_error"
            }
            
        except Exception as e:
            logger.error(f"[x] Unexpected Shodan error: {e}")
            return {
                "ip": ip_address,
                "error": f"Unexpected error during Shodan lookup: {str(e)}",
                "error_type": "unexpected_error",
                "source": service_name,
                "status": "unexpected_error"
            }
        
        # Wait before retry for transient errors
        if attempt < max_retries - 1:
            wait_time = 2 ** attempt
            logger.info(f"[-] Retrying Shodan REST in {wait_time} seconds...")
            time.sleep(wait_time)
    
    # If we get here, all retries failed
    logger.error(f"[x] Shodan lookup failed for {ip_address} after {max_retries} attempts")
    return {
        "ip": ip_address,
        "error": f"Shodan lookup failed after {max_retries} attempts",
        "source": service_name,
        "status": "max_retries_exceeded"
    }


def _get_shodan_risk_level(risk_score: float) -> str:
    """Determine risk level based on score."""
    if risk_score == 0:
        return "minimal"
    elif risk_score < 20:
        return "low"
    elif risk_score < 40:
        return "medium"
    elif risk_score < 70:
        return "high"
    else:
        return "critical"


def check_shodan_tool(ip_address: str) -> Dict[str, Any]:
    """
    ADK Function Tool wrapper for Shodan API.
    
    This function is designed to be used as a Google ADK Function Tool.
    It provides network and vulnerability information for IP addresses.
    
    **IMPORTANT: This function name is preserved for compatibility with other files**
    
    Args:
        ip_address: The IP address to analyze
        
    Returns:
        dict: Formatted response for the ADK agent
    """
    import os
    from .cache_service import create_cache_service_from_config
    
    # Get configuration from environment
    api_key = os.getenv('SHODAN_API_KEY')
    if not api_key:
        return {
            "status": "error",
            "service": "shodan",
            "ip_address": ip_address,
            "error_message": "Shodan API key not configured",
            "error_type": "configuration_error",
            "data_source": "shodan"
        }
    
    timeout = int(os.getenv('API_TIMEOUT', 10))
    max_retries = int(os.getenv('MAX_RETRIES', 3))
    
    # Create cache service
    cache_service = create_cache_service_from_config()
    
    # Perform lookup using REST API
    result = get_shodan_data(
        ip_address=ip_address,
        api_key=api_key,
        cache_service=cache_service,
        timeout=timeout,
        max_retries=max_retries
    )
    
    # Format for ADK agent consumption (identical format maintained)
    if result.get('status') == 'success':
        return {
            "status": "success",
            "service": "shodan",
            "ip_address": ip_address,
            "network_analysis": {
                "open_ports": result.get('ports', []),
                "port_count": result.get('port_count', 0),
                "high_risk_ports": result.get('high_risk_ports', []),
                "services": result.get('services', []),
                "risk_score": result.get('risk_score', 0),
                "risk_level": result.get('risk_level', 'unknown'),
                "is_suspicious": result.get('is_suspicious', False)
            },
            "vulnerability_analysis": {
                "vulnerabilities": result.get('vulnerabilities', []),
                "vulnerability_count": result.get('vulnerability_count', 0)
            },
            "location": {
                "country": result.get('country'),
                "country_code": result.get('country_code'),
                "city": result.get('city'),
                "region": result.get('region')
            },
            "network_info": {
                "organization": result.get('organization'),
                "isp": result.get('isp'),
                "asn": result.get('asn'),
                "hostnames": result.get('hostnames', [])
            },
            "system_info": {
                "os": result.get('os'),
                "tags": result.get('tags', [])
            },
            "last_update": result.get('last_update'),
            "response_time": result.get('api_response_time'),
            "data_source": "shodan"
        }
    elif result.get('status') == 'no_data':
        return {
            "status": "no_data",
            "service": "shodan",
            "ip_address": ip_address,
            "message": result.get('message', 'No data available'),
            "network_analysis": {
                "open_ports": [],
                "port_count": 0,
                "risk_score": 0,
                "risk_level": "unknown",
                "is_suspicious": False
            },
            "data_source": "shodan"
        }
    else:
        return {
            "status": "error",
            "service": "shodan",
            "ip_address": ip_address,
            "error_message": result.get('error', 'Unknown error'),
            "error_type": result.get('error_type', 'unknown'),
            "data_source": "shodan"
        }
