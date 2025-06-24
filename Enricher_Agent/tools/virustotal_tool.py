"""
VirusTotal API Tool for Google ADK

This tool integrates with VirusTotal API to check IP addresses for malicious activity.
Provides threat intelligence and reputation scoring.
"""

import requests
import logging
import time
from typing import Dict, Any, Optional
from .cache_service import RedisCacheService

logger = logging.getLogger(__name__)

def get_virustotal_data(ip_address: str, api_key: str, 
                       cache_service: Optional[RedisCacheService] = None,
                       timeout: int = 10, max_retries: int = 3) -> Dict[str, Any]:
    """
    Fetches IP reputation data from VirusTotal API with caching and retry logic.
    
    This tool checks an IP address against VirusTotal's database of security vendors
    to determine if it has been flagged as malicious.
    
    Args:
        ip_address: The IP address to check (e.g., "8.8.8.8")
        api_key: VirusTotal API key (required)
        cache_service: Redis cache service instance (optional)
        timeout: Request timeout in seconds (default: 10)
        max_retries: Maximum number of retry attempts (default: 3)
        
    Returns:
        dict: VirusTotal analysis results including vendor detections and reputation
              Returns error information if lookup fails
    """
    service_name = "virustotal"
    
    # Check cache first if available
    if cache_service and cache_service.is_available():
        cached_data = cache_service.get_cached_data(ip_address, service_name)
        if cached_data:
            logger.info(f"🎯 Retrieved {ip_address} from VirusTotal cache")
            return cached_data
    
    # API call logic with retries
    base_url = "https://www.virustotal.com/api/v3"
    
    for attempt in range(max_retries):
        try:
            # Construct URL
            url = f"{base_url}/ip_addresses/{ip_address}"
            
            # Prepare headers
            headers = {
                "x-apikey": api_key,
                "User-Agent": "google-adk-ip-enricher/1.0"
            }
            
            # Make API request
            logger.debug(f"🛡️ VirusTotal API call attempt {attempt + 1} for {ip_address}")
            start_time = time.time()
            
            response = requests.get(url, headers=headers, timeout=timeout)
            elapsed_time = time.time() - start_time
            
            # Check response status
            if response.status_code == 200:
                data = response.json()
                attributes = data.get("data", {}).get("attributes", {})
                
                # Extract analysis statistics
                last_analysis_stats = attributes.get("last_analysis_stats", {})
                reputation = attributes.get("reputation", 0)
                total_votes = attributes.get("total_votes", {})
                
                # Determine if IP is malicious
                malicious_count = last_analysis_stats.get("malicious", 0)
                suspicious_count = last_analysis_stats.get("suspicious", 0)
                total_engines = sum(last_analysis_stats.values()) if last_analysis_stats else 0
                
                is_malicious = malicious_count > 0
                threat_score = 0
                
                if total_engines > 0:
                    # Calculate threat score (0-100)
                    threat_score = min(((malicious_count + suspicious_count * 0.5) / total_engines) * 100, 100)
                
                # Structure the response data
                result = {
                    "ip": ip_address,
                    "last_analysis_stats": last_analysis_stats,
                    "reputation": reputation,
                    "total_votes": total_votes,
                    "malicious_count": malicious_count,
                    "suspicious_count": suspicious_count,
                    "total_engines": total_engines,
                    "is_malicious": is_malicious,
                    "threat_score": round(threat_score, 2),
                    "threat_level": _get_threat_level(threat_score),
                    "last_analysis_date": attributes.get("last_analysis_date"),
                    "last_modification_date": attributes.get("last_modification_date"),
                    "country": attributes.get("country"),
                    "as_owner": attributes.get("as_owner"),
                    "asn": attributes.get("asn"),
                    "network": attributes.get("network"),
                    "whois": attributes.get("whois"),
                    "source": service_name,
                    "api_response_time": round(elapsed_time, 3),
                    "status": "success"
                }
                
                # Add detected engines details if any detections
                if malicious_count > 0 or suspicious_count > 0:
                    last_analysis_results = attributes.get("last_analysis_results", {})
                    detected_engines = []
                    
                    for engine, details in last_analysis_results.items():
                        category = details.get("category", "")
                        if category in ["malicious", "suspicious"]:
                            detected_engines.append({
                                "engine": engine,
                                "category": category,
                                "result": details.get("result", ""),
                                "method": details.get("method", "")
                            })
                    
                    result["detected_engines"] = detected_engines
                
                # Cache the results
                if cache_service and cache_service.is_available():
                    cache_service.cache_data(ip_address, service_name, result)
                
                logger.info(f"✅ VirusTotal lookup successful for {ip_address} ({elapsed_time:.3f}s)")
                return result
                
            elif response.status_code == 429:
                logger.warning(f"⚠️ VirusTotal rate limit exceeded. Attempt {attempt + 1}/{max_retries}")
                if attempt < max_retries - 1:
                    wait_time = 2 ** attempt
                    logger.info(f"⏳ Waiting {wait_time} seconds before retry...")
                    time.sleep(wait_time)
                    
            elif response.status_code == 404:
                logger.warning(f"⚠️ VirusTotal: No data found for IP {ip_address}")
                return {
                    "ip": ip_address,
                    "message": "No analysis data found for this IP address",
                    "is_malicious": False,
                    "threat_score": 0,
                    "threat_level": "unknown",
                    "source": service_name,
                    "status": "no_data"
                }
                
            elif response.status_code == 401:
                logger.error(f"❌ VirusTotal: Authentication failed")
                return {
                    "ip": ip_address,
                    "error": "VirusTotal API authentication failed. Check your API key.",
                    "error_code": 401,
                    "source": service_name,
                    "status": "auth_error"
                }
                
            else:
                logger.error(f"❌ VirusTotal HTTP Error {response.status_code}")
                if attempt == max_retries - 1:
                    return {
                        "ip": ip_address,
                        "error": f"VirusTotal API error: HTTP {response.status_code}",
                        "error_code": response.status_code,
                        "source": service_name,
                        "status": "api_error"
                    }
                    
        except requests.exceptions.Timeout:
            logger.error(f"⏰ VirusTotal timeout on attempt {attempt + 1}/{max_retries}")
            if attempt == max_retries - 1:
                return {
                    "ip": ip_address,
                    "error": f"VirusTotal API timeout after {max_retries} attempts",
                    "error_type": "timeout",
                    "source": service_name,
                    "status": "timeout_error"
                }
                
        except requests.exceptions.ConnectionError:
            logger.error(f"🌐 VirusTotal connection error on attempt {attempt + 1}/{max_retries}")
            if attempt == max_retries - 1:
                return {
                    "ip": ip_address,
                    "error": f"VirusTotal API connection error after {max_retries} attempts",
                    "error_type": "connection_error",
                    "source": service_name,
                    "status": "connection_error"
                }
                
        except Exception as e:
            logger.error(f"❌ Unexpected VirusTotal error: {e}")
            return {
                "ip": ip_address,
                "error": f"Unexpected error during VirusTotal lookup: {str(e)}",
                "error_type": "unexpected_error",
                "source": service_name,
                "status": "unexpected_error"
            }
        
        # Wait before retry
        if attempt < max_retries - 1:
            wait_time = 2 ** attempt
            logger.info(f"⏳ Retrying VirusTotal in {wait_time} seconds...")
            time.sleep(wait_time)
    
    # If we get here, all retries failed
    logger.error(f"❌ VirusTotal lookup failed for {ip_address} after {max_retries} attempts")
    return {
        "ip": ip_address,
        "error": f"VirusTotal lookup failed after {max_retries} attempts",
        "source": service_name,
        "status": "max_retries_exceeded"
    }


def _get_threat_level(threat_score: float) -> str:
    """Determine threat level based on score."""
    if threat_score == 0:
        return "clean"
    elif threat_score < 10:
        return "low"
    elif threat_score < 30:
        return "medium"
    elif threat_score < 70:
        return "high"
    else:
        return "critical"


def check_virustotal_tool(ip_address: str) -> Dict[str, Any]:
    """
    ADK Function Tool wrapper for VirusTotal API.
    
    This function is designed to be used as a Google ADK Function Tool.
    It provides threat intelligence analysis for IP addresses.
    
    Args:
        ip_address: The IP address to analyze
        
    Returns:
        dict: Formatted response for the ADK agent
    """
    import os
    from .cache_service import create_cache_service_from_config
    
    # Get configuration from environment
    api_key = os.getenv('VIRUSTOTAL_API_KEY')
    if not api_key:
        return {
            "status": "error",
            "service": "virustotal",
            "ip_address": ip_address,
            "error_message": "VirusTotal API key not configured",
            "error_type": "configuration_error",
            "data_source": "virustotal"
        }
    
    timeout = int(os.getenv('API_TIMEOUT', 10))
    max_retries = int(os.getenv('MAX_RETRIES', 3))
    
    # Create cache service
    cache_service = create_cache_service_from_config()
    
    # Perform lookup
    result = get_virustotal_data(
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
            "service": "virustotal",
            "ip_address": ip_address,
            "threat_analysis": {
                "is_malicious": result.get('is_malicious', False),
                "threat_score": result.get('threat_score', 0),
                "threat_level": result.get('threat_level', 'unknown'),
                "malicious_detections": result.get('malicious_count', 0),
                "suspicious_detections": result.get('suspicious_count', 0),
                "total_engines": result.get('total_engines', 0),
                "reputation": result.get('reputation', 0)
            },
            "analysis_stats": result.get('last_analysis_stats', {}),
            "detected_engines": result.get('detected_engines', []),
            "network_info": {
                "asn": result.get('asn'),
                "as_owner": result.get('as_owner'),
                "country": result.get('country'),
                "network": result.get('network')
            },
            "last_analysis_date": result.get('last_analysis_date'),
            "response_time": result.get('api_response_time'),
            "data_source": "virustotal"
        }
    elif result.get('status') == 'no_data':
        return {
            "status": "no_data",
            "service": "virustotal",
            "ip_address": ip_address,
            "message": result.get('message', 'No analysis data available'),
            "threat_analysis": {
                "is_malicious": False,
                "threat_score": 0,
                "threat_level": "unknown"
            },
            "data_source": "virustotal"
        }
    else:
        return {
            "status": "error",
            "service": "virustotal",
            "ip_address": ip_address,
            "error_message": result.get('error', 'Unknown error'),
            "error_type": result.get('error_type', 'unknown'),
            "data_source": "virustotal"
        }