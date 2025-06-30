"""
AbuseIPDB API Tool for Google ADK

This tool integrates with AbuseIPDB API to check IP addresses for reported abuse activity.
Provides threat intelligence and reputation scoring.
"""

import requests
import logging
import time
from typing import Dict, Any, Optional
from .cache_service import RedisCacheService

logger = logging.getLogger(__name__)


def get_abuseipdb_data(ip_address: str, api_key: str,
                      cache_service: Optional[RedisCacheService] = None,
                      timeout: int = 10, max_retries: int = 3) -> Dict[str, Any]:
    """
    Fetches IP reputation data from AbuseIPDB API with caching and retry logic.

    Args:
        ip_address: The IP address to check (e.g., "8.8.8.8")
        api_key: AbuseIPDB API key (required)
        cache_service: Redis cache service instance (optional)
        timeout: Request timeout in seconds (default: 10)
        max_retries: Maximum number of retry attempts (default: 3)

    Returns:
        dict: AbuseIPDB analysis results including abuse confidence score and reports
              Returns error information if lookup fails
    """
    service_name = "abuseipdb"

    # Check cache first if available
    if cache_service and cache_service.is_available():
        cached_data = cache_service.get_cached_data(ip_address, service_name)
        if cached_data:
            logger.info(f"[-] Retrieved {ip_address} from AbuseIPDB cache")
            return cached_data

    base_url = "https://api.abuseipdb.com/api/v2/check"

    for attempt in range(max_retries):
        try:
            params = {
                "ipAddress": ip_address,
                "maxAgeInDays": 90  # configurable if needed
            }
            headers = {
                "Key": api_key,
                "Accept": "application/json",
                "User-Agent": "google-adk-ip-enricher/1.0"
            }
            logger.debug(f"[-] AbuseIPDB API call attempt {attempt + 1} for {ip_address}")
            start_time = time.time()
            response = requests.get(base_url, headers=headers, params=params, timeout=timeout)
            elapsed_time = time.time() - start_time

            if response.status_code == 200:
                data = response.json().get("data", {})
                abuse_confidence_score = data.get("abuseConfidenceScore", 0)
                total_reports = data.get("totalReports", 0)
                country_code = data.get("countryCode")
                isp = data.get("isp")
                domain = data.get("domain")
                usage_type = data.get("usageType")
                last_reported_at = data.get("lastReportedAt")
                num_distinct_users = data.get("numDistinctUsers", 0)
                is_whitelisted = data.get("isWhitelisted", False)

                result = {
                    "ip": ip_address,
                    "abuse_confidence_score": abuse_confidence_score,
                    "total_reports": total_reports,
                    "country_code": country_code,
                    "isp": isp,
                    "domain": domain,
                    "usage_type": usage_type,
                    "last_reported_at": last_reported_at,
                    "num_distinct_users": num_distinct_users,
                    "is_whitelisted": is_whitelisted,
                    "source": service_name,
                    "api_response_time": round(elapsed_time, 3),
                    "status": "success"
                }

                if cache_service and cache_service.is_available():
                    cache_service.cache_data(ip_address, service_name, result)

                logger.info(f"[-] AbuseIPDB lookup successful for {ip_address} ({elapsed_time:.3f}s)")
                return result

            elif response.status_code == 429:
                logger.warning(f"[x] AbuseIPDB rate limit exceeded. Attempt {attempt + 1}/{max_retries}")
                if attempt < max_retries - 1:
                    wait_time = 2 ** attempt
                    logger.info(f"[-] Waiting {wait_time} seconds before retry...")
                    time.sleep(wait_time)

            elif response.status_code == 404:
                logger.warning(f"[x] AbuseIPDB: No data found for IP {ip_address}")
                return {
                    "ip": ip_address,
                    "message": "No abuse data found for this IP address",
                    "abuse_confidence_score": 0,
                    "total_reports": 0,
                    "source": service_name,
                    "status": "no_data"
                }

            elif response.status_code == 401:
                logger.error(f"[x] AbuseIPDB: Authentication failed")
                return {
                    "ip": ip_address,
                    "error": "AbuseIPDB API authentication failed. Check your API key.",
                    "error_code": 401,
                    "source": service_name,
                    "status": "auth_error"
                }

            else:
                logger.error(f"[x] AbuseIPDB HTTP Error {response.status_code}: {response.text}")
                if attempt == max_retries - 1:
                    return {
                        "ip": ip_address,
                        "error": f"AbuseIPDB API error: HTTP {response.status_code}",
                        "error_code": response.status_code,
                        "source": service_name,
                        "status": "api_error"
                    }

        except requests.exceptions.Timeout:
            logger.error(f"[-] AbuseIPDB timeout on attempt {attempt + 1}/{max_retries}")
            if attempt == max_retries - 1:
                return {
                    "ip": ip_address,
                    "error": f"AbuseIPDB API timeout after {max_retries} attempts",
                    "error_type": "timeout",
                    "source": service_name,
                    "status": "timeout_error"
                }

        except requests.exceptions.ConnectionError:
            logger.error(f"[-] AbuseIPDB connection error on attempt {attempt + 1}/{max_retries}")
            if attempt == max_retries - 1:
                return {
                    "ip": ip_address,
                    "error": f"AbuseIPDB API connection error after {max_retries} attempts",
                    "error_type": "connection_error",
                    "source": service_name,
                    "status": "connection_error"
                }

        except Exception as e:
            logger.error(f"[x] Unexpected AbuseIPDB error: {e}")
            return {
                "ip": ip_address,
                "error": f"Unexpected error during AbuseIPDB lookup: {str(e)}",
                "error_type": "unexpected_error",
                "source": service_name,
                "status": "unexpected_error"
            }

        # Wait before retry (exponential backoff)
        if attempt < max_retries - 1:
            wait_time = 2 ** attempt
            logger.info(f"[-] Retrying AbuseIPDB in {wait_time} seconds...")
            time.sleep(wait_time)

    # If we get here, all retries failed
    logger.error(f"[x] AbuseIPDB lookup failed for {ip_address} after {max_retries} attempts")
    return {
        "ip": ip_address,
        "error": f"AbuseIPDB lookup failed after {max_retries} attempts",
        "source": service_name,
        "status": "max_retries_exceeded"
    }


def check_abuseipdb_tool(ip_address: str) -> Dict[str, Any]:
    """
    ADK Function Tool wrapper for AbuseIPDB API.

    This function is designed to be used as a Google ADK Function Tool.
    It provides abuse intelligence analysis for IP addresses.

    Args:
        ip_address: The IP address to analyze

    Returns:
        dict: Formatted response for the ADK agent
    """
    import os
    from .cache_service import create_cache_service_from_config

    api_key = os.getenv('ABUSEIPDB_API_KEY')
    if not api_key:
        return {
            "status": "error",
            "service": "abuseipdb",
            "ip_address": ip_address,
            "error_message": "AbuseIPDB API key not configured",
            "error_type": "configuration_error",
            "data_source": "abuseipdb"
        }

    timeout = int(os.getenv('API_TIMEOUT', 10))
    max_retries = int(os.getenv('MAX_RETRIES', 3))
    cache_service = create_cache_service_from_config()

    result = get_abuseipdb_data(
        ip_address=ip_address,
        api_key=api_key,
        cache_service=cache_service,
        timeout=timeout,
        max_retries=max_retries
    )

    if result.get('status') == 'success':
        return {
            "status": "success",
            "service": "abuseipdb",
            "ip_address": ip_address,
            "abuse_confidence_score": result.get('abuse_confidence_score', 0),
            "total_reports": result.get('total_reports', 0),
            "country_code": result.get('country_code'),
            "isp": result.get('isp'),
            "domain": result.get('domain'),
            "usage_type": result.get('usage_type'),
            "last_reported_at": result.get('last_reported_at'),
            "num_distinct_users": result.get('num_distinct_users', 0),
            "is_whitelisted": result.get('is_whitelisted', False),
            "response_time": result.get('api_response_time'),
            "data_source": "abuseipdb"
        }
    elif result.get('status') == 'no_data':
        return {
            "status": "no_data",
            "service": "abuseipdb",
            "ip_address": ip_address,
            "message": result.get('message', 'No abuse data available'),
            "abuse_confidence_score": 0,
            "total_reports": 0,
            "data_source": "abuseipdb"
        }
    else:
        return {
            "status": "error",
            "service": "abuseipdb",
            "ip_address": ip_address,
            "error_message": result.get('error', 'Unknown error'),
            "error_type": result.get('error_type', 'unknown'),
            "data_source": "abuseipdb"
        } 