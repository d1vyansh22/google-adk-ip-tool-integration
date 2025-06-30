"""
tools package initialization.
Exposes public tools and utilities for the multi-agent system.
"""

# Optionally, expose key tools for easier importing
from .cache_service import RedisCacheService
from .ipinfo_tool import get_ipinfo_data
from .virustotal_tool import get_virustotal_data
from .shodan_tool import get_shodan_data
from .abuseipdb_tool import get_abuseipdb_data, check_abuseipdb_tool

# Define public interface (for 'from tools import *')
__all__ = [
    'RedisCacheService',
    'get_ipinfo_data',
    'get_virustotal_data',
    'get_shodan_data',
]

# Optionally, initialize logging or package-level variables
# import logging
# logging.basicConfig(level=logging.INFO)
# logger = logging.getLogger(__name__)
