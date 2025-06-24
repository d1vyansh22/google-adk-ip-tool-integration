"""
utils package initialization.
Exposes utility functions and classes for the multi-agent system.
"""

# Optionally, expose key utilities for easier importing
from .ip_validator import validate_ip_address, validate_multiple_ips, should_analyze_ip, get_ip_classification

# Define public interface (for 'from utils import *')   
__all__ = [
    'validate_ip_address',
    'validate_multiple_ips',
    'should_analyze_ip',
    'get_ip_classification'
]

# Optionally, initialize logging or package-level variables
# import logging
# logging.basicConfig(level=logging.INFO)
# logger = logging.getLogger(__name__)
