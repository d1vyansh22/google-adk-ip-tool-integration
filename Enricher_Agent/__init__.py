"""
Google ADK IP Tool Integration

A comprehensive IP address intelligence and threat analysis system built with 
Google's Agent Development Kit (ADK). This package integrates multiple threat 
intelligence sources (IPInfo, VirusTotal, Shodan) to provide detailed analysis 
of IP addresses for security and threat detection.

Author: IP Tool Integration Team
Version: 1.0.0
"""

__version__ = "1.0.0"
__author__ = "IP Tool Integration Team"
__description__ = "Google ADK IP Intelligence and Threat Analysis Agent"

from . import agent
from .agent import EnricherAgent

# You may need to load config here, e.g. from a config file or environment
config = {}  # Replace with actual config loading logic
enricher_agent_instance = EnricherAgent(config)
root_agent = enricher_agent_instance.agent  # or .root_agent if that's the attribute
