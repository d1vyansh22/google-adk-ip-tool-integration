"""
Google ADK IP Intelligence Agent

A comprehensive IP address intelligence and threat analysis system built with
Google's Agent Development Kit (ADK). This package integrates multiple threat
intelligence sources (IPInfo, VirusTotal, Shodan) to provide detailed analysis
of IP addresses for security and threat detection.

Author: Google ADK IP Intelligence Team
Version: 2.0.0
"""

__version__ = "2.0.0"
__author__ = "Google ADK IP Intelligence Team"
__description__ = "Google ADK IP Intelligence and Threat Analysis Agent"

from .agent import EnricherAgent

# Load configuration and create agent instance
from config import get_config

# Create the main agent instance
config = get_config()
enricher_agent_instance = EnricherAgent(config)

# Expose the ADK agent for direct access
enricher_agent = enricher_agent_instance.agent

# Expose the agent instance for programmatic access
__all__ = ['EnricherAgent', 'enricher_agent_instance', 'enricher_agent', 'root_agent']

root_agent = enricher_agent  # Expose as required by the loader