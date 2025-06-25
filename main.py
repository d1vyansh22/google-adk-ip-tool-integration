# Google ADK IP Enricher Agent - Main Entry Point

"""
Main Entry Point for Google ADK IP Enricher Agent

This module provides the main entry point for the Google ADK agent
"""

import logging
from typing import Dict, Any
from config import Config, setup_logging, validate_configuration
from Enricher_Agent.agent import EnricherAgent

logger = logging.getLogger(__name__)

def get_enricher_agent() -> EnricherAgent:
    """
    Get configured enricher agent instance.
    
    Returns:
        EnricherAgent: Configured agent ready for use
    """
    # Setup logging
    setup_logging()
    
    # Validate configuration
    if not validate_configuration():
        logger.error("Configuration validation failed")
        raise ValueError("Configuration validation failed. Check your .env file and API keys.")
    
    # Initialize and return agent
    try:
        agent = EnricherAgent(Config.to_dict())
        logger.info("✅ EnricherAgent initialized successfully")
        return agent
    except Exception as e:
        logger.error(f"❌ Failed to initialize agent: {e}")
        raise

# Create global agent instance for ADK usage
enricher_agent_instance = get_enricher_agent()

# Expose the ADK agent for direct access
enricher_agent = enricher_agent_instance.agent

if __name__ == "__main__":
    # For direct execution, just verify the agent is working
    print("🛡️ Google ADK IP Enricher Agent")
    print("=" * 50)
    print("Agent initialized successfully!")
    print(f"Model: {Config.MODEL}")
    print(f"App Name: {Config.APP_NAME}")
    print("\nTo use this agent:")
    print("1. adk web --agent main:enricher_agent")
    print("2. Or import and use programmatically")