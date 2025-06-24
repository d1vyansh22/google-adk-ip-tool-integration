"""
Enhanced Configuration Management for Multi-Agent IP Threat Intelligence System
==============================================================================

This configuration module manages all API keys, service settings, and system
parameters for the comprehensive IP threat intelligence analysis system.

Features:
- Environment variable loading with validation
- API key management for multiple threat intelligence sources
- Redis caching configuration
- Google ADK model settings
- Logging configuration
- Rate limiting and timeout settings

Author: Enhanced IP Threat Intelligence System
Version: 2.0.0
"""
import os
from typing import Dict, Any, Optional
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

class Config:
    """Configuration class for the IP Enricher Agent."""
    
    # API Keys - retrieved from environment variables
    IPINFO_API_KEY: Optional[str] = os.getenv('IPINFO_API_KEY')
    VIRUSTOTAL_API_KEY: Optional[str] = os.getenv('VIRUSTOTAL_API_KEY')
    SHODAN_API_KEY: Optional[str] = os.getenv('SHODAN_API_KEY')
    
    # API Configuration
    API_TIMEOUT: int = int(os.getenv('API_TIMEOUT', '10'))
    MAX_RETRIES: int = int(os.getenv('MAX_RETRIES', '3'))
    MAX_CONCURRENT_REQUESTS: int = int(os.getenv('MAX_CONCURRENT_REQUESTS', '10'))
    
    # Redis Configuration
    REDIS_HOST: str = os.getenv('REDIS_HOST', 'localhost')
    REDIS_PORT: int = int(os.getenv('REDIS_PORT', '6379'))
    REDIS_DB: int = int(os.getenv('REDIS_DB', '0'))
    REDIS_PASSWORD: Optional[str] = os.getenv('REDIS_PASSWORD')
    CACHE_TTL: int = int(os.getenv('CACHE_TTL', '86400'))  # 24 hours default
    
    # Google ADK Configuration
    MODEL: str = os.getenv('ADK_MODEL', 'gemini-2.0-flash')
    APP_NAME: str = os.getenv('APP_NAME', 'ip-enricher-agent')
    
    # Logging Configuration
    LOG_LEVEL: str = os.getenv('LOG_LEVEL', 'INFO')
    LOG_FORMAT: str = os.getenv('LOG_FORMAT', '%(asctime)s %(levelname)s [%(name)s]: %(message)s')
    
    # Feature Flags
    ENABLE_CACHE: bool = os.getenv('ENABLE_CACHE', 'true').lower() == 'true'
    ENABLE_IPINFO: bool = os.getenv('ENABLE_IPINFO', 'true').lower() == 'true'
    ENABLE_VIRUSTOTAL: bool = os.getenv('ENABLE_VIRUSTOTAL', 'true').lower() == 'true'
    ENABLE_SHODAN: bool = os.getenv('ENABLE_SHODAN', 'true').lower() == 'true'
    
    @classmethod
    def to_dict(cls) -> Dict[str, Any]:
        """Convert configuration to dictionary."""
        return {
            # API Keys
            'IPINFO_API_KEY': cls.IPINFO_API_KEY,
            'VIRUSTOTAL_API_KEY': cls.VIRUSTOTAL_API_KEY,
            'SHODAN_API_KEY': cls.SHODAN_API_KEY,
            
            # API Configuration
            'API_TIMEOUT': cls.API_TIMEOUT,
            'MAX_RETRIES': cls.MAX_RETRIES,
            'MAX_CONCURRENT_REQUESTS': cls.MAX_CONCURRENT_REQUESTS,
            
            # Redis Configuration
            'REDIS_HOST': cls.REDIS_HOST,
            'REDIS_PORT': cls.REDIS_PORT,
            'REDIS_DB': cls.REDIS_DB,
            'REDIS_PASSWORD': cls.REDIS_PASSWORD,
            'CACHE_TTL': cls.CACHE_TTL,
            
            # Google ADK Configuration
            'MODEL': cls.MODEL,
            'APP_NAME': cls.APP_NAME,
            
            # Logging Configuration
            'LOG_LEVEL': cls.LOG_LEVEL,
            'LOG_FORMAT': cls.LOG_FORMAT,
            
            # Feature Flags
            'ENABLE_CACHE': cls.ENABLE_CACHE,
            'ENABLE_IPINFO': cls.ENABLE_IPINFO,
            'ENABLE_VIRUSTOTAL': cls.ENABLE_VIRUSTOTAL,
            'ENABLE_SHODAN': cls.ENABLE_SHODAN
        }
    
    @classmethod
    def validate_config(cls) -> Dict[str, Any]:
        """
        Validate configuration and return status report.
        
        Returns:
            dict: Configuration validation results
        """
        validation_results = {
            'valid': True,
            'warnings': [],
            'errors': [],
            'api_keys_status': {},
            'services_available': {}
        }
        
        # Check API keys
        api_keys = {
            'IPInfo': cls.IPINFO_API_KEY,
            'VirusTotal': cls.VIRUSTOTAL_API_KEY,
            'Shodan': cls.SHODAN_API_KEY
        }
        
        for service, api_key in api_keys.items():
            if api_key:
                validation_results['api_keys_status'][service] = 'configured'
                validation_results['services_available'][service] = True
            else:
                validation_results['api_keys_status'][service] = 'missing'
                validation_results['services_available'][service] = False
                validation_results['warnings'].append(f"{service} API key not configured")
        
        # Check if at least one API key is configured
        if not any(validation_results['services_available'].values()):
            validation_results['valid'] = False
            validation_results['errors'].append("No API keys configured. At least one threat intelligence service is required.")
        
        # Validate numeric configurations
        if cls.API_TIMEOUT <= 0:
            validation_results['errors'].append("API_TIMEOUT must be greater than 0")
            validation_results['valid'] = False
        
        if cls.MAX_RETRIES < 0:
            validation_results['errors'].append("MAX_RETRIES must be non-negative")
            validation_results['valid'] = False
        
        if cls.CACHE_TTL <= 0:
            validation_results['warnings'].append("CACHE_TTL should be greater than 0 for effective caching")
        
        # Check Redis configuration
        try:
            if cls.REDIS_PORT < 1 or cls.REDIS_PORT > 65535:
                validation_results['errors'].append("REDIS_PORT must be between 1 and 65535")
                validation_results['valid'] = False
        except ValueError:
            validation_results['errors'].append("REDIS_PORT must be a valid integer")
            validation_results['valid'] = False
        
        return validation_results
    
    @classmethod
    def print_config_status(cls) -> None:
        """Print configuration status to console."""
        print("\n" + "=" * 60)
        print("🔧 IP ENRICHER AGENT CONFIGURATION STATUS")
        print("=" * 60)
        
        validation = cls.validate_config()
        
        # Overall status
        if validation['valid']:
            print("✅ Configuration Status: VALID")
        else:
            print("❌ Configuration Status: INVALID")
        
        print(f"\n📊 Google ADK Model: {cls.MODEL}")
        print(f"📱 Application Name: {cls.APP_NAME}")
        
        # API Services
        print(f"\n🔌 API Services:")
        for service, available in validation['services_available'].items():
            status = "✅ Available" if available else "❌ Not configured"
            print(f"   {service}: {status}")
        
        # Redis Configuration
        print(f"\n💾 Redis Configuration:")
        print(f"   Host: {cls.REDIS_HOST}:{cls.REDIS_PORT}")
        print(f"   Database: {cls.REDIS_DB}")
        print(f"   Cache TTL: {cls.CACHE_TTL} seconds ({cls.CACHE_TTL // 3600} hours)")
        print(f"   Enabled: {'Yes' if cls.ENABLE_CACHE else 'No'}")
        
        # API Configuration
        print(f"\n⚡ API Configuration:")
        print(f"   Timeout: {cls.API_TIMEOUT} seconds")
        print(f"   Max Retries: {cls.MAX_RETRIES}")
        print(f"   Max Concurrent: {cls.MAX_CONCURRENT_REQUESTS}")
        
        # Warnings and Errors
        if validation['warnings']:
            print(f"\n⚠️  Warnings:")
            for warning in validation['warnings']:
                print(f"   • {warning}")
        
        if validation['errors']:
            print(f"\n❌ Errors:")
            for error in validation['errors']:
                print(f"   • {error}")
        
        print("=" * 60 + "\n")


def get_config() -> Dict[str, Any]:
    """Get configuration as dictionary."""
    return Config.to_dict()


def validate_configuration() -> bool:
    """
    Validate configuration and return True if valid.
    
    Returns:
        bool: True if configuration is valid, False otherwise
    """
    validation = Config.validate_config()
    return validation['valid']


def setup_logging() -> None:
    """Set up logging configuration."""
    import logging
    
    # Configure logging
    logging.basicConfig(
        level=getattr(logging, Config.LOG_LEVEL.upper()),
        format=Config.LOG_FORMAT,
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    
    # Set specific logger levels
    logging.getLogger('google.adk').setLevel(logging.INFO)
    logging.getLogger('redis').setLevel(logging.WARNING)
    logging.getLogger('urllib3').setLevel(logging.WARNING)


# Global configuration instance
config = get_config()


# Configuration validation on import
if __name__ == "__main__":
    Config.print_config_status()