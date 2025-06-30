"""
Redis Cache Service for IP Intelligence Data

This module provides Redis caching functionality for IP intelligence data from multiple sources.
"""

import redis
import json
import time
import logging
from typing import Optional, Dict, Any, List, Union, cast
from redis.exceptions import RedisError, ConnectionError
import os

logger = logging.getLogger(__name__)

class RedisCacheService:
    """Redis cache service for IP intelligence data with health monitoring."""
    
    def __init__(self, host: str = 'localhost', port: int = 6379, db: int = 0, 
                 password: Optional[str] = None, ttl: int = 86400):
        """
        Initialize Redis cache service.
        
        Args:
            host: Redis host (default: localhost)
            port: Redis port (default: 6379)  
            db: Redis database number (default: 0)
            password: Redis password (optional)
            ttl: Cache time-to-live in seconds (default: 24 hours)
        """
        self.host = host
        self.port = port
        self.db = db
        self.password = password
        self.ttl = ttl
        
        # Initialize Redis client with error handling
        try:
            self.redis_client = redis.Redis(
                host=self.host,
                port=self.port,
                db=self.db,
                password=self.password,
                decode_responses=True,  # Critical for type safety
                socket_timeout=3,  # Fail fast on network issues
                socket_connect_timeout=3,  # Quick failure if Redis down
                protocol=3  # Explicit protocol version
            )
            
            # Test connection
            self.redis_client.ping()
            self.redis_available = True
            logger.info(f"[-] Redis connected successfully at {host}:{port}")
            
        except redis.RedisError as e:
            logger.error(f"[x] Redis unavailable: {e}")
            self.redis_available = False
            self.redis_client = None
            
        # Metrics tracking
        self.metrics = {
            'hits': 0,
            'misses': 0, 
            'failures': 0,
            'stores': 0
        }
    
    def is_available(self) -> bool:
        """Check if Redis is available."""
        return self.redis_available and self.redis_client is not None
    
    def get_cached_data(self, ip_address: str, service_name: str) -> Optional[Dict[str, Any]]:
        """
        Retrieve cached data for an IP address from a specific service.
        
        Args:
            ip_address: The IP address to lookup
            service_name: The service name (ipinfo, virustotal, shodan)
            
        Returns:
            Cached data dictionary or None if not found
        """
        if not self.is_available():
            return None
            
        key = f"{service_name}:{ip_address}"
        
        try:
            if self.redis_client is None:
                raise redis.RedisError("Redis client is not initialized")
            cached: Optional[str] = cast(Optional[str], self.redis_client.get(key))
            if cached:
                self.metrics['hits'] += 1
                logger.debug(f"[-] Cache HIT for {service_name}:{ip_address}")
                return json.loads(cached)
            else:
                self.metrics['misses'] += 1
                logger.debug(f"[x] Cache MISS for {service_name}:{ip_address}")
                return None
                
        except (redis.RedisError, json.JSONDecodeError) as e:
            self.metrics['failures'] += 1
            logger.warning(f"[!] Redis cache error for {key}: {e}")
            return None
    
    def cache_data(self, ip_address: str, service_name: str, data: Dict[str, Any]) -> bool:
        """
        Cache data for an IP address from a specific service.
        
        Args:
            ip_address: The IP address
            service_name: The service name (ipinfo, virustotal, shodan)
            data: Data to cache
            
        Returns:
            True if cached successfully, False otherwise
        """
        if not self.is_available():
            return False
            
        key = f"{service_name}:{ip_address}"
        
        try:
            # Add timestamp to cached data
            cache_data = {
                **data,
                '_cached_at': time.time(),
                '_service': service_name
            }
            
            if self.redis_client is None:
                raise redis.RedisError("Redis client is not initialized")
            
            success = self.redis_client.setex(
                name=key,
                time=self.ttl,
                value=json.dumps(cache_data)
            )
            
            if success:
                self.metrics['stores'] += 1
                logger.debug(f"[-] Cached data for {service_name}:{ip_address}")
                return True
            else:
                self.metrics['failures'] += 1
                return False
                
        except redis.RedisError as e:
            self.metrics['failures'] += 1
            logger.warning(f"[!] Redis store error for {key}: {e}")
            return False
    
    def is_cached(self, ip_address: str, service_name: str) -> bool:
        """
        Check if an IP address is cached for a specific service.
        
        Args:
            ip_address: The IP address
            service_name: The service name
            
        Returns:
            True if cached, False otherwise
        """
        if not self.is_available():
            return False
            
        key = f"{service_name}:{ip_address}"
        if self.redis_client is None:
            logger.warning("[!] Redis client is not available when checking cache for %s", key)
            return False
        try:
            exists = self.redis_client.exists(key)
            return bool(exists)
        except redis.RedisError as e:
            logger.warning(f"[!] Redis exists check error for {key}: {e}")
            return False
        

    
    def get_metrics(self) -> Dict[str, Any]:
        """Return cache metrics."""
        total_requests = self.metrics['hits'] + self.metrics['misses']
        hit_rate = (self.metrics['hits'] / total_requests * 100) if total_requests > 0 else 0
        
        return {
            'hits': self.metrics['hits'],
            'misses': self.metrics['misses'],
            'failures': self.metrics['failures'],
            'stores': self.metrics['stores'],
            'total_requests': total_requests,
            'hit_rate_percent': round(hit_rate, 2)
        }
    
    def get_health_info(self) -> Dict[str, Any]:
        """
        Get Redis health and connection information.
        
        Returns:
            Dict[str, Any]: Health information dictionary
        """
        if not self.redis_available or self.redis_client is None:
            return {
                'status': 'unavailable',
                'connection': False,
                'host': self.host,
                'port': self.port,
                'error': 'Redis client not initialized'
            }
        
        try:
            # info() returns a dictionary
            info_data = self.redis_client.info()
            
            health_info = {
                'status': 'connected',
                'connection': True,
                'host': self.host,
                'port': self.port,
                'redis_version': None,
                'memory_usage': None,
                'connected_clients': None
            }
            
            # Safely extract information if info_data is a dictionary
            if isinstance(info_data, dict):
                health_info.update({
                    'redis_version': info_data.get('redis_version'),
                    'memory_usage': info_data.get('used_memory_human'),
                    'connected_clients': info_data.get('connected_clients')
                })
            
            return health_info
            
        except (redis.RedisError, Exception) as e:
            logger.warning(f"[x] Redis health check error: {e}")
            return {
                'status': 'error',
                'connection': False,
                'host': self.host,
                'port': self.port,
                'error': str(e)
            }


def create_cache_service_from_config() -> RedisCacheService:
    """Create cache service from environment configuration."""
    return RedisCacheService(
        host=os.getenv('REDIS_HOST', 'localhost'),
        port=int(os.getenv('REDIS_PORT', 6379)),
        db=int(os.getenv('REDIS_DB', 0)),
        password=os.getenv('REDIS_PASSWORD'),
        ttl=int(os.getenv('CACHE_TTL', 86400))
    )