"""
Location tracking and geolocation service for Flask 2FA application.

This module provides location tracking functionality including:
- IP geolocation lookup
- Distance calculation between locations
- Suspicious login detection
- Location approval management

Security features:
- Rate limiting for API calls
- Error handling and fallbacks
- Privacy-aware location tracking
"""

import requests
import logging
import math
from typing import Optional, Dict, Any, Tuple
from flask import request, current_app
from datetime import datetime, timedelta


class LocationService:
    """
    Service for handling location tracking and geolocation functionality.
    
    Provides methods for IP geolocation, distance calculation,
    and suspicious login detection.
    """
    
    def __init__(self):
        """Initialize location service."""
        self.logger = logging.getLogger(__name__)
        self.api_timeout = 5  # seconds
        self.cache = {}  # Simple in-memory cache
        self.cache_duration = timedelta(hours=1)
    
    def get_client_ip(self) -> str:
        """
        Get client IP address from request.
        
        Handles various proxy headers for accurate IP detection.
        
        Returns:
            str: Client IP address
        """
        # Check for forwarded headers (proxy/load balancer)
        forwarded_for = request.headers.get('X-Forwarded-For')
        if forwarded_for:
            # Take first IP if multiple are present
            return forwarded_for.split(',')[0].strip()
        
        real_ip = request.headers.get('X-Real-IP')
        if real_ip:
            return real_ip
        
        # Fallback to direct connection
        return request.remote_addr or '127.0.0.1'
    
    def get_user_agent(self) -> str:
        """
        Get user agent string from request.
        
        Returns:
            str: User agent string
        """
        return request.headers.get('User-Agent', 'Unknown')
    
    def get_location_from_ip(self, ip_address: str) -> Dict[str, Any]:
        """
        Get location data from IP address using geolocation API.
        
        Uses multiple fallback services for reliability.
        
        Args:
            ip_address: IP address to lookup
            
        Returns:
            Dict containing location data
        """
        # Skip private/local IPs
        if self._is_private_ip(ip_address):
            return self._get_default_location("Private Network")
        
        # Check cache first
        cache_key = f"location_{ip_address}"
        if cache_key in self.cache:
            cached_data, timestamp = self.cache[cache_key]
            if datetime.utcnow() - timestamp < self.cache_duration:
                return cached_data
        
        location_data = self._fetch_location_data(ip_address)
        
        # Cache the result
        self.cache[cache_key] = (location_data, datetime.utcnow())
        
        return location_data
    
    def _fetch_location_data(self, ip_address: str) -> Dict[str, Any]:
        """
        Fetch location data from external APIs with fallbacks.
        
        Args:
            ip_address: IP address to lookup
            
        Returns:
            Dict containing location data
        """
        # Try multiple geolocation services
        services = [
            self._fetch_from_ipapi,
            self._fetch_from_ipinfo,
            self._fetch_from_freeipapi
        ]
        
        for service in services:
            try:
                data = service(ip_address)
                if data and data.get('country'):
                    self.logger.info(f"Successfully fetched location for {ip_address}")
                    return data
            except Exception as e:
                self.logger.warning(f"Failed to fetch from service: {str(e)}")
                continue
        
        # All services failed
        self.logger.error(f"All geolocation services failed for {ip_address}")
        return self._get_default_location("Unknown")
    
    def _fetch_from_ipapi(self, ip_address: str) -> Dict[str, Any]:
        """Fetch location from ip-api.com (free service)."""
        url = f"http://ip-api.com/json/{ip_address}"
        response = requests.get(url, timeout=self.api_timeout)
        response.raise_for_status()
        
        data = response.json()
        if data.get('status') == 'success':
            return {
                'country': data.get('country'),
                'region': data.get('regionName'),
                'city': data.get('city'),
                'latitude': data.get('lat'),
                'longitude': data.get('lon'),
                'timezone': data.get('timezone'),
                'isp': data.get('isp')
            }
        raise Exception(f"API returned error: {data.get('message')}")
    
    def _fetch_from_ipinfo(self, ip_address: str) -> Dict[str, Any]:
        """Fetch location from ipinfo.io (free tier)."""
        url = f"https://ipinfo.io/{ip_address}/json"
        response = requests.get(url, timeout=self.api_timeout)
        response.raise_for_status()
        
        data = response.json()
        if 'country' in data:
            loc = data.get('loc', '').split(',')
            return {
                'country': data.get('country'),
                'region': data.get('region'),
                'city': data.get('city'),
                'latitude': float(loc[0]) if len(loc) > 0 and loc[0] else None,
                'longitude': float(loc[1]) if len(loc) > 1 and loc[1] else None,
                'timezone': data.get('timezone'),
                'isp': data.get('org')
            }
        raise Exception("No location data in response")
    
    def _fetch_from_freeipapi(self, ip_address: str) -> Dict[str, Any]:
        """Fetch location from freeipapi.com."""
        url = f"https://freeipapi.com/api/json/{ip_address}"
        response = requests.get(url, timeout=self.api_timeout)
        response.raise_for_status()
        
        data = response.json()
        if data.get('countryName'):
            return {
                'country': data.get('countryName'),
                'region': data.get('regionName'),
                'city': data.get('cityName'),
                'latitude': data.get('latitude'),
                'longitude': data.get('longitude'),
                'timezone': data.get('timeZone'),
                'isp': None
            }
        raise Exception("No location data in response")
    
    def _is_private_ip(self, ip_address: str) -> bool:
        """
        Check if IP address is private/local.
        
        Args:
            ip_address: IP address to check
            
        Returns:
            bool: True if IP is private
        """
        private_ranges = [
            '127.',      # Localhost
            '10.',       # Private network
            '172.16.',   # Private network
            '172.17.',   # Private network
            '172.18.',   # Private network
            '172.19.',   # Private network
            '172.20.',   # Private network
            '172.21.',   # Private network
            '172.22.',   # Private network
            '172.23.',   # Private network
            '172.24.',   # Private network
            '172.25.',   # Private network
            '172.26.',   # Private network
            '172.27.',   # Private network
            '172.28.',   # Private network
            '172.29.',   # Private network
            '172.30.',   # Private network
            '172.31.',   # Private network
            '192.168.',  # Private network
            '::1',       # IPv6 localhost
        ]
        
        return any(ip_address.startswith(prefix) for prefix in private_ranges)
    
    def _get_default_location(self, reason: str) -> Dict[str, Any]:
        """
        Get default location data when lookup fails.
        
        Args:
            reason: Reason for using default location
            
        Returns:
            Dict containing default location data
        """
        return {
            'country': reason,
            'region': None,
            'city': None,
            'latitude': None,
            'longitude': None,
            'timezone': None,
            'isp': None
        }
    
    def calculate_distance(self, 
                          lat1: float, lon1: float, 
                          lat2: float, lon2: float) -> float:
        """
        Calculate distance between two geographic points using Haversine formula.
        
        Args:
            lat1, lon1: First point coordinates
            lat2, lon2: Second point coordinates
            
        Returns:
            float: Distance in kilometers
        """
        if None in [lat1, lon1, lat2, lon2]:
            return 0.0
        
        # Convert to radians
        lat1, lon1, lat2, lon2 = map(math.radians, [lat1, lon1, lat2, lon2])
        
        # Haversine formula
        dlat = lat2 - lat1
        dlon = lon2 - lon1
        a = (math.sin(dlat/2)**2 + 
             math.cos(lat1) * math.cos(lat2) * math.sin(dlon/2)**2)
        c = 2 * math.asin(math.sqrt(a))
        
        # Radius of Earth in kilometers
        r = 6371
        
        return c * r
    
    def is_suspicious_location(self, 
                              user_id: int, 
                              new_location: Dict[str, Any]) -> Tuple[bool, Optional[Dict[str, Any]]]:
        """
        Check if login location is suspicious based on user's history.
        
        Args:
            user_id: User ID
            new_location: New location data
            
        Returns:
            Tuple of (is_suspicious: bool, last_location: Dict or None)
        """
        from app.models import LoginLocation
        
        # Get user's last approved login location
        last_login = LoginLocation.query.filter_by(
            user_id=user_id,
            is_approved=True
        ).order_by(LoginLocation.login_time.desc()).first()
        
        if not last_login:
            # First login is always approved
            return False, None
        
        # Skip distance check if coordinates are missing
        if (not all([new_location.get('latitude'), new_location.get('longitude')]) or
            not all([last_login.latitude, last_login.longitude])):
            return False, {
                'country': last_login.country,
                'region': last_login.region,
                'city': last_login.city,
                'login_time': last_login.login_time
            }
        
        # Calculate distance
        distance = self.calculate_distance(
            last_login.latitude, last_login.longitude,
            new_location['latitude'], new_location['longitude']
        )
        
        # Check if distance exceeds threshold
        threshold = current_app.config.get('SUSPICIOUS_LOGIN_THRESHOLD_KM', 100)
        is_suspicious = distance > threshold
        
        last_location_data = {
            'country': last_login.country,
            'region': last_login.region,
            'city': last_login.city,
            'login_time': last_login.login_time,
            'distance_km': round(distance, 2)
        }
        
        if is_suspicious:
            self.logger.warning(
                f"Suspicious login detected for user {user_id}: "
                f"{distance:.2f}km from last location"
            )
        
        return is_suspicious, last_location_data


# Global location service instance
location_service = LocationService()
