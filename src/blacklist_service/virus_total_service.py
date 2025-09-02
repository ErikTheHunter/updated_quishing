import os
import json
import time
import hashlib
import requests
import pickle
from pathlib import Path
from typing import Dict, Any, Optional
from urllib.parse import urlparse


class VirusTotalBlacklistChecker:
    """
    Helper class to detect if a url is blacklisted
    
    TODO: later we can convert this class into an abstract class
    the multiple subsclasses can inherit from similar to how the 
    feature extractor classes were implemented.
    
    this will easily allow us swap out blacklisting services
    """
    
    def __init__(self, api_key: str, cache_dir: str = "data/virustotal_cache"):
        """
        Initialize the class with the virus total api key.
        """
        self.api_key = api_key
        self.cache_dir = Path(cache_dir)
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        
        # set up the cache, either load existing cache or initialize a new one 
        # this is to improve performance by mainitaining high cache rate
        self.cache_data = self._load_cache()
        
        # setup our virus total feat
        self.base_url = "https://www.virustotal.com/vtapi/v2"
        self.rate_limit_delay = 15  # Free tier: 4 requests/minute
        self.last_request_time = 0
        self.request_timeout = 30
        
        # Performance tracking
        self.stats = {
            'cache_hits': 0,
            'cache_misses': 0,
            'api_calls': 0,
            'api_errors': 0
        }
    
    def check_url_reputation(self, url: str) -> Optional[Dict[str, Any]]:
        """
        Check url reputation with VirusTotal Service
        """
        # Check if the url is in the cache first to reduce calls
        cached_result = self._get_cached_result(url)
        if cached_result is not None:
            return cached_result
        
        # Always try API request
        try:
            response = self._make_virustotal_request(url)
            result = self._parse_virustotal_response(response)
            self._cache_result(url, result)
            return result
        except Exception:
            # Return None on any error (rate limits, network issues, etc.)
            return None
    
    def _get_cached_result(self, url: str) -> Optional[Dict[str, Any]]:
        """
        Check cache
        """
        try:
            url_hash = self._get_url_hash(url)
            
            if url_hash in self.cache_data:
                cached_entry = self.cache_data[url_hash]
                
                # Check cache age (24 hour expiration)
                cache_age = time.time() - cached_entry.get('timestamp', 0)
                if cache_age < 86400:  # 24 hours
                    self.stats['cache_hits'] += 1
                    return cached_entry['result']
                else:
                    # Remove expired cache entry
                    del self.cache_data[url_hash]
            
            self.stats['cache_misses'] += 1
            return None
            
        except Exception:
            return None
    
    def _make_virustotal_request(self, url: str) -> Dict[str, Any]:
        """
        Make request to virus total 
        """
        scan_response = self._submit_url_for_scan(url)
        if not scan_response.get('success', False):
            raise Exception("Failed to submit URL for scanning")
        
        # analyze the url report 
        report_response = self._get_url_report(url)
        if report_response.get('response_code') != 1:
            raise Exception("No scan report available")
        self.stats['api_calls'] += 1 # update stats
        return report_response
    
    def _submit_url_for_scan(self, url: str) -> Dict[str, Any]:
        """Submit URL to VirusTotal for scanning."""
        try:
            # setup params
            params = {
                'apikey': self.api_key, # virus total api key
                'url': url # url to scan
            }
            
            # make and scan url post 
            response = requests.post(
                f"{self.base_url}/url/scan",
                data=params,
                timeout=self.request_timeout
            )
            
            if response.status_code == 200:
                return {'success': True, 'data': response.json()}
            else:
                return {'success': False, 'error': f'HTTP {response.status_code}'}
                
        except Exception as e:
            # fallback for handling errors
            return {'success': False, 'error': str(e)}
    
    def _get_url_report(self, url: str) -> Dict[str, Any]:
        """Get VirusTotal scan report for URL."""
        try:
            # setup params again 
            params = {
                'apikey': self.api_key, # api key
                'resource': url # subject url
            }
            
            # lets make the requests
            response = requests.get(
                f"{self.base_url}/url/report",
                params=params,
                timeout=self.request_timeout
            )
            
            if response.status_code == 200:
                return response.json()
            else:
                return {'response_code': 0, 'error': f'HTTP {response.status_code}'}
                
        except Exception as e:
            # fallback for error handling 
            return {'response_code': 0, 'error': str(e)}
    
    def _parse_virustotal_response(self, response: Dict[str, Any]) -> Dict[str, Any]:
        """
        Helper function to parse the virustotal response
        and extract relevant threat information. and return in 
        a standardized format 
        """
        try:
            positives = response.get('positives', 0)
            total = response.get('total', 0)
            
            if total == 0:
                threat_score = 0.5  # Unknown
                threat_level = 'Unknown'
            else:
                threat_score = min(positives / total, 1.0)
                
                # Determine threat level following study notes thresholds
                if threat_score >= 0.1:
                    threat_level = 'High'
                elif threat_score >= 0.05:
                    threat_level = 'Medium'
                else:
                    threat_level = 'Low'
            
            return {
                'success': True,
                'threat_score': threat_score,
                'threat_level': threat_level,
                'positives': positives,
                'total_scans': total,
                'scan_date': response.get('scan_date', ''),
                'permalink': response.get('permalink', ''),
                'raw_response': response
            }
            
        except Exception as e:
            return {
                'success': False,
                'error': f'Response parsing error: {e}',
                'threat_score': 0.5,
                'threat_level': 'Unknown'
            }
    
    def _cache_result(self, url: str, result: Dict[str, Any]) -> None:
        try:
            url_hash = self._get_url_hash(url)
            
            cache_entry = {
                'url': url,
                'result': result,
                'timestamp': time.time()
            }
            
            self.cache_data[url_hash] = cache_entry
            self._save_cache()
            
        except Exception:
            # Silent failure for cache operations
            pass
    
    def _rate_limit(self) -> None:
        """
        Helper function to contorl rate limit, this is nescessary 
        because virustotal free tier limits the number of request per minute
        """
        elapsed = time.time() - self.last_request_time
        if elapsed < self.rate_limit_delay:
            time.sleep(self.rate_limit_delay - elapsed)
        self.last_request_time = time.time()
    
    def _get_url_hash(self, url: str) -> str:
        """Generate cache key using MD5 hash."""
        return hashlib.md5(url.encode('utf-8')).hexdigest()
    
    def _load_cache(self) -> Dict[str, Any]:
        """
        lets load cache from our local storgage
        """
        cache_file = self.cache_dir / "virustotal_cache.pkl"
        
        try:
            if cache_file.exists():
                with open(cache_file, 'rb') as f:
                    return pickle.load(f)
        except Exception:
            # if any error, fail silently and return an empty dict
            pass
        
        return {}
    
    def _save_cache(self) -> None:
        """
        Persist the cache to local storage for performance status.
        """
        cache_file = self.cache_dir / "virustotal_cache.pkl"
        
        try:
            with open(cache_file, 'wb') as f:
                pickle.dump(self.cache_data, f)
        except Exception:
            # Fail silently
            pass
    
    def get_cache_stats(self) -> Dict[str, Any]:
        """
        Return cache stats for performance and monitoring.
        we can configure more stats later as need bee 
        """
        total_requests = self.stats['cache_hits'] + self.stats['cache_misses']
        cache_hit_rate = self.stats['cache_hits'] / total_requests if total_requests > 0 else 0
        
        return {
            'cache_hits': self.stats['cache_hits'],
            'cache_misses': self.stats['cache_misses'],
            'api_calls': self.stats['api_calls'],
            'api_errors': self.stats['api_errors'],
            'cache_hit_rate': cache_hit_rate,
            'cached_entries': len(self.cache_data)
        }