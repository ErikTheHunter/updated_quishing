
import re
import socket
import urllib.parse
import requests
from typing import Dict, List, Any, Optional
from . import FeatureExtractor


class NetworkFeatureExtractor(FeatureExtractor):
    """
    Network feature extractor, this class extract domain based
    features, requires third party services to be able to get 
    domain related information.
    """
    
    def __init__(self, config_data: Optional[Dict[str, Any]] = None):
        # initialize class
        super().__init__(config_data)
        
        # popular legitimate brands usually obfuscaed for phishing attacks
        self.known_brands = {
            'google', 'facebook', 'amazon', 'microsoft', 'apple', 'paypal',
            'ebay', 'twitter', 'instagram', 'linkedin', 'netflix', 'spotify',
            'gmail', 'yahoo', 'outlook', 'dropbox', 'github', 'stackoverflow'
        }
        
        # TLD risk scores based on threat intelligence
        self.tld_risk_scores = {
            # High risk TLDs
            'tk': 0.9, 'ml': 0.9, 'ga': 0.9, 'cf': 0.9,
            'top': 0.8, 'xyz': 0.7, 'club': 0.6, 'work': 0.6,
            'click': 0.8, 'download': 0.9, 'stream': 0.7,
            
            # Medium risk TLDs  
            'info': 0.4, 'biz': 0.4, 'us': 0.3, 'cc': 0.5,
            
            # Low risk TLDs
            'com': 0.1, 'org': 0.1, 'net': 0.1, 'edu': 0.05,
            'gov': 0.05, 'mil': 0.05, 'co.uk': 0.1, 'de': 0.1
        }
        
        # max timeouts to avoid hanging processes
        self.dns_timeout = 4.0
        self.http_timeout = 4.0
    
    def extract_features(self, url: str) -> Dict[str, Any]:
        """
        main function to extract features from domains
        """
        try:
            parsed_url = urllib.parse.urlparse(url)
            features = {}
            
            # DNS and domain analysis
            features.update(self._extract_dns_features(parsed_url.netloc))
            features.update(self._extract_domain_features(parsed_url.netloc))
            features.update(self._extract_similarity_features(parsed_url.netloc))
            
            # Network security indicators
            features.update(self._extract_network_security_features(url, parsed_url))
            
            return features
            
        except Exception:
            # Return neutral features on error
            return self._get_neutral_features()
    
    def get_feature_names(self) -> List[str]:
        """Return the featuere names that will be extracted by this extractor."""
        return [
            'dns_resolvable', 'ip_address_count', 'dns_resolution_time',    
            'domain_age_days', 'domain_expiry_days', 'tld_risk_score',
            'domain_reputation_score',
            'brand_similarity_score', 'levenshtein_distance_min',
            'phonetic_similarity_max',
            'uses_non_standard_port', 'has_redirect_chain', 
            'ssl_certificate_valid', 'response_time_ms'
        ]
    
    def _extract_dns_features(self, netloc: str) -> Dict[str, Any]:
        features = {
            'dns_resolvable': 0,
            'ip_address_count': 0,
            'dns_resolution_time': 0.0
        }
        
        if not netloc:
            return features
        
        try:
            hostname = netloc.split(':')[0]
            
            # dns resolution with timeout congigured, 
            import time
            start_time = time.time()

            # set timeout to avoid hanging calls             
            socket.setdefaulttimeout(self.dns_timeout)
            dns_result = socket.gethostbyname_ex(hostname)
            resolution_time = (time.time() - start_time) * 1000  
            features['dns_resolvable'] = 1
            features['ip_address_count'] = len(dns_result[2])
            features['dns_resolution_time'] = resolution_time
            
        except (socket.gaierror, socket.timeout, OSError):
            # DNS resolution failed, rely on default fallback
            pass
        finally:
            socket.setdefaulttimeout(None)
        
        return features
    
    def _extract_domain_features(self, netloc: str) -> Dict[str, Any]:
        """extract domain-specific features."""
        features = {
            'domain_age_days': -1,
            'domain_expiry_days': -1,
            'tld_risk_score': 0.5,
            'domain_reputation_score': 0.5
        }
        
        if not netloc:
            return features
        
        try:
            hostname = netloc.split(':')[0]
            tld = hostname.split('.')[-1].lower()
            
            # top level domain risk assessment
            features['tld_risk_score'] = self.tld_risk_scores.get(tld, 0.5)
              
        except Exception:
            pass
        
        return features
    
    def _extract_similarity_features(self, netloc: str) -> Dict[str, Any]:
        """extract brand similarity features."""
        features = {
            'brand_similarity_score': 0.0,
            'levenshtein_distance_min': 100,
            'phonetic_similarity_max': 0.0
        }
        
        if not netloc:
            return features
        
        try:
            hostname = netloc.split(':')[0].lower()
            
            # calculate similarity with known brands
            max_similarity = 0.0
            min_distance = 100
            max_phonetic = 0.0
            
            for brand in self.known_brands:
                # levenshtein distance
                distance = self._levenshtein_distance(hostname, brand)
                similarity = 1 - (distance / max(len(hostname), len(brand)))
                
                max_similarity = max(max_similarity, similarity)
                min_distance = min(min_distance, distance)
                
                
            features['brand_similarity_score'] = max_similarity
            features['levenshtein_distance_min'] = min_distance
            features['phonetic_similarity_max'] = max_phonetic
            
        except Exception:
            pass
        
        return features
    
    def _extract_network_security_features(self, url: str, parsed_url) -> Dict[str, Any]:
        """extract network security features"""
        features = {
            'uses_non_standard_port': 0, # uses non standard port
            'has_redirect_chain': 0, # uses redirection
            'ssl_certificate_valid': 0, # uses ssl certificate
            'response_time_ms': 0.0 # response time in ms
        }
        
        try:
            # detect usage of any non-standard port 
            if parsed_url.port:
                standard_ports = {80, 443, 8080, 8443}
                features['uses_non_standard_port'] = 1 if parsed_url.port not in standard_ports else 0
            
            # http response analysis
            if parsed_url.scheme in ['http', 'https']:
                response_features = self._analyze_http_response(url)
                features.update(response_features)
            
        except Exception:
            pass
        
        return features
    
    def _analyze_http_response(self, url: str) -> Dict[str, Any]:
        """analyze http response"""
        features = {
            'has_redirect_chain': 0,
            'ssl_certificate_valid': 0,
            'response_time_ms': 0.0
        }
        
        try:
            # http request 
            import time
            start_time = time.time()
            
            #  fetch data 
            response = requests.head(
                url,
                timeout=self.http_timeout,
                allow_redirects=True,
                verify=True,
                headers={'User-Agent': 'PhishingDetector/1.0'}
            )
            
            # check response time
            response_time = (time.time() - start_time) * 1000  # ms
            features['response_time_ms'] = response_time
            
            # check redirection chain 
            if hasattr(response, 'history') and len(response.history) > 0:
                features['has_redirect_chain'] = 1
            
            # is ssl certificate value (for https)
            if url.startswith('https://'):
                features['ssl_certificate_valid'] = 1 if response.status_code < 400 else 0
            
        except (requests.RequestException, requests.Timeout):
            # Network failure 
            # use sensible defaults to allow for graceful degradation
            pass
        
        return features
        
    def _levenshtein_distance(self, s1: str, s2: str) -> int:
        """Calculate Levenshtein distance between two strings."""
        if len(s1) < len(s2):
            return self._levenshtein_distance(s2, s1)
        
        if len(s2) == 0:
            return len(s1)
        
        previous_row = list(range(len(s2) + 1))
        for i, c1 in enumerate(s1):
            current_row = [i + 1]
            for j, c2 in enumerate(s2):
                insertions = previous_row[j + 1] + 1
                deletions = current_row[j] + 1
                substitutions = previous_row[j] + (c1 != c2)
                current_row.append(min(insertions, deletions, substitutions))
            previous_row = current_row
        
        return previous_row[-1]
    
    def _get_neutral_features(self) -> Dict[str, Any]:
        """Return neutral feature values for error cases."""
        return {
            'dns_resolvable': 0,
            'ip_address_count': 0,
            'dns_resolution_time': 0.0,
            'domain_age_days': -1,
            'domain_expiry_days': -1,
            'tld_risk_score': 0.5,
            'domain_reputation_score': 0.5,
            'brand_similarity_score': 0.0,
            'levenshtein_distance_min': 100,
            'phonetic_similarity_max': 0.0,
            'uses_non_standard_port': 0,
            'has_redirect_chain': 0,
            'ssl_certificate_valid': 0,
            'response_time_ms': 0.0
        }