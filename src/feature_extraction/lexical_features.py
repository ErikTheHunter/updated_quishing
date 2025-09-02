import re
import math
import urllib.parse
from typing import Dict, List, Any, Optional
from . import FeatureExtractor


class LexicalFeatureExtractor(FeatureExtractor):
    """
    Lexical feature extractor, this class extract features
    based on the stucture and format of the url itself
    """
    
    def __init__(self, config_data: Optional[Dict[str, Any]] = None):
        # initialize class
        super().__init__(config_data)
        
        # suspicious keywords used often in phishing urls 
        self.suspicious_keywords = {
            'paypal', 'amazon', 'apple', 'microsoft', 'google', 'facebook',
            'login', 'signin', 'verify', 'update', 'secure', 'account',
            'suspended', 'locked', 'confirm', 'banking', 'payment'
        }
        
        # top level domains often associated with phishing
        # as sourced from trusted threat intelligence
        # we can add more here later
        self.phishy_tlds = {
            'tk', 'ml', 'ga', 'cf', 'top', 'xyz', 'club', 'work', 'click',
            'download', 'stream', 'science', 'online', 'site'
        }
        
        # url shortening services
        self.shortener_domains = {
            'bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly', 'short.link',
            'tiny.cc', 'lnkd.in', 'buff.ly', 'ift.tt'
        }
    
    def extract_features(self, url: str) -> Dict[str, Any]:
        """
        extract features for the url 
        """
        try:
            parsed_url = urllib.parse.urlparse(url)
            features = {}
            
            features['url_length'] = len(url)
            features['special_char_count'] = self._count_special_chars(url)
            features['path_level'] = self._calculate_path_level(parsed_url.path)
            features['url_entropy'] = self._calculate_entropy(url)
            features['num_dots'] = url.count('.')
            features['num_subdomains'] = self._count_subdomains(parsed_url.netloc)
            features['numeric_char_count'] = sum(c.isdigit() for c in url)
            features['tld_is_phishy'] = self._is_phishy_tld(parsed_url.netloc)
            features['has_suspicious_keywords'] = self._has_suspicious_keywords(url)
            features['brand_in_subdomain_or_path'] = self._brand_in_subdomain_or_path(url)
            features['has_ip'] = self._has_ip_address(parsed_url.netloc)
            features['uses_shortener'] = self._uses_shortener(parsed_url.netloc)
            features['query_length'] = len(parsed_url.query)
            features['query_component_count'] = len(parsed_url.query.split('&')) if parsed_url.query else 0
            features['has_homograph'] = self._detect_homograph(parsed_url.netloc)
            features['multiple_slash_after_domain'] = self._multiple_slash_after_domain(url)
            features['https_in_hostname'] = self._https_in_hostname(parsed_url.netloc)
            features['unusual_subdomains'] = self._unusual_subdomains(parsed_url.netloc)
            
            return features
            
        except Exception as e:
            # in the event of failure, return sensible defaults for graceful degradation
            return self._get_empty_features()
    
    def get_feature_names(self) -> List[str]:
        """Return the featuere names that will be extracted by this extractor."""
        return [
            'url_length', 'special_char_count', 'path_level', 'url_entropy',
            'num_dots', 'num_subdomains', 'numeric_char_count',    
            'tld_is_phishy', 'has_suspicious_keywords', 'brand_in_subdomain_or_path',
            'has_ip', 'uses_shortener', 'query_length', 'query_component_count',
            'has_homograph', 'multiple_slash_after_domain', 'https_in_hostname',
            'unusual_subdomains'
        ]
    
    def _count_special_chars(self, url: str) -> int:
        """get number of speacial characters in the url."""
        special_chars = set('!@#$%^&*()+=[]{}|\\:";\'<>?,/')
        return sum(1 for c in url if c in special_chars)
    
    def _calculate_path_level(self, path: str) -> int:
        """calculate depth path of the url."""
        if not path or path == '/':
            return 0
        return len([p for p in path.split('/') if p])
    
    def _calculate_entropy(self, url: str) -> float:
        if not url:
            return 0.0
        
        # find character frequency
        char_freq = {}
        for char in url:
            char_freq[char] = char_freq.get(char, 0) + 1
        
        # calculate entropy
        entropy = 0.0
        url_length = len(url)
        
        for freq in char_freq.values():
            probability = freq / url_length
            if probability > 0:
                entropy -= probability * math.log2(probability)
        
        return entropy
    
    def _count_subdomains(self, netloc: str) -> int:
        """number of subdomains."""
        if not netloc:
            return 0
        
        # remove port if present
        domain = netloc.split(':')[0]
        parts = domain.split('.')
        
        # minimum domain has 2 parts (domain.tld)
        return max(0, len(parts) - 2)
    
    def _is_phishy_tld(self, netloc: str) -> int:
        """check if TLD is considered phishy."""
        if not netloc:
            return 0
        
        domain = netloc.split(':')[0]
        tld = domain.split('.')[-1].lower()
        return 1 if tld in self.phishy_tlds else 0
    
    def _has_suspicious_keywords(self, url: str) -> int:
        """check suspicious keywords in URL."""
        url_lower = url.lower()
        return 1 if any(keyword in url_lower for keyword in self.suspicious_keywords) else 0
    
    def _brand_in_subdomain_or_path(self, url: str) -> int:
        """check if there are common brand names appear in suspicious part of the url string."""
        parsed_url = urllib.parse.urlparse(url)
        
        # check subdomains and path for brand keywords
        subdomain_path = f"{parsed_url.netloc}{parsed_url.path}".lower()
        
        # look for brand names in suspicious contexts
        brand_patterns = [
            r'paypal[\.-]', r'amazon[\.-]', r'apple[\.-]', r'microsoft[\.-]',
            r'google[\.-]', r'facebook[\.-]', r'bank[\.-]', r'secure[\.-]'
        ]
        
        return 1 if any(re.search(pattern, subdomain_path) for pattern in brand_patterns) else 0
    
    def _has_ip_address(self, netloc: str) -> int:
        """check if hostname is an IP address."""
        if not netloc:
            return 0
        
        # remove port if present
        hostname = netloc.split(':')[0]
        
        # ip pattern
        ip_pattern = r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$'
        
        return 1 if re.match(ip_pattern, hostname) else 0
    
    def _uses_shortener(self, netloc: str) -> int:
        """check if the url uses popular shortening service"""
        if not netloc:
            return 0
        
        domain = netloc.split(':')[0].lower()
        return 1 if domain in self.shortener_domains else 0
    
    def _detect_homograph(self, netloc: str) -> int:
        """Detect potential homograph attacks."""
        if not netloc:
            return 0
        
        # Simple homograph detection - look for mixed scripts
        domain = netloc.split(':')[0]
        
        # Check for suspicious character combinations
        suspicious_chars = ['0', '5', '>', '@', 'A', 'C', 'E']  # Cyrillic chars similar to Latin
        
        return 1 if any(char in domain for char in suspicious_chars) else 0
    
    def _multiple_slash_after_domain(self, url: str) -> int:
        """check for multiple slashes after domain."""
        pattern = r'://[^/]+//+'
        return 1 if re.search(pattern, url) else 0
    
    def _https_in_hostname(self, netloc: str) -> int:
        """check if 'https' appears in hostname (suspicious)."""
        if not netloc:
            return 0
        
        return 1 if 'https' in netloc.lower() else 0
    
    def _unusual_subdomains(self, netloc: str) -> int:
        """check for unusual subdomain patterns."""
        if not netloc:
            return 0
        
        domain = netloc.split(':')[0]
        parts = domain.split('.')
        
        # check for excessive subdomains
        if len(parts) > 4:
            return 1
        
        # check for unusual subdomain patterns
        for part in parts[:-2]:  # remove domain and TLD
            if len(part) > 20 or re.search(r'\d{4,}', part):
                return 1
        
        return 0
    
    def _get_empty_features(self) -> Dict[str, Any]:
        """return empty feature set for error cases."""
        feature_names = self.get_feature_names()
        return {name: 0 for name in feature_names}