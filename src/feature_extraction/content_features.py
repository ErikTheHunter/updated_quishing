import re
import urllib.parse
import requests
from typing import Dict, List, Any, Optional
from bs4 import BeautifulSoup
from . import FeatureExtractor


class ContentFeatureExtractor(FeatureExtractor):
    """
    Content feature extractor, this class leverages 
    beautiful soup to extract features from html pages, 
    the class leverages smart approaches to extract content 
    to be able to bypass url shorteners and reading of 
    html content safely to avoid executing malicious javascript
    """
    
    def __init__(self, config_data: Optional[Dict[str, Any]] = None):
        # initialize class
        super().__init__(config_data)
        
        
        
        # configurations for security and resilience
        self.max_content_size = 500000  # max page size 500kb
        self.request_timeout = 4.0      # timeout wait 4 seconds
        self.max_redirects = 3          # max redirects allowed
        
        # suspicious html patterns
        self.suspicious_patterns = [
            r'eval\s*\(',
            r'document\.write\s*\(',
            r'innerHTML\s*=',
            r'base64',
            r'fromCharCode',
            r'unescape\s*\(',
            r'decode\s*\('
        ]
    
    def extract_features(self, url: str) -> Dict[str, Any]:
        """
        extract features from html such as number of form tags etc
        """
        try:
            # dict of features
            features = {}
            
            # fetch page 
            content, response_info = self._retrieve_content_safely(url)
            
            if content:
                # analyze html
                features.update(self._analyze_html_structure(content))
                
                # analyze any form/input on the page 
                features.update(self._analyze_forms(content, url))
                
                # we also analyze any metadata on the page
                features.update(self._analyze_metadata(content))
            else:
                features.update(self._get_empty_content_features())
            
            features.update(response_info)
            return features
            
        except Exception:
            # in the event of failure, return sensible defaults for graceful degradation
            return self._get_empty_content_features()
    
    def get_feature_names(self) -> List[str]:
        """Return the featuere names that will be extracted by this extractor."""
        return [
            # HTML structure features
            'has_forms', 'has_iframes', 'has_scripts', 'input_field_count',
            'has_title', 'has_favicon', 'meta_tag_count', 'link_count',
            
            # Form analysis features
            'has_password_field', 'external_form_submit', 'form_method_post',
            'suspicious_form_action',
            
            # Script analysis features
            'script_count', 'external_script_count', 'suspicious_script_patterns',
            'obfuscated_javascript',
            
            # Response metadata features
            'content_length', 'has_ssl_certificate', 'redirect_count',
            'response_status_code'
        ]
    
    def _retrieve_content_safely(self, url: str) -> tuple[Optional[str], Dict[str, Any]]:
        """
        Helper function to determine if a url is safe to processing.
        """
        response_info = {
            'content_length': 0,
            'has_ssl_certificate': 0,
            'redirect_count': 0,
            'response_status_code': 0
        }
        
        try:
            # fetch url
            response = requests.get(
                url,
                timeout=self.request_timeout,
                allow_redirects=True,
                verify=True,
                headers={'User-Agent': 'PhishingDetector/1.0'},
                stream=True
            )
            
            # update respone info dict
            response_info['response_status_code'] = response.status_code
            response_info['redirect_count'] = len(response.history)
            response_info['has_ssl_certificate'] = 1 if url.startswith('https://') else 0
            
            # limit size of page read, for security reasons
            content = response.raw.read(self.max_content_size)
            content_text = content.decode('utf-8', errors='ignore')
            
            response_info['content_length'] = len(content_text)
            
            return content_text, response_info
            
        except (requests.RequestException, requests.Timeout, UnicodeDecodeError):
            # Fail gracefully for errors 
            return None, response_info
    
    def _analyze_html_structure(self, content: str) -> Dict[str, Any]:
        """helper function to analyze html content."""
        features = {
            'has_forms': 0,
            'has_iframes': 0,
            'has_scripts': 0,
            'input_field_count': 0,
            'has_title': 0,
            'has_favicon': 0,
            'meta_tag_count': 0,
            'link_count': 0
        }
        
        try:
            soup = BeautifulSoup(content, 'html.parser')
            
            # Basic HTML structure
            features['has_forms'] = len(soup.find_all('form'))
            features['has_iframes'] = len(soup.find_all('iframe'))
            features['has_scripts'] = len(soup.find_all('script'))
            features['input_field_count'] = len(soup.find_all('input'))
            features['meta_tag_count'] = len(soup.find_all('meta'))
            features['link_count'] = len(soup.find_all('a'))
            
            # check for some metadata properties
            features['has_title'] = 1 if soup.title and soup.title.string else 0
            features['has_favicon'] = 1 if soup.find('link', rel='icon') else 0
            
        except Exception:
            # html analysis failed, we fall back to sensible defaults
            pass
        
        return features
    
    def _analyze_forms(self, content: str, url: str) -> Dict[str, Any]:
        """analyze form elements if found on the page."""
        features = {
            'has_password_field': 0,
            'external_form_submit': 0,
            'form_method_post': 0,
            'suspicious_form_action': 0
        }
        
        try:
            soup = BeautifulSoup(content, 'html.parser')
            parsed_url = urllib.parse.urlparse(url)
            domain = parsed_url.netloc
            
            # use beautiful soup to find all forms 
            forms = soup.find_all('form')
            
            for form in forms:
                # serach for password fields
                if form.find('input',type='password'):
                    features['has_password_field'] = 1
                
                method = form.get('method', '').lower()
                if method == 'post':
                    features['form_method_post'] = 1
                
                # analyze the form behavior, is it submitting to external source
                action = form.get('action', '')
                if action:
                    # check if the form action is submitting externally
                    if action.startswith('http') and domain not in action:
                        features['external_form_submit'] = 1
                    
                    # also check for suspicious form actions
                    suspicious_actions = ['data:', 'javascript:', 'vbscript:']
                    if any(action.lower().startswith(sa) for sa in suspicious_actions):
                        features['suspicious_form_action'] = 1
        
        except Exception:
            # form analysis failed, we fall back to sensible defaults
            pass
        
        return features
  
    def _analyze_metadata(self, content: str) -> Dict[str, Any]:
        """Analyze metadata and document properties."""
        features = {}
        
        try:
            soup = BeautifulSoup(content, 'html.parser')
            
            # we will extract favicon and html title 
            
            
        except Exception:
            pass
        
        return features
    
    def _detect_obfuscation(self, script_content: str) -> bool:
        """detect potential js obfuscation."""
        if not script_content or len(script_content) < 50:
            return False
        
        # basic obfuscation indicators
        obfuscation_indicators = [
            len(re.findall(r'\\x[0-9a-fA-F]{2}', script_content)) > 5,  # Hex encoding
            len(re.findall(r'String\.fromCharCode', script_content)) > 0,  # Char code conversion
            len(re.findall(r'eval\s*\(', script_content)) > 0,  # Dynamic evaluation
            script_content.count('+') > len(script_content) / 20,  # Excessive concatenation
        ]
        
        return sum(obfuscation_indicators) >= 2
    
    def _get_empty_content_features(self) -> Dict[str, Any]:
        """Return empty feature set for content analysis failures."""
        return {
            # html features
            'has_forms': 0, 'has_iframes': 0, 'has_scripts': 0, 'input_field_count': 0,
            'has_title': 0, 'has_favicon': 0, 'meta_tag_count': 0, 'link_count': 0,
            
            # html form features
            'has_password_field': 0, 'external_form_submit': 0, 'form_method_post': 0,
            'suspicious_form_action': 0,
            
            'script_count': 0, 'external_script_count': 0, 'suspicious_script_patterns': 0,
            'obfuscated_javascript': 0,
            
            'content_length': 0, 'has_ssl_certificate': 0, 'redirect_count': 0,
            'response_status_code': 0
        }