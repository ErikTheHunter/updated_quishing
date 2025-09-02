import urllib.parse
from typing import Dict, List, Any, Optional
from .lexical_features import LexicalFeatureExtractor
from .network_features import NetworkFeatureExtractor  
from .content_features import ContentFeatureExtractor
from . import FeatureExtractor


class OptimizedURLFeatureExtractor(FeatureExtractor):
    """
    Optimized feature extractor class that combines all three 
    feature extractor class into a single class to return all 
    features.
    
    This extractor combines the most effective features while
    maintaining operational performance requirements.
    """
    
    def __init__(self, config_data: Optional[Dict[str, Any]] = None):
        super().__init__(config_data)
        
        # initialize individual extractors
        self.lexical_extractor = LexicalFeatureExtractor(config_data)
        self.network_extractor = NetworkFeatureExtractor(config_data)
        self.content_extractor = ContentFeatureExtractor(config_data)
        
        # we have optimized our feature set to this 18 features based
        # on testing and correclation analysis 
        self.optimized_features = [
            'url_length', 'special_char_count', 'path_level', 'url_entropy',
            'num_dots', 'num_subdomains', 'numeric_char_count',
            'tld_is_phishy', 'has_suspicious_keywords', 'brand_in_subdomain_or_path',
            'has_ip', 'uses_shortener', 'query_length', 'query_component_count',
            'has_homograph', 'multiple_slash_after_domain', 'https_in_hostname',
            'unusual_subdomains'
        ]
        
        # control variable to enable/disbale content analysis features
        # this is expensive and requires third party services 
        self.enable_content_analysis = config_data.get('enable_content', False) if config_data else False
    
    def extract_features(self, url: str) -> Dict[str, Any]:
        """
        extract the 18 chosen features for the url 
        """
        try:
            # Always extract lexical features (fast, no network required)
            lexical_features = self.lexical_extractor.extract_features(url)
            
            # Extract optimized feature subset
            optimized_feature_set = {
                feature: lexical_features.get(feature, 0)
                for feature in self.optimized_features
                if feature in lexical_features
            }
            
            # Optionally add network features (slower, for high-accuracy mode)
            if self.enable_content_analysis:
                network_features = self.network_extractor.extract_features(url)
                content_features = self.content_extractor.extract_features(url)
                
                # Add key network indicators
                optimized_feature_set.update({
                    'dns_resolvable': network_features.get('dns_resolvable', 0),
                    'brand_similarity_score': network_features.get('brand_similarity_score', 0.0),
                    'has_forms': content_features.get('has_forms', 0),
                    'has_password_field': content_features.get('has_password_field', 0)
                })
            
            return optimized_feature_set
            
        except Exception:
            # Return empty optimized feature set on error
            return self._get_empty_optimized_features()
    
    def extract_features_comprehensive(self, url: str) -> Dict[str, Any]:
        try:
            all_features = {}
            
            # Extract from all specialized extractors
            lexical_features = self.lexical_extractor.extract_features(url)
            network_features = self.network_extractor.extract_features(url)
            content_features = self.content_extractor.extract_features(url)
            
            # Combine all features
            all_features.update(lexical_features)
            all_features.update(network_features)
            all_features.update(content_features)
            
            return all_features
            
        except Exception:
            # Return empty comprehensive feature set
            return self._get_empty_comprehensive_features()
    
    def get_feature_names(self) -> List[str]:
        """return the featuere names that will be extracted by this extractor."""
        return self.optimized_features.copy()
    
    def get_comprehensive_feature_names(self) -> List[str]:
        """return all available feature names (50+ features)."""
        all_features = []
        all_features.extend(self.lexical_extractor.get_feature_names())
        all_features.extend(self.network_extractor.get_feature_names())
        all_features.extend(self.content_extractor.get_feature_names())
        return all_features
    
    def _get_empty_optimized_features(self) -> Dict[str, Any]:
        """return empty feature sets as fallback."""
        return {feature: 0 for feature in self.optimized_features}
    
    def _get_empty_comprehensive_features(self) -> Dict[str, Any]:
        """return empty comprehensive feature set as fallback."""
        empty_features = {}
        
        # Get empty features from all extractors
        empty_features.update(self.lexical_extractor._get_empty_features())
        empty_features.update(self.network_extractor._get_neutral_features())
        empty_features.update(self.content_extractor._get_empty_content_features())
        
        return empty_features

