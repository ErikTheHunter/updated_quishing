from abc import ABC, abstractmethod
from typing import Dict, List, Any, Optional


class FeatureExtractor(ABC):
    """
    Abstract base class for our URL feature extractors.
    
    All concrete implmentations of this features like lexical, network, content must inherit 
    and implement the features extraction methods we define here.
    """
    
    def __init__(self, config_data: Optional[Dict[str, Any]] = None):
        """
        Initalize the class
        """
        self.config = config_data or {}
    
    @abstractmethod
    def extract_features(self, url: str) -> Dict[str, Any]:
        """
        Extract features form a URL, must be implemented 
        by subclasses if not an error an error is raised
        """
        raise NotImplementedError("did not implement 'extract_features' in subclass!")
    
    @abstractmethod
    def get_feature_names(self) -> List[str]:
        """
        Get list of features names extracted by this class.
        """
        raise NotImplementedError("Subclasses need to define 'get_feature_names', or this won't work!")


class FeatureExtractorFactory:
    """
    Factory class to easily create feature extractor classes
    """
    
    @staticmethod
    def create_extractor(extractor_type: str, config: Optional[Dict[str, Any]] = None) -> FeatureExtractor:
        """
        Creates an extractor class on the extrator type provided and configs
        
        arguments:
            extractor_type: type of extractor options are ("lexical", "network", "content")
            config: Configuration dictionary for the extractor
            
        return:
            a fully configured feature extractor instance
            
        raises:
            ValueError: throws a value error if unknow extractor type is provided
        """
        # we are importing the libraries here to avoid circular dependencies
        from .lexical_features import LexicalFeatureExtractor
        from .network_features import NetworkFeatureExtractor
        from .content_features import ContentFeatureExtractor
        
        if extractor_type == "lexical":
            return LexicalFeatureExtractor(config)
        elif extractor_type == "network":
            return NetworkFeatureExtractor(config)
        elif extractor_type == "content":
            return ContentFeatureExtractor(config)
        else:
            raise ValueError(f"Unknown extractor type: {extractor_type}")


from .lexical_features import LexicalFeatureExtractor
from .network_features import NetworkFeatureExtractor  
from .content_features import ContentFeatureExtractor
from .optimized_extractor import OptimizedURLFeatureExtractor, CompositeFeatureExtractor
from .feature_engineer import FeatureEngineer

__all__ = [
    'FeatureExtractor',
    'FeatureExtractorFactory', 
    'LexicalFeatureExtractor',
    'NetworkFeatureExtractor',
    'ContentFeatureExtractor',
    'OptimizedURLFeatureExtractor',
    'CompositeFeatureExtractor',
    'FeatureEngineer'
]