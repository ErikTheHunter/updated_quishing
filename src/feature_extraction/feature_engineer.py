import os
import pickle
import hashlib
import pandas as pd
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List, Any, Optional
import time

from .optimized_extractor import OptimizedURLFeatureExtractor


class FeatureEngineer:
    """
    Main feature orchestrator class, organizes the pipeline for the 
    feature extraction amoong the various feature extractors
    """
    
    def __init__(self, 
                 cache_dir: str = "data/cache",
                 max_workers: int = 8,
                 enable_caching: bool = True):
        """
        Initialize the class, our system is an 8 core system
        so we will use 8 workers to run the process in parallel
        """
        self.cache_dir = Path(cache_dir)
        self.max_workers = max_workers
        self.enable_caching = enable_caching
        
        # if caching is enable, initialize teh cache folder
        if self.enable_caching:
            self.cache_dir.mkdir(parents=True, exist_ok=True)
        
        # initialize the optimized feature extractor class 
        self.feature_extractor = OptimizedURLFeatureExtractor()
        
        # Performance tracking stats to measure performance
        self.stats = {
            'total_extracted': 0,
            'cache_hits': 0,
            'cache_misses': 0,
            'failed_extractions': 0
        }
        
        
    def extract_features_single(self, url: str) -> Dict[str, Any]:
        """
        Exttract the feature from a single url 
        """
        # Attempt to read the cache first
        cached_features = self._load_from_cache(url)
        if cached_features is not None:
            return cached_features
        
        # if not cached proceed to extract features
        try:
            features = self.feature_extractor.extract_features(url)
            self._save_to_cache(url, features)
            self.stats['total_extracted'] += 1
            return features
            
        except Exception as e:
            self.stats['failed_extractions'] += 1
            return self.feature_extractor._get_empty_optimized_features()
    
    def extract_features_batch(self, urls: List[str], show_progress: bool = True) -> List[Dict[str, Any]]:
        """
        extract features in batches for perforamance
        """
        total_urls = len(urls)
        features_list = []
        processed_count = 0
        
        start_time = time.time()
        
        # use thread pool for the parallel extractino of features
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            future_to_url = {
                executor.submit(self.extract_features_single, url): url 
                for url in urls
            }
            
            for future in as_completed(future_to_url):
                url = future_to_url[future]
                try:
                    features = future.result(timeout=30)  # allow 30 seconds per url
                    features_list.append(features)
                except Exception as e:
                    print(f"error processing {url}: {e}")
                    features_list.append(self.feature_extractor._get_empty_optimized_features())
                    self.stats['failed_extractions'] += 1
                
                processed_count += 1
                
                # show progress every 100 urls, to show the process is still runing
                if show_progress and processed_count % 100 == 0:
                    elapsed_time = time.time() - start_time
                    urls_per_minute = (processed_count / elapsed_time) * 60
                    success_rate = ((processed_count - self.stats['failed_extractions']) 
                                  / processed_count) * 100
                    
                    print(f"Progress: {processed_count}/{total_urls} "
                          f"({processed_count/total_urls:.1%}) - "
                          f"Success: {success_rate:.1f}% - "
                          f"Speed: {urls_per_minute:.0f} URLs/min")
        
        # final statistics
        total_time = time.time() - start_time
        final_speed = (total_urls / total_time) * 60
        
        print(f"Batch extraction completed in {total_time:.1f}s")
        print(f"Final speed: {final_speed:.0f} URLs/min")
        
        return features_list
    
    def create_feature_dataframe(self, 
                                urls: List[str], 
                                cache_file: Optional[str] = None,
                                force_extract: bool = False) -> pd.DataFrame:
        """
        helper function to create the feature dataframe,
        this will extract all urls and create features for them as columns in the dataframe
        """
        # Check for existing cache file
        if cache_file and not force_extract and os.path.exists(cache_file):
            try:
                cached_data = pd.read_csv(cache_file)
                if len(cached_data) == len(urls):
                    print(f"Cache hit: Found existing feature data for {len(urls)} URLs.")
                    return cached_data
            except Exception as e:
                print(f"Warning: Failed to read cache file ({cache_file}): {e}")
        
        print("extracting features from scratch... might take a while.")
        
        # extract features in the batch
        extracted_features = self.extract_features_batch(urls)
        
        # create pandas data frame with the features in thier columns
        feature_df = pd.DataFrame(extracted_features)
        
        # Add URL column for reference
        feature_df.insert(0, 'url', urls)
        
        # Save to cache to reduce future recomputation
        if cache_file:
            try:
                feature_df.to_csv(cache_file, index=False)
                print(f"features saved to cache file: {cache_file}")
            except Exception as e:
                print(f"error could not save to cache: {e}")
        
        return feature_df
    
    def get_extraction_stats(self) -> Dict[str, Any]:
        """
        get extraction metrics for performance tracking
        """
        total_requests = self.stats['cache_hits'] + self.stats['cache_misses']
        cache_hit_rate = self.stats['cache_hits'] / total_requests if total_requests > 0 else 0
        
        return {
            'total_extracted': self.stats['total_extracted'],
            'cache_hits': self.stats['cache_hits'],
            'cache_misses': self.stats['cache_misses'],
            'failed_extractions': self.stats['failed_extractions'],
            'cache_hit_rate': cache_hit_rate,  # Target: >70%
            'success_rate': 1 - (self.stats['failed_extractions'] / max(total_requests, 1))
        }
    
    def _get_cache_key(self, url: str) -> str:
        """hash key for caching."""
        return hashlib.md5(url.encode('utf-8')).hexdigest()
    
    def _load_from_cache(self, url: str) -> Optional[Dict[str, Any]]:
        """
        load features from pre existing cache if available
        """
        if not self.enable_caching:
            return None
        
        cache_key = self._get_cache_key(url)
        cache_file = self.cache_dir / f"{cache_key}.pkl"
        
        try:
            if cache_file.exists():
                with open(cache_file, 'rb') as f:
                    cached_data = pickle.load(f)
                    if cached_data.get('url') == url:  # Verify URL match
                        self.stats['cache_hits'] += 1
                        return cached_data['features']
        except Exception:
            # Cache corruption, extract features normally
            # apply graceful degradation
            pass
        
        self.stats['cache_misses'] += 1
        return None
    
    def _save_to_cache(self, url: str, features: Dict[str, Any]) -> None:
        """Save features to cache with URL validation."""
        if not self.enable_caching:
            return
        
        try:
            cache_key = self._get_cache_key(url)
            cache_file = self.cache_dir / f"{cache_key}.pkl"
            
            cache_data = {
                'url': url,
                'features': features,
                'timestamp': time.time()
            }
            
            with open(cache_file, 'wb') as f:
                pickle.dump(cache_data, f)
                
        except Exception as e:
            print(f"Failed to save cache for {url}: {e}")
   
    def print_performance_summary(self) -> None:
        stats = self.get_extraction_stats()       
        print("Feature Extraction Performance Summary:")
        print(f"Total URLs processed: {stats['total_extracted']:,}")
        print(f"Cache hit rate: {stats['cache_hit_rate']:.1%}")
        print(f"Success rate: {stats['success_rate']:.1%}")
        print(f"Failed extractions: {stats['failed_extractions']:,}")
        if stats['cache_hit_rate'] > 0.7:
            print("Cache performance exceeds 70% target")
        else:
            print("Cache performance below 70% target")